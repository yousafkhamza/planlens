import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { expandPatterns, globToRegExp } from "../../src/node/glob.js";
import { InputError, loadConfig, loadPlan, showBinaryPlan } from "../../src/node/load.js";
import { parseAddress, SourceLocator, splitAddress } from "../../src/node/locate.js";
import { runPlans } from "../../src/node/run.js";
import { FIXTURES } from "../helpers.js";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "planlens-test-"));
}

describe("loadPlan", () => {
  it("loads JSON plans and reports helpful errors", () => {
    expect(loadPlan(`${FIXTURES}real/noop.json`).format_version).toBe("1.2");
    expect(() => loadPlan("missing.json")).toThrow(/not found/);
    const d = tmp();
    writeFileSync(join(d, "empty.json"), "  ");
    expect(() => loadPlan(join(d, "empty.json"))).toThrow(/empty/);
    writeFileSync(join(d, "state.json"), JSON.stringify({ format_version: "1.0", values: {} }));
    expect(() => loadPlan(join(d, "state.json"))).toThrow(InputError);
  });
  it("explains how to convert a binary plan when terraform is unavailable", () => {
    const d = tmp();
    writeFileSync(join(d, "tf.plan"), Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0, 0]));
    expect(() => showBinaryPlan(join(d, "tf.plan"), { ...process.env, TERRAFORM_BINARY: "definitely-not-a-terraform-binary" })).toThrow(
      /terraform show -json tf.plan > plan.json/,
    );
  });
});

describe("loadConfig", () => {
  it("discovers .planlens.yml and validates it", () => {
    const d = tmp();
    expect(loadConfig(undefined, d)).toEqual({ config: {} });
    writeFileSync(join(d, ".planlens.yml"), "fail_on: critical\nignore:\n  - rule: PL001\n    reason: ok\n    expires: 2027-01-01\n");
    const { config, path } = loadConfig(undefined, d);
    expect(config.fail_on).toBe("critical");
    expect(config.ignore?.[0]?.expires).toBe("2027-01-01");
    expect(path).toContain(".planlens.yml");
  });
  it("the shipped example config is valid", () => {
    const { config } = loadConfig(fileURLToPath(new URL("../../examples/.planlens.yml", import.meta.url)));
    expect(config.rules?.map((r) => r.id)).toEqual(["ORG001", "ORG002", "ORG003"]);
    expect(config.ignore?.[1]?.expires).toBe("2027-06-30");
  });

  it("supports JSON and reports parse/validation errors", () => {
    const d = tmp();
    writeFileSync(join(d, "c.json"), JSON.stringify({ fail_on: "low" }));
    expect(loadConfig(join(d, "c.json")).config.fail_on).toBe("low");
    writeFileSync(join(d, "bad.yml"), "fail_on: [unclosed");
    expect(() => loadConfig(join(d, "bad.yml"))).toThrow(/Could not parse/);
    writeFileSync(join(d, "invalid.yml"), "fail_on: maybe\n");
    expect(() => loadConfig(join(d, "invalid.yml"))).toThrow(/fail_on must be/);
    expect(() => loadConfig(join(d, "nope.yml"))).toThrow(/not found/);
  });
});

describe("addresses + source locator", () => {
  it("splits addresses with quoted keys", () => {
    expect(splitAddress('module.a["x.y"].aws_s3_bucket.b[0]')).toEqual(["module", "a", "aws_s3_bucket", "b"]);
    expect(splitAddress('aws_s3_bucket.b["k\\"q"]')).toEqual(["aws_s3_bucket", "b"]);
    expect(parseAddress("module.net.module.sub.data.aws_ami.x")).toEqual({ modules: ["net", "sub"], mode: "data", type: "aws_ami", name: "x" });
  });

  it("maps resources to .tf lines through local modules and falls back to module calls", () => {
    const repo = tmp();
    const root = join(repo, "infra");
    mkdirSync(join(root, "modules", "db"), { recursive: true });
    writeFileSync(
      join(root, "main.tf"),
      'locals {}\n\nmodule "db" {\n  source = "./modules/db"\n}\n\nmodule "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n\nresource "aws_s3_bucket" "logs" {\n}\n\ndata "aws_ami" "x" {}\n',
    );
    writeFileSync(join(root, "modules", "db", "rds.tf"), '\n\nresource "aws_db_instance" "main" {\n}\n');
    const loc = new SourceLocator(root, { "module.db": "./modules/db", "module.vpc": "terraform-aws-modules/vpc/aws" }, repo);
    expect(loc.locate("aws_s3_bucket.logs")).toEqual({ uri: "infra/main.tf", line: 11 });
    expect(loc.locate("module.db.aws_db_instance.main")).toEqual({ uri: "infra/modules/db/rds.tf", line: 3 });
    expect(loc.locate("module.vpc.aws_subnet.private[0]")).toEqual({ uri: "infra/main.tf", line: 7 });
    expect(loc.locate("data.aws_ami.x")).toEqual({ uri: "infra/main.tf", line: 14 });
    expect(loc.locate("aws_s3_bucket.unknown")).toBeUndefined();
    expect(new SourceLocator(join(repo, "nope"), {}).locate("a.b")).toBeUndefined();
  });
});

describe("glob expansion", () => {
  it("converts globs", () => {
    expect(globToRegExp("envs/**/plan.json").test("envs/prod/eu/plan.json")).toBe(true);
    expect(globToRegExp("envs/**/plan.json").test("envs/plan.json")).toBe(true);
    expect(globToRegExp("envs/*/plan.json").test("envs/a/b/plan.json")).toBe(false);
    expect(globToRegExp("a?.json").test("ab.json")).toBe(true);
    expect(globToRegExp("**.json").test("x/y.json")).toBe(true);
  });
  it("expands patterns, passes plain paths through and skips .terraform", () => {
    const d = tmp();
    for (const p of ["envs/prod/plan.json", "envs/dev/plan.json", "envs/dev/.terraform/plan.json", "other.json"]) {
      mkdirSync(join(d, p, ".."), { recursive: true });
      writeFileSync(join(d, p), "{}");
    }
    expect(expandPatterns("envs/*/plan.json", d)).toEqual(["envs/dev/plan.json", "envs/prod/plan.json"]);
    expect(expandPatterns("envs/**/plan.json\nother.json, missing.json", d)).toEqual([
      "envs/dev/plan.json",
      "envs/prod/plan.json",
      "missing.json",
      "other.json",
    ]);
    expect(expandPatterns("nothing/*.json", d)).toEqual([]);
  });
});

describe("runPlans", () => {
  it("labels plans, applies config and locates sources", async () => {
    const d = tmp();
    mkdirSync(join(d, "prod"));
    writeFileSync(join(d, "prod", "plan.json"), readFileSync(`${FIXTURES}real/aws-create.json`));
    writeFileSync(join(d, "prod", "main.tf"), 'resource "aws_iam_role" "github" {\n}\n');
    writeFileSync(join(d, ".planlens.yml"), "fail_on: none\n");
    const res = await runPlans({ plans: ["prod/plan.json"], cwd: d });
    expect(res.reports[0]?.name).toBe("prod/plan.json");
    expect(res.reports[0]?.passed).toBe(true);
    expect(res.configPath).toContain(".planlens.yml");
    const f = res.reports[0]!.findings.find((x) => x.address === "aws_iam_role.github")!;
    expect(res.sarif.locate?.(f, res.reports[0]!)).toEqual({ uri: "prod/main.tf", line: 1 });
    expect(res.sarif.locate?.({ ...f, address: "output.x" }, res.reports[0]!)).toBeUndefined();
    expect(res.sarif.fallbackUri?.(res.reports[0]!)).toBe("prod/plan.json");
  });
  it("uses --name for a single plan and records AI failures as warnings", async () => {
    const res = await runPlans({ plans: [`${FIXTURES}real/lifecycle.json`], name: "dev", ai: "ollama", cwd: FIXTURES });
    expect(res.reports[0]?.name).toBe("dev");
    expect(res.reports[0]?.warnings.join(" ")).toMatch(/AI summary skipped: --ai-model is required/);
  });
});
