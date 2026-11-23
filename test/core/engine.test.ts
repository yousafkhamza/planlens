import { describe, expect, it } from "vitest";
import { ConfigError, resolveConfig, validateConfig } from "../../src/core/config.js";
import { analyzePlan, gatePasses, riskLevel, riskScore } from "../../src/core/engine.js";
import { RULES } from "../../src/core/rules/index.js";
import type { Rule } from "../../src/core/types.js";
import { VERSION } from "../../src/version.js";
import { analyze, byRule, fixture, ids, plan, rc } from "../helpers.js";

describe("scoring and gate", () => {
  it("saturates the score and derives the level", () => {
    expect(riskScore([])).toBe(0);
    expect(riskScore([{ severity: "critical" }])).toBe(50);
    expect(riskScore([{ severity: "critical" }, { severity: "critical" }])).toBe(75);
    expect(riskScore([{ severity: "info" }])).toBe(0);
    expect(riskScore(Array.from({ length: 30 }, () => ({ severity: "critical" as const })))).toBe(100);
    expect(riskLevel([{ severity: "info" }])).toBe("none");
    expect(riskLevel([{ severity: "low" }, { severity: "high" }, { severity: "medium" }])).toBe("high");
  });
  it("gates on fail_on", () => {
    expect(gatePasses([{ severity: "high" }], "critical")).toBe(true);
    expect(gatePasses([{ severity: "high" }], "high")).toBe(false);
    expect(gatePasses([{ severity: "critical" }], "none")).toBe(true);
    expect(gatePasses([{ severity: "info" }], "info")).toBe(false);
  });
  it("defaults fail_on to high; CLI override beats config", () => {
    const p = plan([rc("aws_iam_access_key.k", "create")]);
    expect(analyzePlan(p).failOn).toBe("high");
    expect(analyzePlan(p).passed).toBe(true);
    expect(analyzePlan(p, { config: { fail_on: "medium" } }).passed).toBe(false);
    expect(analyzePlan(p, { config: { fail_on: "medium" }, failOn: "none" }).passed).toBe(true);
    expect(analyzePlan(p, { config: resolveConfig({ fail_on: "medium" }), failOn: "critical" }).failOn).toBe("critical");
  });
});

describe("report shape", () => {
  it("includes metadata, sorted findings and change list", () => {
    const r = analyze([rc("aws_iam_access_key.k", "create"), rc("aws_db_instance.d", "delete"), rc("aws_ami.a", "read", { mode: "data" })]);
    expect(r.schemaVersion).toBe(1);
    expect(r.tool).toEqual({ name: "planlens", version: VERSION });
    expect(r.findings.map((f) => f.severity)).toEqual(["critical", "medium"]);
    expect(r.changes.map((c) => c.address)).toEqual(["aws_iam_access_key.k", "aws_db_instance.d"]);
    expect(r.findings[0]?.remediation).toBeTruthy();
  });
  it("warns about errored, incomplete and non-applyable plans", () => {
    expect(analyze([], {}, { errored: true, applyable: false }).warnings[0]).toMatch(/partial/);
    expect(analyze([], {}, { complete: false }).warnings[0]).toMatch(/incomplete/);
    expect(analyze([rc("null_resource.x", "create")], {}, { applyable: false }).warnings[0]).toMatch(/not applyable/);
    // Terraform marks no-op plans as not applyable — that is not worth a warning.
    expect(analyze([], {}, { applyable: false }).warnings).toEqual([]);
  });
  it("returns a clean report for a no-op plan", () => {
    const r = analyzePlan(fixture("real/noop.json"));
    expect(r.findings).toEqual([]);
    expect(r.summary.total).toBe(0);
    expect(r.level).toBe("none");
    expect(r.passed).toBe(true);
  });
  it("isolates crashing rules", () => {
    const boom: Rule = {
      id: "PLX",
      title: "x",
      severity: "low",
      category: "hygiene",
      description: "",
      remediation: "",
      run: () => {
        throw new Error("kaboom");
      },
    };
    (RULES as Rule[]).push(boom);
    try {
      const r = analyze([rc("aws_db_instance.d", "delete")]);
      expect(r.warnings).toContain("Rule PLX failed and was skipped: kaboom");
      expect(ids(r)).toContain("PL001");
    } finally {
      (RULES as Rule[]).pop();
    }
  });
});

describe("config: disable, overrides, ignores", () => {
  const changes = [rc("aws_db_instance.prod", "delete"), rc("aws_db_instance.scratch", "delete"), rc("aws_iam_access_key.k", "create")];

  it("disables rules and overrides severities", () => {
    const r = analyze(changes, { disable: ["PL308"], severity_overrides: { PL001: "low" } });
    expect(ids(r)).not.toContain("PL308");
    expect(byRule(r, "PL001").every((f) => f.severity === "low")).toBe(true);
    expect(r.passed).toBe(true);
  });

  it("suppresses matching findings with reasons and expiries", () => {
    const r = analyze(changes, {
      ignore: [
        { rule: "PL001", address: "aws_db_instance.scratch", reason: "ephemeral test DB", expires: "2027-01-01" },
        { rule: "PL308", reason: "CI user, rotated monthly", expires: "2026-01-01" },
        { address: "nothing.matches", reason: "stale" },
      ],
    });
    expect(byRule(r, "PL001").map((f) => f.address)).toEqual(["aws_db_instance.prod"]);
    expect(r.suppressed.map((f) => [f.address, f.suppressed?.reason])).toEqual([["aws_db_instance.scratch", "ephemeral test DB"]]);
    // expired ignore → finding active again + warning
    expect(ids(r)).toContain("PL308");
    expect(r.warnings.join("\n")).toMatch(/PL308 expired on 2026-01-01/);
  });
});

describe("custom rules", () => {
  it("evaluates actions, globs and attribute conditions", () => {
    const r = analyze(
      [
        rc("aws_db_instance.prod", "delete", { module: "module.prod", before: { engine: "postgres" } }),
        rc("aws_instance.web", "create", { after: { tags: { Team: "web" }, instance_type: "m5.24xlarge" } }),
        rc("aws_instance.ok", "create", { after: { tags: { Team: "x", CostCenter: "1" }, instance_type: "t3.small" } }),
        rc("aws_s3_bucket.b", "update", { before: { tags: { a: 1 } }, after: { tags: { a: 2 } } }),
      ],
      {
        rules: [
          {
            id: "ORG001",
            title: "No destroy in prod",
            severity: "critical",
            message: "{address} ({action}) is in prod",
            when: { actions: ["delete", "replace"], address: "module.prod.*" },
          },
          {
            id: "ORG002",
            title: "CostCenter tag required",
            severity: "medium",
            when: { actions: ["create"], type: "aws_instance", attributes: [{ path: "tags.CostCenter", op: "absent" }] },
          },
          {
            id: "ORG003",
            title: "No huge instances",
            severity: "high",
            when: { type: ["aws_instance"], attributes: [{ path: "instance_type", op: "matches", value: "\\.(16|24)xlarge$" }] },
          },
          { id: "ORG004", title: "Tag changes", severity: "low", when: { attributes: [{ path: "tags", op: "changed" }] } },
          {
            id: "ORG005",
            title: "Engine",
            severity: "info",
            when: {
              attributes: [
                { path: "engine", op: "in", value: ["postgres"] },
                { path: "engine", op: "not_equals", value: "mysql" },
              ],
            },
          },
          {
            id: "ORG006",
            title: "unused ops",
            severity: "info",
            when: {
              attributes: [
                { path: "instance_type", op: "not_in", value: ["t3.small"] },
                { path: "instance_type", op: "not_matches", value: "^t3" },
                { path: "tags.Team", op: "equals", value: "web" },
                { path: "tags", op: "exists" },
              ],
            },
          },
        ],
      },
    );
    expect(byRule(r, "ORG001")[0]?.message).toBe("module.prod.aws_db_instance.prod (delete) is in prod");
    expect(byRule(r, "ORG002").map((f) => f.address)).toEqual(["aws_instance.web"]);
    expect(byRule(r, "ORG003").map((f) => f.address)).toEqual(["aws_instance.web"]);
    expect(byRule(r, "ORG004").map((f) => f.address)).toEqual(["aws_s3_bucket.b"]);
    expect(byRule(r, "ORG005").map((f) => f.address)).toEqual(["module.prod.aws_db_instance.prod"]);
    expect(byRule(r, "ORG006").map((f) => f.address)).toEqual(["aws_instance.web"]);
    expect(byRule(r, "ORG001")[0]?.category).toBe("custom");
  });
});

describe("validateConfig", () => {
  it("accepts empty and valid configs", () => {
    expect(validateConfig(undefined)).toEqual({});
    expect(validateConfig({ fail_on: "critical", ignore: [{ rule: "PL001", reason: "ok", expires: "2027-01-01" }] })).toBeTruthy();
  });
  it("normalizes Date expiries from YAML parsers", () => {
    const cfg = validateConfig({ ignore: [{ rule: "PL001", reason: "ok", expires: new Date("2027-01-01T00:00:00Z") }] });
    expect(cfg.ignore?.[0]?.expires).toBe("2027-01-01");
  });
  it("lists every problem at once", () => {
    try {
      validateConfig({
        fail_on: "panic",
        typo_key: 1,
        mass_destroy_threshold: 0,
        stateful_types: "aws_x",
        disable: ["PL999"],
        severity_overrides: { PL001: "severe" },
        ignore: [{ reason: "" }, "x", { rule: "NOPE", reason: "r", expires: "tomorrow" }],
        rules: [
          { id: "PL001", title: "x", severity: "high", when: {} },
          { id: "", severity: "bad" },
          {
            id: "A",
            title: "a",
            severity: "low",
            when: {
              actions: ["explode"],
              type: 1,
              bogus: 1,
              attributes: [
                { path: "x", op: "nah" },
                { path: "y", op: "matches", value: "(" },
                { path: "z", op: "in", value: "x" },
              ],
            },
          },
          { id: "A", title: "dup", severity: "low", when: {} },
          "x",
          { id: "B", title: "b", severity: "low", when: { attributes: "x" } },
        ],
      });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError);
      const p = (e as ConfigError).problems.join("\n");
      for (const s of [
        "unknown key `typo_key`",
        "fail_on must be",
        "mass_destroy_threshold",
        "stateful_types must be a list",
        "unknown rule id `PL999`",
        "invalid severity `severe`",
        "needs `rule` and/or `address`",
        "reason is required",
        "ignore[1] must be a mapping",
        "unknown rule id `NOPE`",
        "expires must be a date",
        "collides with a built-in rule",
        "rules[1].id is required",
        "rules[1].title is required",
        "rules[1].severity",
        "rules[1].when is required",
        "when.actions",
        "when.type",
        "unknown key `bogus`",
        "needs `path` and `op`",
        "not a valid regular expression",
        "must be a list for `in`",
        "is duplicated",
        "rules[4] must be a mapping",
        "when.attributes must be a list",
      ]) {
        expect(p).toContain(s);
      }
    }
  });
  it("rejects non-object configs and bad overrides type", () => {
    expect(() => validateConfig("x")).toThrow(ConfigError);
    expect(() => validateConfig({ severity_overrides: [] })).toThrow(/severity_overrides must be a mapping/);
    expect(() => validateConfig({ ignore: {} })).toThrow(/ignore must be a list/);
    expect(() => validateConfig({ rules: {} })).toThrow(/rules must be a list/);
  });
});

describe("real fixtures (generated by Terraform)", () => {
  it("aws-create: catches the expected security issues", () => {
    const r = analyzePlan(fixture("real/aws-create.json"));
    const got = new Set(r.findings.map((f) => `${f.ruleId} ${f.address}`));
    for (const e of [
      "PL201 aws_security_group.bastion",
      "PL201 aws_vpc_security_group_ingress_rule.postgres",
      "PL301 aws_iam_policy.ci_admin",
      "PL302 aws_iam_policy.deployer",
      "PL303 aws_iam_policy.deployer",
      "PL304 aws_iam_role_policy_attachment.github_admin",
      "PL305 aws_s3_bucket_policy.data",
      "PL306 aws_iam_role.github",
      "PL104 aws_db_instance.main",
      "PL202 aws_db_instance.main",
      "PL205 aws_s3_bucket_public_access_block.data",
      "PL204 aws_eks_cluster.main",
      "PL207 aws_instance.legacy",
      "PL308 aws_iam_access_key.ci",
      "PL401 aws_lambda_function.api",
    ]) {
      expect(got, e).toContain(e);
    }
    // the DB password is marked sensitive by the provider → must never be reported
    expect(JSON.stringify(r)).not.toContain("not-a-real-password");
    expect(r.level).toBe("critical");
    expect(r.passed).toBe(false);
  });

  it("lifecycle: replace, rename, count shift, drift, import, moved, output", () => {
    const r = analyzePlan(fixture("real/lifecycle.json"));
    const got = r.findings.map((f) => `${f.ruleId} ${f.address}`);
    expect(got).toEqual(
      expect.arrayContaining([
        "PL003 random_password.db",
        "PL006 random_pet.old_name",
        "PL006 local_file.per_name",
        "PL007 local_file.drift",
        "PL008 random_id.imported",
        "PL009 terraform_data.moved_new",
        "PL402 output.api_token",
      ]),
    );
    expect(got).not.toContain("PL402 output.db_password");
    expect(got.some((g) => g.includes("forget_me"))).toBe(false);
  });
});
