import { readFileSync } from "node:fs";
import { Ajv } from "ajv";
import { describe, expect, it } from "vitest";
import { analyzePlan } from "../../src/core/engine.js";
import { fnv1a } from "../../src/report/common.js";
import { renderJson, toJson } from "../../src/report/json.js";
import { MAX_COMMENT_CHARS, renderMarkdown } from "../../src/report/markdown.js";
import { renderSarif } from "../../src/report/sarif.js";
import { renderText } from "../../src/report/text.js";
import { analyze, FIXTURES, fixture, rc } from "../helpers.js";

const aws = () => analyzePlan(fixture("real/aws-create.json"), { name: "envs/prod" });
const life = () => analyzePlan(fixture("real/lifecycle.json"), { name: "envs/dev" });

describe("markdown", () => {
  it("renders the sticky marker, headline, table and details", () => {
    const md = renderMarkdown([aws()], { marker: "planlens:default" });
    expect(md.startsWith("<!-- planlens:default -->")).toBe(true);
    expect(md).toMatch(/## 🔴 planlens — Risk \*\*100\/100\*\* · CRITICAL/);
    expect(md).toContain("`envs/prod` · Terraform 1.9.8");
    expect(md).toContain("Gate ❌ failed (fail-on: `high`)");
    expect(md).toContain("| ➕ Create | 🔄 Update |");
    expect(md).toContain("| 🔴 CRITICAL | `PL306` |");
    expect(md).toContain("<details><summary>Details and fixes");
    expect(md).toContain("**Fix:**");
    expect(md).toContain("<details><summary>🔵 Low / info");
    expect(md).toContain("All changes (15 resources)");
    expect(md).not.toContain("not-a-real-password");
  });

  it("renders moved blocks as code, accepted risks, warnings and AI summary", () => {
    const r = life();
    r.aiSummary = "This rotates the DB password.";
    r.warnings.push("something odd");
    r.suppressed.push({ ...r.findings[0]!, suppressed: { reason: "known | intended", expires: "2027-01-01" } });
    const md = renderMarkdown([r], { acceptedBy: "planlens:accept-risk" });
    expect(md).toContain("```hcl\nmoved {");
    expect(md).toContain("Risk accepted via label `planlens:accept-risk`");
    expect(md).toContain("✔️ Accepted risks (1)");
    expect(md).toContain("known \\| intended (until 2027-01-01)");
    expect(md).toContain("> [!WARNING]\n> something odd");
    expect(md).toContain("🤖 AI summary");
    expect(md).toMatch(/♻️ replace \(3\)/);
    expect(md).toContain("forced by `length`");
  });

  it("summarizes multiple plans", () => {
    const md = renderMarkdown([aws(), life()]);
    expect(md).toMatch(/^## 🔴 planlens — 2 plans · highest risk \*\*100\/100\*\* · Gate ❌ failed/);
    expect(md).toContain("### 🔴 `envs/prod`");
    expect(md).toContain("### 🟠 `envs/dev`");
  });

  it("says so when there is nothing to do", () => {
    const md = renderMarkdown([analyzePlan(fixture("real/noop.json"), { name: "noop" })]);
    expect(md).toContain("No changes. Infrastructure matches the configuration.");
    expect(md).toContain("🟢 planlens");
    expect(md).toContain("Gate ✅ passed");
  });

  it("drops low-priority sections to stay under GitHub's limit", () => {
    const changes = Array.from({ length: 900 }, (_, i) =>
      rc("aws_security_group_rule.r", "create", {
        index: i,
        after: { type: "ingress", protocol: "tcp", from_port: 22, to_port: 22, cidr_blocks: ["0.0.0.0/0"] },
      }),
    );
    const md = renderMarkdown([analyze(changes)], { runUrl: "https://ci/run/1" });
    expect(md.length).toBeLessThanOrEqual(MAX_COMMENT_CHARS);
    expect(md).toContain("Comment truncated");
    expect(md).toContain("[CI run](https://ci/run/1)");
  });
});

describe("text", () => {
  it("renders without color by default and hides low/info unless verbose", () => {
    const out = renderText([life()]);
    expect(out).not.toContain("\u001b[");
    expect(out).toMatch(/low\/info finding\(s\) hidden/);
    expect(out).toContain("✗ Gate failed");
    const verbose = renderText([life()], { verbose: true, color: true });
    expect(verbose).toContain("\u001b[");
    expect(verbose).toContain("Changes:");
    expect(verbose).toContain("PL009");
  });
  it("shows the pass line and suppressed count", () => {
    const r = analyze([rc("aws_db_instance.d", "delete")], { ignore: [{ rule: "PL001", reason: "x" }] });
    const out = renderText([r]);
    expect(out).toContain("1 finding(s) suppressed");
    expect(out).toContain("No risky changes found");
    expect(out).toContain("✓ Gate passed (fail-on: high)");
  });
});

describe("json", () => {
  it("wraps reports in a stable envelope", () => {
    const env = toJson([aws(), life()]);
    expect(env).toMatchObject({ schemaVersion: 1, passed: false, maxScore: 100 });
    expect(env.reports).toHaveLength(2);
    expect(JSON.parse(renderJson([life()])).reports[0].name).toBe("envs/dev");
    expect(toJson([]).tool.name).toBe("planlens");
  });
});

describe("sarif", () => {
  const schema = JSON.parse(readFileSync(`${FIXTURES}sarif-schema-2.1.0.json`, "utf8"));
  const ajv = new Ajv({ strict: false, allErrors: true, validateFormats: false });
  const validate = ajv.compile(schema);

  it("is valid SARIF 2.1.0 with rules, locations and fingerprints", () => {
    const r = analyze([rc("aws_db_instance.d", "delete")], { rules: [{ id: "ORG1", title: "custom", severity: "low", when: { type: "aws_db_instance" } }] });
    const sarif = JSON.parse(
      renderSarif([aws(), r], {
        locate: (f) => (f.address === "aws_iam_role.github" ? { uri: "infra\\iam.tf", line: 12 } : undefined),
        fallbackUri: (rep) => `${rep.name}/plan.json`,
      }),
    );
    const ok = validate(sarif);
    expect(validate.errors ?? []).toEqual([]);
    expect(ok).toBe(true);
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("planlens");
    expect(run.tool.driver.rules.find((x: { id: string }) => x.id === "PL306").properties["security-severity"]).toBe("9.5");
    expect(run.tool.driver.rules.some((x: { id: string }) => x.id === "ORG1")).toBe(true);
    const gh = run.results.find((x: { properties: { address: string } }) => x.properties.address === "aws_iam_role.github");
    expect(gh.locations[0].physicalLocation).toEqual({ artifactLocation: { uri: "infra/iam.tf" }, region: { startLine: 12 } });
    expect(gh.level).toBe("error");
    expect(gh.partialFingerprints["planlens/v1"]).toBe(fnv1a("envs/prod|PL306|aws_iam_role.github"));
    const other = run.results.find((x: { properties: { address: string } }) => x.properties.address === "aws_eks_cluster.main");
    expect(other.locations[0].physicalLocation.artifactLocation.uri).toBe("envs/prod/plan.json");
    expect(other.level).toBe("warning");
    expect(sarif.runs[0].results.every((x: { message: { text: string } }) => !x.message.text.includes("`"))).toBe(true);
  });

  it("defaults the location to the report name", () => {
    const sarif = JSON.parse(renderSarif([analyze([rc("aws_db_instance.d", "delete")])]));
    expect(validate(sarif)).toBe(true);
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe("plan");
  });
});
