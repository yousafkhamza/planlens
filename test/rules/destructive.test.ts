import { describe, expect, it } from "vitest";
import { similarity } from "../../src/core/rules/destructive.js";
import { analyze, byRule, ids, rc } from "../helpers.js";

describe("PL001 stateful destroyed", () => {
  it("flags a deleted database with snapshot + removed-block hints", () => {
    const r = analyze([rc("aws_db_instance.main", "delete", { before: { skip_final_snapshot: true }, reason: "delete_because_no_resource_config" })]);
    const [f] = byRule(r, "PL001");
    expect(f?.severity).toBe("critical");
    expect(f?.details.join(" ")).toMatch(/skip_final_snapshot/);
    expect(f?.details.join(" ")).toMatch(/removed \{/);
    expect(ids(r)).not.toContain("PL004");
  });
  it("supports glob types and user-defined stateful types", () => {
    expect(ids(analyze([rc("aws_fsx_lustre_file_system.x", "delete")]))).toContain("PL001");
    expect(ids(analyze([rc("custom_db.x", "delete")], { stateful_types: ["custom_*"] }))).toContain("PL001");
  });
  it("does not flag creates/updates or data sources", () => {
    expect(byRule(analyze([rc("aws_db_instance.main", "update"), rc("aws_db_instance.n", "create")]), "PL001")).toHaveLength(0);
    expect(byRule(analyze([rc("aws_s3_bucket.x", "delete", { mode: "data" })]), "PL001")).toHaveLength(0);
  });
});

describe("PL002 stateful replaced", () => {
  it("shows the attribute that forces replacement, honouring sensitivity", () => {
    const r = analyze([
      rc("aws_db_instance.main", "replace", {
        before: { identifier: "a", password: "old" },
        after: { identifier: "b", password: "new" },
        replacePaths: [["identifier"], ["password"]],
        afterSensitive: { password: true },
        beforeSensitive: { password: true },
        reason: "replace_because_cannot_update",
      }),
    ]);
    const f = byRule(r, "PL002")[0];
    expect(f?.severity).toBe("critical");
    const d = f?.details.join("\n") ?? "";
    expect(d).toContain('`identifier`: "a" → "b"');
    expect(d).toContain("`password`: (sensitive) → (sensitive)");
    expect(d).not.toContain("old");
    expect(d).toMatch(/destroy-then-create/);
  });
  it("mentions create-before-destroy ordering and (known after apply)", () => {
    const r = analyze([
      rc("aws_s3_bucket.b", "replace-cbd", { before: { bucket: "x" }, after: { bucket: null }, afterUnknown: { bucket: true }, replacePaths: [["bucket"]] }),
    ]);
    const d = byRule(r, "PL002")[0]?.details.join("\n") ?? "";
    expect(d).toMatch(/create-before-destroy/);
    expect(d).toContain("(known after apply)");
  });
  it("warns that the apply will fail when deletion protection is on", () => {
    const r = analyze([
      rc("aws_db_instance.p", "replace", { before: { deletion_protection: true }, after: { deletion_protection: false }, replacePaths: [["identifier"]] }),
    ]);
    expect(byRule(r, "PL002")[0]?.details.join(" ")).toMatch(/apply will fail at the destroy step/);
  });
  it("truncates long replace path lists", () => {
    const paths = Array.from({ length: 8 }, (_, i) => [`a${i}`]);
    const d = byRule(analyze([rc("aws_ebs_volume.v", "replace", { replacePaths: paths })]), "PL002")[0]?.details.join("\n");
    expect(d).toMatch(/\+2 more/);
  });
});

describe("PL003/PL004 other destroys", () => {
  it("rates high-impact types high and adds a secret rotation note", () => {
    const r = analyze([rc("aws_eks_cluster.main", "replace", { replacePaths: [["name"]] }), rc("tls_private_key.k", "replace")]);
    expect(byRule(r, "PL003").map((f) => f.severity)).toEqual(["high", "high"]);
    expect(
      byRule(r, "PL003")
        .find((f) => f.address === "tls_private_key.k")
        ?.details.join(" "),
    ).toMatch(/new secret/);
  });
  it("supports user-defined critical types", () => {
    expect(ids(analyze([rc("my_thing.x", "delete")], { critical_types: ["my_*"] }))).toContain("PL003");
  });
  it("lists everything else as low", () => {
    const r = analyze([rc("aws_iam_policy.p", "delete"), rc("null_resource.x", "replace")]);
    expect(byRule(r, "PL004").map((f) => f.severity)).toEqual(["low", "low"]);
  });
});

describe("PL005 mass destroy", () => {
  it("fires at the threshold with a by-type breakdown", () => {
    const changes = Array.from({ length: 10 }, (_, i) => rc("aws_route53_record.r", "delete", { index: i }));
    const f = byRule(analyze(changes), "PL005")[0];
    expect(f?.message).toMatch(/10 resources/);
    expect(f?.details[0]).toContain("aws_route53_record ×10");
  });
  it("respects a custom threshold", () => {
    const changes = Array.from({ length: 3 }, (_, i) => rc("null_resource.r", "delete", { index: i }));
    expect(byRule(analyze(changes), "PL005")).toHaveLength(0);
    expect(byRule(analyze(changes, { mass_destroy_threshold: 3 }), "PL005")).toHaveLength(1);
  });
});

describe("PL006 refactor recreate", () => {
  it("suggests a moved block for a rename", () => {
    const r = analyze([
      rc("aws_s3_bucket.old", "delete", { before: { bucket: "logs", acl: "private", id: "logs", arn: "arn:x" } }),
      rc("aws_s3_bucket.new", "create", { after: { bucket: "logs", acl: "private", id: null }, afterUnknown: { id: true, arn: true } }),
    ]);
    const f = byRule(r, "PL006")[0];
    expect(f?.severity).toBe("high");
    expect(f?.details.join("\n")).toContain("from = aws_s3_bucket.old\n  to   = aws_s3_bucket.new");
  });
  it("matches moves into modules and prefers the best candidate", () => {
    const r = analyze([
      rc("aws_iam_policy.p", "delete", { before: { name: "a", policy: "{}", path: "/" } }),
      rc("aws_iam_policy.p", "create", { module: "module.iam", after: { name: "a", policy: "{}", path: "/" } }),
      rc("aws_iam_policy.q", "create", { after: { name: "zzz", policy: "{}", path: "/" } }),
    ]);
    const f = byRule(r, "PL006")[0];
    expect(f?.severity).toBe("medium");
    expect(f?.message).toContain("module.iam.aws_iam_policy.p");
  });
  it("ignores dissimilar and imported creates", () => {
    const r = analyze([
      rc("aws_iam_policy.a", "delete", { before: { name: "a", policy: "1" } }),
      rc("aws_iam_policy.b", "create", { after: { name: "b", policy: "2" } }),
      rc("aws_iam_policy.c", "create", { after: { name: "a", policy: "1" }, importing: true }),
    ]);
    expect(byRule(r, "PL006")).toHaveLength(0);
  });
  it("detects count index shifts", () => {
    const r = analyze([
      rc("aws_subnet.private", "update", { index: 1, before: { cidr_block: "10.0.2.0/24" }, after: { cidr_block: "10.0.3.0/24" } }),
      rc("aws_subnet.private", "delete", { index: 2, reason: "delete_because_count_index", before: { cidr_block: "10.0.3.0/24" } }),
    ]);
    const f = byRule(r, "PL006").find((x) => x.address === "aws_subnet.private");
    expect(f?.severity).toBe("high");
    expect(f?.message).toMatch(/shifts indexes/);
  });
  it("rates a shift of unimportant resources as medium", () => {
    const r = analyze([rc("null_resource.n", "update", { index: 0 }), rc("null_resource.n", "delete", { index: 1, reason: "delete_because_count_index" })]);
    expect(byRule(r, "PL006")[0]?.severity).toBe("medium");
  });
  it("similarity ignores unknown/computed keys", () => {
    expect(similarity({ a: 1, id: "x" }, { a: 1, id: null, b: null }, {})).toBe(1);
    expect(similarity({ a: 1 }, { a: 2 }, {})).toBe(0);
    expect(similarity(null, { a: 1 }, {})).toBe(0);
    expect(similarity({ a: 1 }, { x: 1, a: 1 }, { x: true })).toBe(1);
    expect(similarity({}, { id: "1", l: [] }, {})).toBe(0);
  });
});

describe("PL007/PL008/PL009 drift, import, moved", () => {
  it("reports drift (changed and deleted)", () => {
    const r = analyze(
      [],
      {},
      {
        resource_drift: [rc("aws_security_group.sg", "update", { before: { description: "a" }, after: { description: "b" } }), rc("aws_instance.i", "delete")],
      },
    );
    const f = byRule(r, "PL007");
    expect(f.map((x) => x.message)).toEqual([expect.stringMatching(/deleted outside/), expect.stringMatching(/changed outside/)]);
    expect(f[1]?.details[0]).toContain("`description`");
  });
  it("reports imports, including import + update", () => {
    const r = analyze([
      rc("aws_s3_bucket.a", "no-op", { importing: true }),
      rc("aws_s3_bucket.b", "update", { importing: true, before: { x: 1 }, after: { x: 2 } }),
    ]);
    const f = byRule(r, "PL008");
    expect(f).toHaveLength(2);
    expect(f.find((x) => x.address === "aws_s3_bucket.b")?.message).toMatch(/then updated/);
  });
  it("reports moved addresses as info", () => {
    const r = analyze([rc("aws_s3_bucket.new", "no-op", { previous: "aws_s3_bucket.old" })]);
    expect(byRule(r, "PL009")[0]?.severity).toBe("info");
    expect(r.level).toBe("none");
  });
});
