import { describe, expect, it } from "vitest";
import { actionsToKind, assertPlan, normalizePlan, PlanParseError, parsePlanText, summarize } from "../../src/core/plan.js";
import { fixture, plan, rc } from "../helpers.js";

describe("parsePlanText / assertPlan", () => {
  it("accepts a real plan and strips a BOM", () => {
    const text = `﻿${JSON.stringify(fixture("real/lifecycle.json"))}`;
    expect(parsePlanText(text).format_version).toBe("1.2");
  });
  it("rejects invalid JSON with a clear message", () => {
    expect(() => parsePlanText("{nope")).toThrow(/not valid JSON/);
  });
  it("rejects non-objects", () => {
    expect(() => assertPlan([])).toThrow(PlanParseError);
  });
  it("explains how to produce a plan when format_version is missing", () => {
    expect(() => assertPlan({ resource_changes: [] })).toThrow(/terraform show -json/);
  });
  it("detects state JSON passed by mistake", () => {
    expect(() => assertPlan({ format_version: "1.0", values: {} })).toThrow(/state/);
  });
  it("rejects objects without changes", () => {
    expect(() => assertPlan({ format_version: "1.0" })).toThrow(/no `resource_changes`/);
  });
  it("rejects unsupported major versions", () => {
    expect(() => assertPlan({ format_version: "2.0", resource_changes: [] })).toThrow(/Unsupported/);
  });
  it("rejects malformed resource_changes", () => {
    expect(() => assertPlan({ format_version: "1.2", resource_changes: {} })).toThrow(/must be an array/);
  });
});

describe("actionsToKind", () => {
  it.each([
    [["create"], "create", false],
    [["update"], "update", false],
    [["delete"], "delete", false],
    [["delete", "create"], "replace", false],
    [["create", "delete"], "replace", true],
    [["read"], "read", false],
    [["no-op"], "no-op", false],
    [["forget"], "no-op", false],
  ])("%j → %s", (actions, kind, cbd) => {
    expect(actionsToKind(actions)).toEqual({ kind, createBeforeDestroy: cbd });
  });
});

describe("normalizePlan", () => {
  it("normalizes addresses, providers and changed paths", () => {
    const p = normalizePlan(
      plan([
        rc("aws_subnet.private", "update", { index: 2, module: "module.vpc", before: { cidr: "a", tags: { x: 1 } }, after: { cidr: "b", tags: { x: 1 } } }),
        rc("aws_s3_bucket.b", "create", { index: "logs", provider: "registry.terraform.io/hashicorp/aws" }),
        rc("aws_ami.x", "read", { mode: "data" }),
      ]),
    );
    const [subnet, bucket, ami] = p.changes;
    expect(subnet?.address).toBe("module.vpc.aws_subnet.private[2]");
    expect(subnet?.baseAddress).toBe("module.vpc.aws_subnet.private");
    expect(subnet?.changedPaths).toEqual(["cidr"]);
    expect(bucket?.baseAddress).toBe("aws_s3_bucket.b");
    expect(bucket?.providerShort).toBe("aws");
    expect(ami?.mode).toBe("data");
  });

  it("collects nested module sources from configuration", () => {
    const p = normalizePlan(
      plan([], {
        configuration: { root_module: { module_calls: { app: { source: "./modules/app", module: { module_calls: { db: { source: "../db" } } } } } } },
      }),
    );
    expect(p.moduleSources).toEqual({ "module.app": "./modules/app", "module.app.module.db": "../db" });
  });

  it("reads real Terraform output: replace paths, moves, imports, forget, drift, outputs", () => {
    const p = normalizePlan(fixture("real/lifecycle.json"));
    const by = (a: string) => p.changes.find((c) => c.address === a);
    expect(by("random_password.db")?.kind).toBe("replace");
    expect(by("random_password.db")?.replacePaths).toEqual(["length"]);
    expect(by("terraform_data.moved_new")?.moved).toBe(true);
    expect(by("terraform_data.moved_new")?.previousAddress).toBe("terraform_data.moved_old");
    expect(by("random_id.imported")?.importing).toBe(true);
    expect(by("terraform_data.forget_me")?.kind).toBe("no-op");
    expect(by("local_file.per_name[2]")?.reason).toBe("delete_because_count_index");
    expect(p.drift.map((d) => d.address)).toEqual(["local_file.drift"]);
    expect(p.outputs.find((o) => o.name === "db_password")?.sensitive).toBe(true);
    expect(p.outputs.find((o) => o.name === "api_token")?.sensitive).toBe(false);
  });

  it("defaults missing optional fields", () => {
    const p = normalizePlan({ format_version: "1.2", resource_changes: [{ address: "x.y", type: "x", name: "y", change: { actions: ["create"] } }] });
    expect(p.terraformVersion).toBe("unknown");
    expect(p.changes[0]?.providerShort).toBe("x");
    expect(p.changes[0]?.after).toBeNull();
    expect(p.errored).toBe(false);
  });
});

describe("summarize", () => {
  it("counts the real lifecycle plan", () => {
    const s = summarize(normalizePlan(fixture("real/lifecycle.json")));
    expect(s).toMatchObject({ create: 2, update: 1, replace: 3, delete: 3, imported: 1, moved: 1, drifted: 1 });
    expect(s.total).toBe(9);
  });
  it("counts data reads separately", () => {
    const s = summarize(normalizePlan(plan([rc("aws_ami.x", "read", { mode: "data" }), rc("aws_s3_bucket.b", "read")])));
    expect(s.read).toBe(2);
    expect(s.total).toBe(0);
  });
});
