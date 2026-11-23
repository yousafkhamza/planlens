import { describe, expect, it } from "vitest";
import {
  anyGlob,
  changedPaths,
  containsSensitive,
  deepEqual,
  formatPath,
  getAll,
  globMatch,
  isSensitiveAt,
  parsePath,
  plural,
  show,
} from "../../src/core/util.js";

describe("paths", () => {
  it("formats and parses round-trip", () => {
    expect(formatPath(["ingress", 0, "cidr_blocks"])).toBe("ingress[0].cidr_blocks");
    expect(parsePath("ingress[0].cidr_blocks")).toEqual(["ingress", 0, "cidr_blocks"]);
    expect(parsePath("a[*].b")).toEqual(["a", "*", "b"]);
  });

  it("getAll fans out over nested-block arrays", () => {
    const obj = { vpc_config: [{ endpoint_public_access: true, cidrs: ["a", "b"] }], tags: { Name: "x" } };
    expect(getAll(obj, "vpc_config.endpoint_public_access")).toEqual([true]);
    expect(getAll(obj, "vpc_config[0].cidrs[1]")).toEqual(["b"]);
    expect(getAll(obj, "tags.Name")).toEqual(["x"]);
    expect(getAll(obj, "tags.*")).toEqual(["x"]);
    expect(getAll(obj, "vpc_config[*].cidrs")).toEqual([["a", "b"]]);
    expect(getAll(obj, "missing.path")).toEqual([]);
    expect(getAll(null, "a")).toEqual([]);
    expect(getAll([1, 2], [5])).toEqual([]);
  });
});

describe("sensitivity masks", () => {
  it("detects sensitive leaves and whole-object masks", () => {
    expect(isSensitiveAt(true, ["anything"])).toBe(true);
    expect(isSensitiveAt({ password: true }, ["password"])).toBe(true);
    expect(isSensitiveAt({ password: true }, ["username"])).toBe(false);
    expect(isSensitiveAt({ env: [{ value: true }] }, ["env", 0, "value"])).toBe(true);
    expect(isSensitiveAt({ env: [{ value: true }] }, ["env", "value"])).toBe(true);
    expect(isSensitiveAt({ a: { b: true } }, ["a"])).toBe(false);
    expect(isSensitiveAt("x", ["a"])).toBe(false);
    expect(containsSensitive({ a: [{ b: true }] })).toBe(true);
    expect(containsSensitive({ a: false })).toBe(false);
  });
});

describe("deepEqual", () => {
  it("treats null and missing keys as equal", () => {
    expect(deepEqual({ a: 1, b: null }, { a: 1 })).toBe(true);
    expect(deepEqual([1, { x: 2 }], [1, { x: 2 }])).toBe(true);
    expect(deepEqual([1], [1, 2])).toBe(false);
    expect(deepEqual({ a: 1 }, { a: 2 })).toBe(false);
    expect(deepEqual("1", 1)).toBe(false);
    expect(deepEqual([1], { 0: 1 })).toBe(false);
  });
});

describe("changedPaths", () => {
  it("lists leaf paths that change or become unknown", () => {
    const before = { name: "a", tags: { env: "dev", team: "x" }, list: [1, 2], id: "i-1" };
    const after = { name: "b", tags: { env: "prod", team: "x" }, list: [1, 3], id: null };
    expect(changedPaths(before, after, { id: true })).toEqual(["id", "list[1]", "name", "tags.env"]);
  });
  it("handles list length changes and new keys", () => {
    expect(changedPaths({ l: [1] }, { l: [1, 2], n: 1 }, {})).toEqual(["l", "n"]);
  });
  it("respects max depth", () => {
    expect(changedPaths({ a: { b: { c: 1 } } }, { a: { b: { c: 2 } } }, {}, 1)).toEqual(["a"]);
  });
});

describe("glob + misc", () => {
  it("matches globs", () => {
    expect(globMatch("aws_fsx_*", "aws_fsx_lustre_file_system")).toBe(true);
    expect(globMatch("module.prod*", "module.production.aws_s3_bucket.x")).toBe(true);
    expect(globMatch("aws_s3_bucket.b[?]", "aws_s3_bucket.b[1]")).toBe(true);
    expect(globMatch('aws_s3_bucket.b["x"]', 'aws_s3_bucket.b["x"]')).toBe(true);
    expect(globMatch("aws_*", "google_x")).toBe(false);
    expect(anyGlob(undefined, "x")).toBe(true);
    expect(anyGlob(["a*", "b*"], "bx")).toBe(true);
  });
  it("renders short values", () => {
    expect(show("x")).toBe('"x"');
    expect(show(undefined)).toBe("(unset)");
    expect(show("y".repeat(200), 10)).toHaveLength(10);
    expect(plural(1, "thing")).toBe("1 thing");
    expect(plural(2, "thing")).toBe("2 things");
  });
});
