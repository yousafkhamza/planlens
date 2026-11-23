import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { analyzePlan } from "../src/core/engine.js";
import type { Finding, PlanlensConfig, RawPlan, RawResourceChange, Report } from "../src/core/types.js";

export const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));

export function fixture(name: string): RawPlan {
  return JSON.parse(readFileSync(`${FIXTURES}${name}`, "utf8")) as RawPlan;
}

type Actions = "create" | "update" | "delete" | "replace" | "replace-cbd" | "no-op" | "read" | "forget";

const ACTIONS: Record<Actions, string[]> = {
  create: ["create"],
  update: ["update"],
  delete: ["delete"],
  replace: ["delete", "create"],
  "replace-cbd": ["create", "delete"],
  "no-op": ["no-op"],
  read: ["read"],
  forget: ["forget"],
};

export interface RcOpts {
  before?: Record<string, unknown> | null;
  after?: Record<string, unknown> | null;
  afterUnknown?: unknown;
  beforeSensitive?: unknown;
  afterSensitive?: unknown;
  replacePaths?: Array<Array<string | number>>;
  reason?: string;
  index?: string | number;
  module?: string;
  previous?: string;
  importing?: boolean;
  mode?: "managed" | "data";
  provider?: string;
}

/** Build a resource_changes entry. `addr` is "type.name" (module prefix via opts.module). */
export function rc(addr: string, actions: Actions, o: RcOpts = {}): RawResourceChange {
  const [type, name] = addr.split(".") as [string, string];
  const idx = o.index === undefined ? "" : typeof o.index === "number" ? `[${o.index}]` : `[${JSON.stringify(o.index)}]`;
  const address = `${o.module ? `${o.module}.` : ""}${o.mode === "data" ? "data." : ""}${addr}${idx}`;
  const isCreate = actions === "create";
  const isDelete = actions === "delete";
  return {
    address,
    module_address: o.module,
    mode: o.mode ?? "managed",
    type,
    name,
    index: o.index,
    provider_name: o.provider ?? `registry.terraform.io/hashicorp/${type.split("_")[0]}`,
    previous_address: o.previous,
    action_reason: o.reason,
    change: {
      actions: ACTIONS[actions],
      before: isCreate ? null : (o.before ?? {}),
      after: isDelete ? null : (o.after ?? {}),
      after_unknown: o.afterUnknown ?? {},
      before_sensitive: o.beforeSensitive ?? (isCreate ? false : {}),
      after_sensitive: o.afterSensitive ?? (isDelete ? false : {}),
      replace_paths: o.replacePaths,
      importing: o.importing ? { id: "x" } : undefined,
    },
  };
}

export function plan(changes: RawResourceChange[], extra: Partial<RawPlan> = {}): RawPlan {
  return { format_version: "1.2", terraform_version: "1.9.8", resource_changes: changes, ...extra };
}

export function analyze(changes: RawResourceChange[] | RawPlan, config: PlanlensConfig = {}, extra: Partial<RawPlan> = {}): Report {
  const raw = Array.isArray(changes) ? plan(changes, extra) : changes;
  return analyzePlan(raw, { config, now: new Date("2026-06-01T00:00:00Z") });
}

export function ids(report: Report): string[] {
  return report.findings.map((f) => f.ruleId);
}

export function byRule(report: Report, id: string): Finding[] {
  return report.findings.filter((f) => f.ruleId === id);
}

export function policy(...statements: Array<Record<string, unknown>>): string {
  return JSON.stringify({ Version: "2012-10-17", Statement: statements });
}
