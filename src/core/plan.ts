import type { ChangeKind, ChangeSummary, NormalizedPlan, OutputChange, RawModuleConfig, RawPlan, RawResourceChange, ResourceChange } from "./types.js";
import { changedPaths, formatPath, isRecord } from "./util.js";

export class PlanParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PlanParseError";
  }
}

/** Parse JSON text and validate it looks like `terraform show -json <planfile>` output. */
export function parsePlanText(text: string): RawPlan {
  let data: unknown;
  try {
    data = JSON.parse(text.replace(/^﻿/, ""));
  } catch (e) {
    throw new PlanParseError(`Input is not valid JSON: ${(e as Error).message}`);
  }
  return assertPlan(data);
}

export function assertPlan(data: unknown): RawPlan {
  if (!isRecord(data)) throw new PlanParseError("Plan JSON must be an object.");
  if (isInfracostJson(data)) {
    throw new PlanParseError(
      "This is Infracost output, not a Terraform plan. Load it as the cost estimate instead (CLI: --infracost infracost.json · web: the Infracost box), " +
        "and give planlens the plan from: terraform show -json tf.plan > plan.json",
    );
  }
  if (!("format_version" in data)) {
    throw new PlanParseError(
      "This does not look like a Terraform plan: missing `format_version`. " +
        "Generate it with: terraform plan -out=tf.plan && terraform show -json tf.plan > plan.json",
    );
  }
  if (!("resource_changes" in data) && !("planned_values" in data) && !("output_changes" in data)) {
    // `terraform show -json` on a *state* file has `values` but no `resource_changes`.
    if ("values" in data) {
      throw new PlanParseError("This is Terraform *state* JSON, not a plan. Run `terraform show -json <planfile>` on a saved plan instead.");
    }
    throw new PlanParseError("Plan JSON has no `resource_changes` — is this a Terraform plan?");
  }
  const major = String(data.format_version).split(".")[0];
  if (major !== "1" && major !== "0") {
    throw new PlanParseError(`Unsupported plan format_version ${String(data.format_version)} (expected 1.x).`);
  }
  if (data.resource_changes !== undefined && !Array.isArray(data.resource_changes)) {
    throw new PlanParseError("`resource_changes` must be an array.");
  }
  return data as RawPlan;
}

export function actionsToKind(actions: readonly string[]): { kind: ChangeKind; createBeforeDestroy: boolean } {
  const a = actions.join(",");
  switch (a) {
    case "create":
      return { kind: "create", createBeforeDestroy: false };
    case "update":
      return { kind: "update", createBeforeDestroy: false };
    case "delete":
      return { kind: "delete", createBeforeDestroy: false };
    case "delete,create":
      return { kind: "replace", createBeforeDestroy: false };
    case "create,delete":
      return { kind: "replace", createBeforeDestroy: true };
    case "read":
      return { kind: "read", createBeforeDestroy: false };
    default:
      // "no-op", "forget" (removed block with destroy = false), unknown future actions
      return { kind: "no-op", createBeforeDestroy: false };
  }
}

function providerShort(providerName: string | undefined, type: string): string {
  if (providerName) {
    const last = providerName.split("/").pop();
    if (last) return last;
  }
  return type.split("_")[0] ?? type;
}

function baseAddressOf(address: string, index: string | number | undefined): string {
  if (index === undefined) return address;
  const suffixes = [`[${JSON.stringify(index)}]`, `[${String(index)}]`];
  for (const s of suffixes) if (address.endsWith(s)) return address.slice(0, -s.length);
  return address.replace(/\[[^\]]*\]$/, "");
}

function asObj(v: unknown): Record<string, unknown> | null {
  return isRecord(v) ? v : null;
}

export function normalizeResourceChange(rc: RawResourceChange): ResourceChange {
  const change = rc.change ?? { actions: ["no-op"] };
  const { kind, createBeforeDestroy } = actionsToKind(change.actions ?? ["no-op"]);
  const before = asObj(change.before);
  const after = asObj(change.after);
  const replacePaths = (change.replace_paths ?? []).map((p) => formatPath(p));
  return {
    address: rc.address,
    baseAddress: baseAddressOf(rc.address, rc.index),
    previousAddress: rc.previous_address,
    moduleAddress: rc.module_address,
    mode: rc.mode === "data" ? "data" : "managed",
    type: rc.type,
    name: rc.name,
    index: rc.index,
    provider: rc.provider_name ?? "",
    providerShort: providerShort(rc.provider_name, rc.type),
    kind,
    createBeforeDestroy,
    reason: rc.action_reason,
    replacePaths,
    before,
    after,
    afterUnknown: change.after_unknown ?? {},
    beforeSensitive: change.before_sensitive ?? {},
    afterSensitive: change.after_sensitive ?? {},
    importing: change.importing !== undefined && change.importing !== null,
    moved: rc.previous_address !== undefined && rc.previous_address !== rc.address,
    deposed: rc.deposed,
    changedPaths: kind === "update" || kind === "replace" || (kind === "no-op" && before && after) ? changedPaths(before, after, change.after_unknown) : [],
  };
}

function collectModuleSources(mod: RawModuleConfig | undefined, prefix: string, out: Record<string, string>): void {
  if (!mod?.module_calls) return;
  for (const [name, call] of Object.entries(mod.module_calls)) {
    const addr = prefix ? `${prefix}.module.${name}` : `module.${name}`;
    if (call.source) out[addr] = call.source;
    collectModuleSources(call.module, addr, out);
  }
}

export function normalizePlan(raw: RawPlan): NormalizedPlan {
  const changes = (raw.resource_changes ?? []).map(normalizeResourceChange);
  const drift = (raw.resource_drift ?? []).map(normalizeResourceChange);
  const outputs: OutputChange[] = Object.entries(raw.output_changes ?? {}).map(([name, ch]) => ({
    name,
    kind: actionsToKind(ch.actions ?? ["no-op"]).kind,
    sensitive: ch.after_sensitive === true || ch.before_sensitive === true,
    before: ch.before,
    after: ch.after,
    afterUnknown: ch.after_unknown === true,
  }));
  const moduleSources: Record<string, string> = {};
  collectModuleSources(raw.configuration?.root_module, "", moduleSources);
  return {
    formatVersion: String(raw.format_version ?? ""),
    terraformVersion: String(raw.terraform_version ?? "unknown"),
    changes,
    drift,
    outputs,
    errored: raw.errored === true,
    applyable: raw.applyable !== false,
    complete: raw.complete !== false,
    moduleSources,
  };
}

export function summarize(plan: NormalizedPlan): ChangeSummary {
  const s: ChangeSummary = {
    create: 0,
    update: 0,
    delete: 0,
    replace: 0,
    read: 0,
    noop: 0,
    imported: 0,
    moved: 0,
    drifted: plan.drift.length,
    total: 0,
  };
  for (const c of plan.changes) {
    if (c.mode === "data") {
      if (c.kind === "read") s.read++;
      continue;
    }
    if (c.kind === "no-op") s.noop++;
    else if (c.kind === "read") s.read++;
    else s[c.kind]++;
    if (c.importing) s.imported++;
    if (c.moved) s.moved++;
  }
  s.total = s.create + s.update + s.delete + s.replace;
  return s;
}

/** Managed resources that actually change (excludes no-op and data reads). */
export function managedChanges(plan: NormalizedPlan): ResourceChange[] {
  return plan.changes.filter((c) => c.mode === "managed" && c.kind !== "no-op" && c.kind !== "read");
}

/** Infracost JSON has `projects` and no Terraform `format_version`. */
export function isInfracostJson(data: unknown): boolean {
  return isRecord(data) && Array.isArray(data.projects) && !("format_version" in data);
}

/** Classify a JSON document so UIs can route dropped/pasted files to the right input. */
export function detectJsonKind(text: string): "plan" | "infracost" | "state" | "unknown" {
  let data: unknown;
  try {
    data = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    return "unknown";
  }
  if (isInfracostJson(data)) return "infracost";
  if (!isRecord(data) || !("format_version" in data)) return "unknown";
  if ("resource_changes" in data || "planned_values" in data || "output_changes" in data) return "plan";
  if ("values" in data) return "state";
  return "unknown";
}
