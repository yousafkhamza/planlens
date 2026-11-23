import { CRITICAL_TYPES, PUBLIC_WEB_PORTS, SENSITIVE_PORTS, STATEFUL_TYPES } from "../catalog.js";
import type { Finding, ResolvedConfig, ResourceChange, Severity } from "../types.js";
import { anyGlob, getAll, isSensitiveAt, parsePath, SENSITIVE, show, UNKNOWN } from "../util.js";

export type Hit = Omit<Finding, "ruleId" | "category" | "title">;

export function isStateful(type: string, cfg: ResolvedConfig): boolean {
  return anyGlob([...STATEFUL_TYPES, ...cfg.statefulTypes], type);
}

export function isCritical(type: string, cfg: ResolvedConfig): boolean {
  return anyGlob([...CRITICAL_TYPES, ...cfg.criticalTypes], type);
}

/** First value at path on the given side. */
export function v(rc: ResourceChange, side: "before" | "after", path: string): unknown {
  return getAll(side === "before" ? rc.before : rc.after, path)[0];
}

export function all(rc: ResourceChange, side: "before" | "after", path: string): unknown[] {
  return getAll(side === "before" ? rc.before : rc.after, path);
}

/** Is the attribute going to be computed at apply time? */
export function isUnknown(rc: ResourceChange, path: string): boolean {
  return getAll(rc.afterUnknown, path).some((x) => x === true);
}

/** Render a value for a report, honouring sensitive masks and unknowns. */
export function display(rc: ResourceChange, side: "before" | "after", path: string): string {
  const mask = side === "before" ? rc.beforeSensitive : rc.afterSensitive;
  if (isSensitiveAt(mask, parsePath(path))) return SENSITIVE;
  if (side === "after" && isUnknown(rc, path)) return UNKNOWN;
  return show(v(rc, side, path));
}

/**
 * A condition is "introduced" when it holds after the change but did not hold
 * before (or the resource is new). This keeps findings focused on regressions
 * the PR causes — not on pre-existing debt.
 */
export function introduced(rc: ResourceChange, test: (obj: Record<string, unknown>) => boolean): boolean {
  if (rc.kind !== "create" && rc.kind !== "update" && rc.kind !== "replace") return false;
  if (!rc.after || !test(rc.after)) return false;
  return !rc.before || rc.kind === "create" || !test(rc.before);
}

/** Changes that modify or create a resource (have an `after`). */
export function writes(rc: ResourceChange): boolean {
  return rc.mode === "managed" && (rc.kind === "create" || rc.kind === "update" || rc.kind === "replace");
}

export function destroys(rc: ResourceChange): boolean {
  return rc.mode === "managed" && (rc.kind === "delete" || rc.kind === "replace");
}

export const REASON_TEXT: Record<string, string> = {
  replace_because_cannot_update: "an attribute that cannot be updated in place changed",
  replace_because_tainted: "the resource is tainted (a previous apply failed or `terraform taint` was used)",
  replace_by_request: "`-replace` was requested explicitly",
  replace_by_triggers: "a `replace_triggered_by` reference changed",
  delete_because_no_resource_config: "the resource block was removed from configuration",
  delete_because_wrong_repetition: "`count`/`for_each` was added or removed on the block",
  delete_because_count_index: "its `count` index no longer exists",
  delete_because_each_key: "its `for_each` key no longer exists",
  delete_because_no_module: "its module call was removed",
  delete_because_no_move_target: "a `moved` block points to an address that does not exist",
};

/** Detail lines that explain why Terraform will destroy/replace something. */
export function destroyDetails(rc: ResourceChange): string[] {
  const d: string[] = [];
  if (rc.reason && REASON_TEXT[rc.reason]) d.push(`Why: ${REASON_TEXT[rc.reason]}.`);
  if (rc.kind === "replace" && rc.replacePaths.length > 0) {
    const shown = rc.replacePaths.slice(0, 6).map((p) => `\`${p}\`: ${display(rc, "before", p)} → ${display(rc, "after", p)}`);
    d.push(`Forced by: ${shown.join(", ")}${rc.replacePaths.length > 6 ? ` (+${rc.replacePaths.length - 6} more)` : ""}`);
  }
  if (["deletion_protection", "deletion_protection_enabled", "enable_deletion_protection"].some((k) => rc.before?.[k] === true)) {
    d.push("Deletion protection is ON for the existing object — the apply will fail at the destroy step unless protection is disabled first.");
  }
  if (rc.kind === "replace") {
    d.push(
      rc.createBeforeDestroy
        ? "Order: create-before-destroy (new object is created first)."
        : "Order: destroy-then-create — expect downtime between the two steps.",
    );
  }
  return d;
}

// ---------------------------------------------------------------------------
// Ports / exposure
// ---------------------------------------------------------------------------

export type PortRange = [number, number];

/** Parse "22", "1000-2000", "*", numbers. Returns null for "all ports". */
export function parsePortRange(p: unknown): PortRange | null | undefined {
  if (p === undefined || p === null) return undefined;
  const s = String(p).trim();
  if (s === "*" || s === "" || s === "0-65535" || s === "1-65535") return null;
  const m = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(s);
  if (!m) return undefined;
  const from = Number(m[1]);
  const to = m[2] !== undefined ? Number(m[2]) : from;
  if (from <= 1 && to >= 65535) return null;
  return [from, to];
}

export interface Exposure {
  severity: Severity;
  label: string;
}

/** Severity of exposing these port ranges to the internet. `null` entry = all ports. */
export function exposureSeverity(ranges: Array<PortRange | null>): Exposure {
  if (ranges.some((r) => r === null)) return { severity: "critical", label: "all ports" };
  const concrete = ranges as PortRange[];
  const hits: string[] = [];
  for (const [port, name] of Object.entries(SENSITIVE_PORTS)) {
    const n = Number(port);
    if (concrete.some(([a, b]) => n >= a && n <= b)) hits.push(`${n} (${name})`);
  }
  const label = concrete.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(", ");
  if (hits.length > 0) {
    return { severity: "critical", label: `${label} — includes ${hits.slice(0, 5).join(", ")}${hits.length > 5 ? "…" : ""}` };
  }
  const onlyWeb = concrete.every(([a, b]) => a === b && PUBLIC_WEB_PORTS.has(a));
  if (onlyWeb) return { severity: "low", label };
  return { severity: "high", label };
}

export const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function maxSeverity(list: Severity[]): Severity | undefined {
  let best: Severity | undefined;
  for (const s of list) if (!best || SEVERITY_RANK[s] > SEVERITY_RANK[best]) best = s;
  return best;
}
