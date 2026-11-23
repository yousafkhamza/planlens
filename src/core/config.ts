import { RULES } from "./rules/index.js";
import { type FailOn, type PlanlensConfig, type ResolvedConfig, SEVERITIES, type Severity } from "./types.js";
import { isRecord } from "./util.js";

export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Invalid planlens config:\n  - ${problems.join("\n  - ")}`);
    this.name = "ConfigError";
  }
}

const FAIL_ON: readonly string[] = [...SEVERITIES, "none"];
const TOP_KEYS = new Set(["fail_on", "mass_destroy_threshold", "stateful_types", "critical_types", "disable", "severity_overrides", "ignore", "rules"]);
const ACTIONS = new Set(["create", "update", "delete", "replace", "read", "no-op"]);
const OPS = new Set(["exists", "absent", "equals", "not_equals", "matches", "not_matches", "in", "not_in", "changed"]);

function isStringList(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

/** Validate an untrusted config object (from YAML/JSON). Throws ConfigError listing every problem. */
export function validateConfig(input: unknown): PlanlensConfig {
  if (input === null || input === undefined) return {};
  if (!isRecord(input)) throw new ConfigError(["config must be a mapping/object"]);
  const p: string[] = [];
  const knownIds = new Set(RULES.map((r) => r.id));

  for (const k of Object.keys(input)) if (!TOP_KEYS.has(k)) p.push(`unknown key \`${k}\` (allowed: ${[...TOP_KEYS].join(", ")})`);

  if (input.fail_on !== undefined && !FAIL_ON.includes(String(input.fail_on))) p.push(`fail_on must be one of ${FAIL_ON.join(", ")}`);
  if (input.mass_destroy_threshold !== undefined && (!Number.isInteger(input.mass_destroy_threshold) || (input.mass_destroy_threshold as number) < 1)) {
    p.push("mass_destroy_threshold must be a positive integer");
  }
  for (const key of ["stateful_types", "critical_types", "disable"] as const) {
    if (input[key] !== undefined && !isStringList(input[key])) p.push(`${key} must be a list of strings`);
  }
  if (isStringList(input.disable)) for (const id of input.disable) if (!knownIds.has(id)) p.push(`disable: unknown rule id \`${id}\``);

  if (input.severity_overrides !== undefined) {
    if (!isRecord(input.severity_overrides)) p.push("severity_overrides must be a mapping of rule id → severity");
    else
      for (const [id, sev] of Object.entries(input.severity_overrides)) {
        if (!SEVERITIES.includes(sev as Severity)) p.push(`severity_overrides.${id}: invalid severity \`${String(sev)}\``);
      }
  }

  const customIds = new Set<string>();
  if (input.rules !== undefined) {
    if (!Array.isArray(input.rules)) p.push("rules must be a list");
    else
      input.rules.forEach((r, i) => {
        const at = `rules[${i}]`;
        if (!isRecord(r)) {
          p.push(`${at} must be a mapping`);
          return;
        }
        if (typeof r.id !== "string" || r.id === "") p.push(`${at}.id is required`);
        else if (knownIds.has(r.id)) p.push(`${at}.id \`${r.id}\` collides with a built-in rule`);
        else if (customIds.has(r.id)) p.push(`${at}.id \`${r.id}\` is duplicated`);
        else customIds.add(r.id);
        if (typeof r.title !== "string") p.push(`${at}.title is required`);
        if (!SEVERITIES.includes(r.severity as Severity)) p.push(`${at}.severity must be one of ${SEVERITIES.join(", ")}`);
        if (!isRecord(r.when)) {
          p.push(`${at}.when is required`);
          return;
        }
        const w = r.when;
        for (const k of Object.keys(w)) if (!["actions", "type", "address", "attributes"].includes(k)) p.push(`${at}.when: unknown key \`${k}\``);
        if (w.actions !== undefined && (!isStringList(w.actions) || w.actions.some((a) => !ACTIONS.has(a)))) {
          p.push(`${at}.when.actions must be a list of: ${[...ACTIONS].join(", ")}`);
        }
        for (const k of ["type", "address"] as const) {
          if (w[k] !== undefined && typeof w[k] !== "string" && !isStringList(w[k])) p.push(`${at}.when.${k} must be a string or list of strings`);
        }
        if (w.attributes !== undefined) {
          if (!Array.isArray(w.attributes)) p.push(`${at}.when.attributes must be a list`);
          else
            w.attributes.forEach((c, j) => {
              if (!isRecord(c) || typeof c.path !== "string" || !OPS.has(String(c.op))) {
                p.push(`${at}.when.attributes[${j}] needs \`path\` and \`op\` (${[...OPS].join(", ")})`);
                return;
              }
              if ((c.op === "matches" || c.op === "not_matches") && typeof c.value === "string") {
                try {
                  new RegExp(c.value);
                } catch {
                  p.push(`${at}.when.attributes[${j}].value is not a valid regular expression`);
                }
              }
              if ((c.op === "in" || c.op === "not_in") && !Array.isArray(c.value)) p.push(`${at}.when.attributes[${j}].value must be a list for \`${c.op}\``);
            });
        }
      });
  }

  if (input.ignore !== undefined) {
    if (!Array.isArray(input.ignore)) p.push("ignore must be a list");
    else
      input.ignore.forEach((e, i) => {
        const at = `ignore[${i}]`;
        if (!isRecord(e)) {
          p.push(`${at} must be a mapping`);
          return;
        }
        if (e.rule === undefined && e.address === undefined) p.push(`${at} needs \`rule\` and/or \`address\``);
        if (typeof e.reason !== "string" || e.reason.trim() === "") p.push(`${at}.reason is required — document why the risk is accepted`);
        if (e.rule !== undefined && !knownIds.has(String(e.rule)) && !customIds.has(String(e.rule)))
          p.push(`${at}.rule: unknown rule id \`${String(e.rule)}\``);
        if (e.expires !== undefined) {
          const s = e.expires instanceof Date ? e.expires.toISOString().slice(0, 10) : String(e.expires);
          if (!/^\d{4}-\d{2}-\d{2}$/.test(s) || Number.isNaN(Date.parse(s))) p.push(`${at}.expires must be a date (YYYY-MM-DD)`);
          else e.expires = s;
        }
      });
  }

  if (p.length) throw new ConfigError(p);
  return input as PlanlensConfig;
}

export function resolveConfig(cfg: PlanlensConfig = {}, overrides: { failOn?: FailOn; now?: Date } = {}): ResolvedConfig {
  return {
    failOn: overrides.failOn ?? cfg.fail_on ?? "high",
    massDestroyThreshold: cfg.mass_destroy_threshold ?? 10,
    statefulTypes: new Set(cfg.stateful_types ?? []),
    criticalTypes: new Set(cfg.critical_types ?? []),
    disable: new Set(cfg.disable ?? []),
    severityOverrides: cfg.severity_overrides ?? {},
    ignore: cfg.ignore ?? [],
    rules: cfg.rules ?? [],
    now: overrides.now ?? new Date(),
  };
}
