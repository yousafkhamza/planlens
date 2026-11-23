import { VERSION } from "../version.js";
import { resolveConfig, validateConfig } from "./config.js";
import { parseInfracost } from "./cost.js";
import { runCustomRules } from "./custom.js";
import { assertPlan, managedChanges, normalizePlan, summarize } from "./plan.js";
import { SEVERITY_RANK } from "./rules/helpers.js";
import { RULES } from "./rules/index.js";
import type { CostSummary, FailOn, Finding, NormalizedPlan, PlanlensConfig, Report, ResolvedConfig, RiskLevel, Severity } from "./types.js";
import { globMatch } from "./util.js";

export interface AnalyzeOptions {
  /** Raw (validated here) or already-resolved config. */
  config?: PlanlensConfig | ResolvedConfig;
  /** CLI/Action override of fail_on. */
  failOn?: FailOn;
  name?: string;
  now?: Date;
  /** Infracost JSON (raw object/string) or an already-parsed CostSummary. */
  cost?: unknown;
}

function isCostSummary(v: unknown): v is CostSummary {
  return typeof v === "object" && v !== null && "resources" in v && "currency" in v && !("projects" in v);
}

const WEIGHT: Record<Severity, number> = { critical: 0.5, high: 0.25, medium: 0.08, low: 0.02, info: 0 };

/** 0–100. Saturating: one critical = 50, two = 75, a high = 25, a medium = 8 … */
export function riskScore(findings: Pick<Finding, "severity">[]): number {
  let safe = 1;
  for (const f of findings) safe *= 1 - WEIGHT[f.severity];
  return Math.round((1 - safe) * 100);
}

export function riskLevel(findings: Pick<Finding, "severity">[]): RiskLevel {
  let level: RiskLevel = "none";
  for (const f of findings) {
    if (f.severity === "info") continue;
    if (level === "none" || SEVERITY_RANK[f.severity] > SEVERITY_RANK[level]) level = f.severity;
  }
  return level;
}

export function gatePasses(findings: Pick<Finding, "severity">[], failOn: FailOn): boolean {
  if (failOn === "none") return true;
  return !findings.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[failOn]);
}

function isResolved(c: PlanlensConfig | ResolvedConfig | undefined): c is ResolvedConfig {
  return !!c && (c as ResolvedConfig).statefulTypes instanceof Set;
}

function today(now: Date): string {
  return now.toISOString().slice(0, 10);
}

export function analyzePlan(rawInput: unknown, opts: AnalyzeOptions = {}): Report {
  const raw = assertPlan(rawInput);
  const plan = normalizePlan(raw);
  const config = isResolved(opts.config)
    ? { ...opts.config, failOn: opts.failOn ?? opts.config.failOn }
    : resolveConfig(validateConfig(opts.config ?? {}), { failOn: opts.failOn, now: opts.now });
  const cost = opts.cost === undefined || opts.cost === null ? undefined : isCostSummary(opts.cost) ? opts.cost : parseInfracost(opts.cost);
  return analyzeNormalized(plan, config, opts.name ?? "plan", cost);
}

export function analyzeNormalized(plan: NormalizedPlan, config: ResolvedConfig, name: string, cost?: CostSummary): Report {
  const warnings: string[] = [];
  if (plan.errored) warnings.push("Terraform reported errors while planning — this plan is partial and the review may miss changes.");
  if (!plan.complete) warnings.push("The plan is incomplete (deferred actions); another plan/apply round will be needed.");
  // Terraform sets applyable=false on no-op plans too; only worth a warning when there are changes.
  if (!plan.applyable && !plan.errored && managedChanges(plan).length > 0) warnings.push("Terraform marked this plan as not applyable.");
  if (cost && cost.resources.length > 0) {
    const addrs = new Set(plan.changes.flatMap((c) => [c.address, c.baseAddress]));
    const strip = (a: string) => a.replace(/^[^:]+: (?=\S+\.)/, "");
    if (!cost.resources.some((r) => addrs.has(strip(r.address)))) {
      warnings.push(
        "The Infracost estimate does not mention any resource in this plan — it was probably generated from a different plan. Re-run `infracost breakdown --path plan.json` on this plan.",
      );
    }
  }

  let findings: Finding[] = [];
  for (const rule of RULES) {
    if (config.disable.has(rule.id)) continue;
    try {
      for (const hit of rule.run({ plan, config, cost })) {
        findings.push({ ...hit, ruleId: rule.id, category: rule.category, title: rule.title, remediation: hit.remediation ?? rule.remediation });
      }
    } catch (e) {
      warnings.push(`Rule ${rule.id} failed and was skipped: ${(e as Error).message}`);
    }
  }
  try {
    findings.push(...runCustomRules(config.rules, managedChanges(plan)).filter((f) => !config.disable.has(f.ruleId)));
  } catch (e) {
    warnings.push(`Custom rules failed: ${(e as Error).message}`);
  }

  // Severity overrides.
  findings = findings.map((f) => {
    const s = config.severityOverrides[f.ruleId];
    return s ? { ...f, severity: s } : f;
  });

  // De-duplicate.
  const seen = new Set<string>();
  findings = findings.filter((f) => {
    const k = `${f.ruleId}|${f.address}|${f.message}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  // Ignores (with expiry).
  const now = today(config.now);
  const used = new Set<number>();
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) {
    const idx = config.ignore.findIndex((e) => (e.rule === undefined || e.rule === f.ruleId) && (e.address === undefined || globMatch(e.address, f.address)));
    const entry = idx >= 0 ? config.ignore[idx] : undefined;
    if (entry) {
      used.add(idx);
      if (entry.expires && entry.expires < now) {
        active.push(f);
        continue;
      }
      suppressed.push({ ...f, suppressed: { reason: entry.reason, expires: entry.expires } });
    } else active.push(f);
  }
  config.ignore.forEach((e, i) => {
    const what = [e.rule, e.address].filter(Boolean).join(" @ ");
    if (e.expires && e.expires < now && used.has(i)) warnings.push(`Ignore for ${what} expired on ${e.expires} — the finding is active again.`);
  });

  const order = (f: Finding) => -SEVERITY_RANK[f.severity];
  active.sort((a, b) => order(a) - order(b) || a.ruleId.localeCompare(b.ruleId) || a.address.localeCompare(b.address));
  suppressed.sort((a, b) => order(a) - order(b) || a.address.localeCompare(b.address));

  return {
    schemaVersion: 1,
    tool: { name: "planlens", version: VERSION },
    name,
    terraformVersion: plan.terraformVersion,
    summary: summarize(plan),
    score: riskScore(active),
    level: riskLevel(active),
    failOn: config.failOn,
    passed: gatePasses(active, config.failOn),
    findings: active,
    suppressed,
    warnings,
    cost,
    changes: managedChanges(plan).map((c) => ({
      address: c.address,
      type: c.type,
      kind: c.kind,
      reason: c.reason,
      replacePaths: c.replacePaths,
      changedPaths: c.changedPaths,
      previousAddress: c.previousAddress,
      importing: c.importing,
    })),
  };
}
