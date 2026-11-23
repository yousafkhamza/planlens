import type { CostSummary, Rule } from "./types.js";
import { asArray, isRecord } from "./util.js";

export class CostParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CostParseError";
  }
}

function num(v: unknown): number | undefined {
  if (v === null || v === undefined || v === "") return undefined;
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : undefined;
}

/**
 * Normalize `infracost breakdown --format json` or `infracost diff --format json`
 * output. Infracost encodes money as decimal strings.
 */
export function parseInfracost(data: unknown): CostSummary {
  let obj = data;
  if (typeof data === "string") {
    try {
      obj = JSON.parse(data);
    } catch (e) {
      throw new CostParseError(`Infracost file is not valid JSON: ${(e as Error).message}`);
    }
  }
  if (!isRecord(obj) || !Array.isArray(obj.projects)) {
    throw new CostParseError(
      "This does not look like Infracost JSON (missing `projects`). Generate it with: infracost breakdown --path plan.json --format json --out-file infracost.json",
    );
  }
  const projects = obj.projects.filter(isRecord);
  const sumProjects = (pick: (p: Record<string, unknown>) => unknown): number | undefined => {
    const vals = projects.map((p) => num(pick(p))).filter((x): x is number => x !== undefined);
    return vals.length ? vals.reduce((a, b) => a + b, 0) : undefined;
  };
  const monthly = num(obj.totalMonthlyCost) ?? sumProjects((p) => (isRecord(p.breakdown) ? p.breakdown.totalMonthlyCost : undefined));
  const pastMonthly = num(obj.pastTotalMonthlyCost) ?? sumProjects((p) => (isRecord(p.pastBreakdown) ? p.pastBreakdown.totalMonthlyCost : undefined));
  let diffMonthly = num(obj.diffTotalMonthlyCost) ?? sumProjects((p) => (isRecord(p.diff) ? p.diff.totalMonthlyCost : undefined));
  if (diffMonthly === undefined && monthly !== undefined && pastMonthly !== undefined) diffMonthly = monthly - pastMonthly;

  const deltas = new Map<string, number>();
  for (const p of projects) {
    const prefix = projects.length > 1 && typeof p.name === "string" ? `${p.name}: ` : "";
    for (const r of asArray<unknown>(isRecord(p.diff) ? p.diff.resources : undefined)) {
      if (!isRecord(r) || typeof r.name !== "string") continue;
      const d = num(r.monthlyCost);
      if (d === undefined || Math.abs(d) < 0.005) continue;
      deltas.set(`${prefix}${r.name}`, (deltas.get(`${prefix}${r.name}`) ?? 0) + d);
    }
  }
  const resources = [...deltas.entries()]
    .map(([address, diff]) => ({ address, diffMonthly: Math.round(diff * 100) / 100 }))
    .sort((a, b) => Math.abs(b.diffMonthly) - Math.abs(a.diffMonthly))
    .slice(0, 20);

  const round = (n: number | undefined) => (n === undefined ? undefined : Math.round(n * 100) / 100);
  return {
    currency: typeof obj.currency === "string" && obj.currency ? obj.currency : "USD",
    pastMonthly: round(pastMonthly),
    monthly: round(monthly),
    diffMonthly: round(diffMonthly),
    resources,
  };
}

export function formatMoney(n: number, currency: string, signed = false): string {
  let s: string;
  try {
    s = new Intl.NumberFormat("en-US", { style: "currency", currency, minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(Math.abs(n));
  } catch {
    s = `${Math.abs(n).toFixed(2)} ${currency}`;
  }
  if (n < 0) return `-${s}`;
  return signed ? `+${s}` : s;
}

/** "+$412.30/mo (+34%)" */
export function describeCostDelta(c: CostSummary): string | undefined {
  if (c.diffMonthly === undefined) return undefined;
  const pct = c.pastMonthly && c.pastMonthly > 0 ? ` (${c.diffMonthly >= 0 ? "+" : ""}${Math.round((c.diffMonthly / c.pastMonthly) * 100)}%)` : "";
  return `${formatMoney(c.diffMonthly, c.currency, true)}/mo${pct}`;
}

export const costIncrease: Rule = {
  id: "PL501",
  title: "Monthly cost increase above budget",
  severity: "high",
  category: "cost",
  description:
    "The Infracost estimate for this plan raises the monthly bill by more than `cost.max_monthly_increase` (absolute) or `cost.max_monthly_increase_percent`. Only active when an Infracost file is provided and a threshold is configured.",
  remediation:
    "Check the largest cost deltas (instance sizes, NAT gateways, provisioned IOPS, data transfer). Right-size, use Savings Plans/Spot, or get the budget owner's approval and record it with an `ignore` entry.",
  run({ cost, config }) {
    if (!cost || cost.diffMonthly === undefined || cost.diffMonthly <= 0) return [];
    const reasons: string[] = [];
    if (config.costMaxIncrease !== undefined && cost.diffMonthly > config.costMaxIncrease) {
      reasons.push(`more than ${formatMoney(config.costMaxIncrease, cost.currency)}/mo`);
    }
    if (config.costMaxIncreasePercent !== undefined && cost.pastMonthly && cost.pastMonthly > 0) {
      const pct = (cost.diffMonthly / cost.pastMonthly) * 100;
      if (pct > config.costMaxIncreasePercent) reasons.push(`more than ${config.costMaxIncreasePercent}%`);
    }
    if (reasons.length === 0) return [];
    const top = cost.resources.filter((r) => r.diffMonthly > 0).slice(0, 5);
    return [
      {
        severity: "high",
        address: "(plan)",
        message: `Estimated monthly cost rises by ${describeCostDelta(cost)} — ${reasons.join(" and ")}.`,
        details: top.length ? [`Largest increases: ${top.map((r) => `\`${r.address}\` ${formatMoney(r.diffMonthly, cost.currency, true)}`).join(", ")}`] : [],
      },
    ];
  },
};
