import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CostParseError, describeCostDelta, formatMoney, parseInfracost } from "../../src/core/cost.js";
import { analyzePlan } from "../../src/core/engine.js";
import { renderMarkdown } from "../../src/report/markdown.js";
import { renderText } from "../../src/report/text.js";
import { byRule, FIXTURES, fixture, ids } from "../helpers.js";

const infracost = () => readFileSync(`${FIXTURES}infracost/prod-change.json`, "utf8");

describe("parseInfracost", () => {
  it("reads totals and per-resource deltas from Infracost JSON", () => {
    const c = parseInfracost(infracost());
    expect(c).toMatchObject({ currency: "USD", pastMonthly: 2140.5, monthly: 2552.8, diffMonthly: 412.3 });
    expect(c.resources).toEqual([
      { address: "module.data.aws_db_instance.payments", diffMonthly: 380.2 },
      { address: "aws_ecs_service.worker", diffMonthly: 32.1 },
    ]);
  });

  it("falls back to summing projects and computing the diff", () => {
    const c = parseInfracost({
      currency: "EUR",
      projects: [
        {
          name: "a",
          pastBreakdown: { totalMonthlyCost: "10" },
          breakdown: { totalMonthlyCost: "25" },
          diff: { resources: [{ name: "x.y", monthlyCost: "15" }] },
        },
        {
          name: "b",
          pastBreakdown: { totalMonthlyCost: "5" },
          breakdown: { totalMonthlyCost: "1" },
          diff: { resources: [{ name: "x.y", monthlyCost: "-4" }, { name: "bad" }, "junk"] },
        },
      ],
    });
    expect(c).toMatchObject({ currency: "EUR", pastMonthly: 15, monthly: 26, diffMonthly: 11 });
    expect(c.resources.map((r) => r.address)).toEqual(["a: x.y", "b: x.y"]);
  });

  it("handles breakdown-only output (no past cost)", () => {
    const c = parseInfracost({ projects: [{ breakdown: { totalMonthlyCost: "99.999" } }], totalMonthlyCost: null });
    expect(c).toEqual({ currency: "USD", pastMonthly: undefined, monthly: 100, diffMonthly: undefined, resources: [] });
    expect(describeCostDelta(c)).toBeUndefined();
  });

  it("rejects non-Infracost input with a hint", () => {
    expect(() => parseInfracost("{oops")).toThrow(CostParseError);
    expect(() => parseInfracost({ format_version: "1.2" })).toThrow(/infracost breakdown --path plan.json/);
  });

  it("formats money and deltas", () => {
    expect(formatMoney(1234.5, "USD")).toBe("$1,234.50");
    expect(formatMoney(-3, "USD")).toBe("-$3.00");
    expect(formatMoney(3, "USD", true)).toBe("+$3.00");
    expect(formatMoney(3, "NOT-A-CURRENCY")).toBe("3.00 NOT-A-CURRENCY");
    expect(describeCostDelta({ currency: "USD", pastMonthly: 100, diffMonthly: -25, resources: [] })).toBe("-$25.00/mo (-25%)");
    expect(describeCostDelta({ currency: "USD", diffMonthly: 5, resources: [] })).toBe("+$5.00/mo");
  });
});

describe("cost in reports and PL501", () => {
  const plan = () => fixture("../../docs/samples/prod-change.json");

  it("attaches cost to the report and renders it", () => {
    const r = analyzePlan(plan(), { cost: infracost(), name: "prod" });
    expect(r.cost?.diffMonthly).toBe(412.3);
    expect(ids(r)).not.toContain("PL501"); // no threshold configured
    const md = renderMarkdown([r]);
    expect(md).toContain("💰 **Cost:** $2,140.50 → $2,552.80 /mo (**+$412.30/mo (+19%)**)");
    expect(md).toContain("| `module.data.aws_db_instance.payments` | +$380.20 |");
    expect(renderText([r])).toMatch(/Cost \$2,552\.80\/mo \+\$412\.30\/mo \(\+19%\)/);
  });

  it("fires PL501 on absolute and percentage thresholds", () => {
    const abs = analyzePlan(plan(), { cost: infracost(), config: { cost: { max_monthly_increase: 400 } } });
    const f = byRule(abs, "PL501")[0];
    expect(f?.severity).toBe("high");
    expect(f?.message).toContain("more than $400.00/mo");
    expect(f?.details[0]).toContain("`module.data.aws_db_instance.payments` +$380.20");
    const pct = analyzePlan(plan(), { cost: infracost(), config: { cost: { max_monthly_increase_percent: 10, max_monthly_increase: 1000 } } });
    expect(byRule(pct, "PL501")[0]?.message).toMatch(/more than 10%/);
    expect(byRule(pct, "PL501")[0]?.message).not.toMatch(/\$1,000/);
    const under = analyzePlan(plan(), { cost: infracost(), config: { cost: { max_monthly_increase: 500, max_monthly_increase_percent: 50 } } });
    expect(ids(under)).not.toContain("PL501");
  });

  it("does not fire on savings or without cost data", () => {
    const saving = { currency: "USD", pastMonthly: 100, monthly: 50, diffMonthly: -50, resources: [] };
    expect(ids(analyzePlan(plan(), { cost: saving, config: { cost: { max_monthly_increase: 0 } } }))).not.toContain("PL501");
    expect(ids(analyzePlan(plan(), { config: { cost: { max_monthly_increase: 0 } } }))).not.toContain("PL501");
  });

  it("validates the cost config block", () => {
    expect(() => analyzePlan(plan(), { config: { cost: { max_monthly_increase: -1 } } as never })).toThrow(/non-negative number/);
    expect(() => analyzePlan(plan(), { config: { cost: { budget: 1 } } as never })).toThrow(/unknown key `budget`/);
    expect(() => analyzePlan(plan(), { config: { cost: 5 } as never })).toThrow(/cost must be a mapping/);
  });
});
