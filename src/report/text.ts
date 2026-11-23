import { describeCostDelta, formatMoney } from "../core/cost.js";
import type { Report, RiskLevel, Severity } from "../core/types.js";
import { overallPassed } from "./common.js";

export interface TextOptions {
  color?: boolean;
  /** Show low/info findings and the full change list. */
  verbose?: boolean;
}

const CODES = { reset: 0, bold: 1, dim: 2, red: 31, green: 32, yellow: 33, blue: 34, magenta: 35, cyan: 36, gray: 90 } as const;
type Color = keyof typeof CODES;

export function renderText(reports: Report[], opts: TextOptions = {}): string {
  const c = (color: Color, s: string) => (opts.color ? `\u001b[${CODES[color]}m${s}\u001b[0m` : s);
  const sevColor: Record<Severity | "none", Color> = { critical: "red", high: "magenta", medium: "yellow", low: "blue", info: "gray", none: "green" };
  const tag = (s: Severity | RiskLevel) => c(sevColor[s], c("bold", s.toUpperCase().padEnd(8)));
  const strip = (s: string) => s.replace(/`/g, "");
  const out: string[] = [];

  for (const r of reports) {
    const s = r.summary;
    out.push("");
    out.push(`${c("bold", "planlens")} ${c("dim", `v${r.tool.version}`)}  ${c("cyan", r.name)}  ${c("dim", `terraform ${r.terraformVersion}`)}`);
    out.push(
      `  ${c("green", `+${s.create} create`)}  ${c("yellow", `~${s.update} update`)}  ${c("magenta", `±${s.replace} replace`)}  ${c("red", `-${s.delete} destroy`)}` +
        (s.imported ? `  ${c("cyan", `${s.imported} import`)}` : "") +
        (s.moved ? `  ${c("cyan", `${s.moved} moved`)}` : "") +
        (s.drifted ? `  ${c("yellow", `${s.drifted} drifted`)}` : ""),
    );
    out.push(`  Risk ${c("bold", `${r.score}/100`)} ${tag(r.level)}`);
    const delta = r.cost ? describeCostDelta(r.cost) : undefined;
    if (r.cost && (delta || r.cost.monthly !== undefined)) {
      const total = r.cost.monthly !== undefined ? `${formatMoney(r.cost.monthly, r.cost.currency)}/mo` : "";
      out.push(
        `  Cost ${c("bold", total)}${delta ? ` ${c(r.cost.diffMonthly && r.cost.diffMonthly > 0 ? "yellow" : "green", delta)}` : ""} ${c("dim", "(Infracost)")}`,
      );
    }
    for (const w of r.warnings) out.push(`  ${c("yellow", "warning:")} ${w}`);
    out.push("");

    const shown = opts.verbose ? r.findings : r.findings.filter((f) => f.severity !== "info" && f.severity !== "low");
    for (const f of shown) {
      out.push(`  ${tag(f.severity)} ${c("dim", f.ruleId)}  ${strip(f.message)}`);
      for (const d of f.details) {
        for (const line of strip(d).split("\n")) if (line.trim() && !line.startsWith("hcl")) out.push(`  ${" ".repeat(9)}${c("dim", "│")} ${line}`);
      }
    }
    const hidden = r.findings.length - shown.length;
    if (hidden > 0) out.push(c("dim", `  …${hidden} low/info finding(s) hidden (use --verbose)`));
    if (r.suppressed.length) out.push(c("dim", `  ${r.suppressed.length} finding(s) suppressed by config ignores`));
    if (r.findings.length === 0) out.push(`  ${c("green", "✓")} No risky changes found.`);

    if (opts.verbose && r.changes.length) {
      out.push("", c("bold", "  Changes:"));
      for (const ch of r.changes) out.push(`    ${ch.kind.padEnd(8)} ${ch.address}`);
    }
    out.push("");
  }

  const passed = overallPassed(reports);
  const failOn = reports[0]?.failOn ?? "high";
  out.push(passed ? c("green", `✓ Gate passed (fail-on: ${failOn})`) : c("red", c("bold", `✗ Gate failed: findings at or above "${failOn}" severity`)));
  return `${out.join("\n")}\n`;
}
