import { describeCostDelta, formatMoney } from "../core/cost.js";
import type { Finding, Report } from "../core/types.js";
import { plural } from "../core/util.js";
import { countBySeverity, DOCS_URL, KIND_ICON, KIND_LABEL, LEVEL_ICON, overallPassed, RULES_URL, SEVERITY_ICON } from "./common.js";

/** GitHub rejects comments over 65,536 chars; stay well under. */
export const MAX_COMMENT_CHARS = 60_000;

export interface MarkdownOptions {
  /** Hidden marker used to find and update the sticky PR comment. */
  marker?: string;
  /** Shown when the gate was overridden by an accept-risk label. */
  acceptedBy?: string;
  /** Link to the CI run, for the "truncated" note. */
  runUrl?: string;
}

function cell(s: string): string {
  return s.replace(/\r?\n/g, " ").replace(/\|/g, "\\|");
}

function summaryTable(r: Report): string {
  const s = r.summary;
  const head = "| ➕ Create | 🔄 Update | ♻️ Replace | 🗑️ Destroy | 📥 Import | 🚚 Move | ⚠️ Drift |";
  const sep = "|:-:|:-:|:-:|:-:|:-:|:-:|:-:|";
  const b = (n: number) => (n > 0 ? `**${n}**` : "0");
  return `${head}\n${sep}\n| ${b(s.create)} | ${b(s.update)} | ${b(s.replace)} | ${b(s.delete)} | ${b(s.imported)} | ${b(s.moved)} | ${b(s.drifted)} |`;
}

function findingsTable(findings: Finding[]): string {
  const rows = findings.map((f) => `| ${SEVERITY_ICON[f.severity]} ${f.severity.toUpperCase()} | \`${f.ruleId}\` | ${cell(f.message)} |`);
  return `| Severity | Rule | Finding |\n|---|---|---|\n${rows.join("\n")}`;
}

function findingDetails(findings: Finding[]): string {
  return findings
    .map((f) => {
      const lines = [`#### ${SEVERITY_ICON[f.severity]} ${f.ruleId} · ${f.title}`, "", f.message];
      for (const d of f.details) lines.push("", d.includes("```") ? d : `- ${d}`);
      if (f.remediation) lines.push("", `**Fix:** ${f.remediation}`);
      return lines.join("\n");
    })
    .join("\n\n");
}

function changesList(r: Report): string {
  const order = ["delete", "replace", "update", "create"] as const;
  const out: string[] = [];
  for (const kind of order) {
    const list = r.changes.filter((c) => c.kind === kind);
    if (list.length === 0) continue;
    out.push(`**${KIND_ICON[kind]} ${KIND_LABEL[kind]} (${list.length})**`, "");
    for (const c of list.slice(0, 200)) {
      let extra = "";
      if (c.kind === "replace" && c.replacePaths.length)
        extra = ` — forced by ${c.replacePaths
          .slice(0, 3)
          .map((p) => `\`${p}\``)
          .join(", ")}`;
      else if (c.kind === "update" && c.changedPaths.length)
        extra = ` — ${c.changedPaths
          .slice(0, 4)
          .map((p) => `\`${p}\``)
          .join(", ")}${c.changedPaths.length > 4 ? "…" : ""}`;
      out.push(`- \`${c.address}\`${c.importing ? " (import)" : ""}${extra}`);
    }
    if (list.length > 200) out.push(`- …and ${list.length - 200} more`);
    out.push("");
  }
  return out.join("\n");
}

/** "💰 **Cost:** $1,200.00 → $1,612.30 /mo (**+$412.30/mo (+34%)**) · Infracost estimate" */
export function costLine(r: Report): string | undefined {
  const c = r.cost;
  if (!c || (c.monthly === undefined && c.diffMonthly === undefined)) return undefined;
  const parts: string[] = [];
  if (c.pastMonthly !== undefined && c.monthly !== undefined)
    parts.push(`${formatMoney(c.pastMonthly, c.currency)} → ${formatMoney(c.monthly, c.currency)} /mo`);
  else if (c.monthly !== undefined) parts.push(`${formatMoney(c.monthly, c.currency)} /mo`);
  const delta = describeCostDelta(c);
  if (delta) parts.push(`(**${delta}**)`);
  return `💰 **Cost:** ${parts.join(" ")} · Infracost estimate`;
}

function headline(r: Report): string {
  const c = countBySeverity(r);
  const parts = (["critical", "high", "medium", "low"] as const).filter((s) => c[s] > 0).map((s) => `${c[s]} ${s}`);
  return parts.length ? parts.join(" · ") : "no risky changes found";
}

interface Section {
  priority: number; // higher = dropped first when over the size limit
  text: string;
}

function reportSections(r: Report, multi: boolean): Section[] {
  const s: Section[] = [];
  const titlePrefix = multi ? "### " : "## ";
  const gate = r.passed ? "✅ passed" : `❌ failed (fail-on: \`${r.failOn}\`)`;
  s.push({
    priority: 0,
    text: [
      `${titlePrefix}${LEVEL_ICON[r.level]} ${multi ? `\`${r.name}\`` : "planlens"} — Risk **${r.score}/100** · ${r.level.toUpperCase()}`,
      "",
      `${multi ? "" : `\`${r.name}\` · `}Terraform ${r.terraformVersion} · ${headline(r)} · Gate ${gate}`,
      "",
      summaryTable(r),
    ].join("\n"),
  });
  const cost = costLine(r);
  if (cost) s.push({ priority: 0, text: cost });
  if (r.cost?.resources.length) {
    const rows = r.cost.resources.slice(0, 10).map((x) => `| \`${cell(x.address)}\` | ${formatMoney(x.diffMonthly, r.cost?.currency ?? "USD", true)} |`);
    s.push({
      priority: 3,
      text: `<details><summary>💰 Cost changes by resource</summary>\n\n| Resource | Monthly Δ |\n|---|--:|\n${rows.join("\n")}\n\n</details>`,
    });
  }
  if (r.warnings.length) s.push({ priority: 0, text: r.warnings.map((w) => `> [!WARNING]\n> ${w}`).join("\n\n") });

  const main = r.findings.filter((f) => f.severity !== "low" && f.severity !== "info");
  const minor = r.findings.filter((f) => f.severity === "low" || f.severity === "info");
  if (r.summary.total === 0 && r.findings.length === 0) s.push({ priority: 0, text: "No changes. Infrastructure matches the configuration." });
  if (main.length) {
    s.push({ priority: 1, text: findingsTable(main) });
    s.push({ priority: 3, text: `<details><summary>Details and fixes (${main.length})</summary>\n\n${findingDetails(main)}\n\n</details>` });
  }
  if (minor.length)
    s.push({ priority: 2, text: `<details><summary>${SEVERITY_ICON.low} Low / info (${minor.length})</summary>\n\n${findingsTable(minor)}\n\n</details>` });
  if (r.suppressed.length) {
    const rows = r.suppressed.map(
      (f) => `| \`${f.ruleId}\` | ${cell(f.message)} | ${cell(f.suppressed?.reason ?? "")}${f.suppressed?.expires ? ` (until ${f.suppressed.expires})` : ""} |`,
    );
    s.push({
      priority: 2,
      text: `<details><summary>✔️ Accepted risks (${r.suppressed.length})</summary>\n\n| Rule | Finding | Reason |\n|---|---|---|\n${rows.join("\n")}\n\n</details>`,
    });
  }
  if (r.aiSummary)
    s.push({ priority: 2, text: `<details open><summary>🤖 AI summary (advisory — does not affect the gate)</summary>\n\n${r.aiSummary}\n\n</details>` });
  if (r.changes.length)
    s.push({ priority: 4, text: `<details><summary>All changes (${plural(r.changes.length, "resource")})</summary>\n\n${changesList(r)}\n</details>` });
  return s;
}

export function renderMarkdown(reports: Report[], opts: MarkdownOptions = {}): string {
  const multi = reports.length > 1;
  const header: string[] = [];
  if (opts.marker) header.push(`<!-- ${opts.marker} -->`);
  if (multi) {
    const worst = reports.reduce((a, b) => (b.score > a.score ? b : a));
    const passed = overallPassed(reports);
    header.push(
      `## ${LEVEL_ICON[worst.level]} planlens — ${reports.length} plans · highest risk **${worst.score}/100** · Gate ${passed ? "✅ passed" : "❌ failed"}`,
    );
  }
  if (opts.acceptedBy) header.push(`> [!NOTE]\n> Risk accepted via label \`${opts.acceptedBy}\` — the gate will not block this PR.`);

  const sections: Section[] = reports.flatMap((r) => reportSections(r, multi));
  const footer = `<sub>[planlens](${DOCS_URL}) v${reports[0]?.tool.version ?? ""} · [rule reference](${RULES_URL}) · plan values never leave your CI runner</sub>`;

  const build = (maxPriority: number) => {
    const kept = sections.filter((s) => s.priority <= maxPriority).map((s) => s.text);
    const dropped = sections.some((s) => s.priority > maxPriority);
    const note = dropped
      ? `\n\n> [!NOTE]\n> Comment truncated to fit GitHub's size limit. Full report: ${opts.runUrl ? `[CI run](${opts.runUrl})` : "see the job summary / JSON artifact"}.`
      : "";
    return [...header, ...kept].join("\n\n") + note + `\n\n${footer}\n`;
  };
  for (const p of [4, 3, 2, 1, 0]) {
    const md = build(p);
    if (md.length <= MAX_COMMENT_CHARS) return md;
  }
  return `${build(0).slice(0, MAX_COMMENT_CHARS - 100)}\n\n…(truncated)\n`;
}
