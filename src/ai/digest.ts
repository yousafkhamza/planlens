import type { Report } from "../core/types.js";

/**
 * Build the ONLY data that is sent to an LLM: resource addresses, change
 * kinds, attribute *names* and finding messages, with account IDs, emails and
 * IP addresses masked. Attribute values from the plan are never included.
 */
export function buildDigest(report: Report): string {
  const digest = {
    plan: report.name,
    summary: report.summary,
    risk: { score: report.score, level: report.level },
    findings: report.findings.slice(0, 60).map((f) => ({ rule: f.ruleId, severity: f.severity, title: f.title, message: f.message })),
    changes: report.changes.slice(0, 300).map((c) => ({
      address: c.address,
      action: c.kind,
      forcedBy: c.replacePaths.length ? c.replacePaths : undefined,
      changedAttributes: c.kind === "update" && c.changedPaths.length ? c.changedPaths.slice(0, 15) : undefined,
    })),
    truncated: report.changes.length > 300 || report.findings.length > 60,
  };
  return maskIdentifiers(JSON.stringify(digest));
}

export function maskIdentifiers(s: string): string {
  return s
    .replace(/\b\d{12}\b/g, "<account-id>")
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "<email>")
    .replace(/\b(?!0\.0\.0\.0\b)(?:\d{1,3}\.){3}\d{1,3}\b/g, "<ip>");
}

export const SYSTEM_PROMPT = `You are a senior platform engineer reviewing a Terraform plan before it is applied to production.
You receive a JSON digest: change counts, a deterministic risk score, findings from a rule engine, and the list of resource changes (addresses and attribute names only — never values).

Write a short review in GitHub-flavoured Markdown:
1. One sentence: what this change does, in plain English.
2. "Biggest risks": up to 4 bullets, most dangerous first. Explain the real-world impact (downtime, data loss, exposure) — do not just repeat rule titles.
3. "Before you apply": up to 4 concrete checks the reviewer should do.

Rules: be specific to the resources listed; never invent resources or values; if there are no risky changes, say so in one line. Max 180 words. No preamble, no headings larger than bold text.`;
