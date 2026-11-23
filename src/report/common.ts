import type { ChangeKind, Report, RiskLevel, Severity } from "../core/types.js";

export const SEVERITY_ICON: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

export const LEVEL_ICON: Record<RiskLevel, string> = { ...SEVERITY_ICON, none: "🟢" };

export const KIND_ICON: Record<ChangeKind, string> = {
  create: "➕",
  update: "🔄",
  replace: "♻️",
  delete: "🗑️",
  read: "📖",
  "no-op": "·",
};

export const KIND_LABEL: Record<ChangeKind, string> = {
  create: "create",
  update: "update in place",
  replace: "replace",
  delete: "destroy",
  read: "read",
  "no-op": "no change",
};

export function overallPassed(reports: Report[]): boolean {
  return reports.every((r) => r.passed);
}

export function countBySeverity(report: Report): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of report.findings) c[f.severity]++;
  return c;
}

/** FNV-1a 32-bit, hex. Stable fingerprints without crypto APIs (works in browser + node). */
export function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

export const DOCS_URL = "https://yousafkhamza.github.io/planlens/";
export const RULES_URL = "https://github.com/yousafkhamza/planlens/blob/main/docs/rules.md";
