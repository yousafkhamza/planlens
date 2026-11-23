import { RULES } from "../core/rules/index.js";
import type { Finding, Report, Severity } from "../core/types.js";
import { DOCS_URL, fnv1a, RULES_URL } from "./common.js";

export interface SourceLocation {
  uri: string;
  line: number;
}

export interface SarifOptions {
  /** Map a finding to a source file/line (e.g. the `.tf` file declaring the resource). */
  locate?: (finding: Finding, report: Report) => SourceLocation | undefined;
  /** Fallback artifact when no source location is found (normally the plan file path). */
  fallbackUri?: (report: Report) => string;
}

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** GitHub code scanning maps this to Critical/High/Medium/Low. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "1.0",
};

function plain(s: string): string {
  return s.replace(/`/g, "'");
}

export function renderSarif(reports: Report[], opts: SarifOptions = {}): string {
  const customs = new Map<string, Finding>();
  for (const r of reports) for (const f of r.findings) if (!RULES.some((x) => x.id === f.ruleId)) customs.set(f.ruleId, f);

  const rules = [
    ...RULES.map((r) => ({
      id: r.id,
      name: r.title
        .replace(/[^A-Za-z0-9]+/g, " ")
        .trim()
        .replace(/ (\w)/g, (_, ch: string) => ch.toUpperCase())
        .replace(/^\w/, (ch) => ch.toUpperCase()),
      shortDescription: { text: r.title },
      fullDescription: { text: r.description },
      help: { text: r.remediation, markdown: `${r.description}\n\n**Remediation:** ${r.remediation}` },
      helpUri: `${RULES_URL}#${r.id.toLowerCase()}`,
      defaultConfiguration: { level: LEVEL[r.severity] },
      properties: {
        tags: [...new Set(["terraform", "iac", r.category, ...(["security", "iam", "network", "secrets"].includes(r.category) ? ["security"] : [])])],
        "security-severity": SECURITY_SEVERITY[r.severity],
        precision: "high",
      },
    })),
    ...[...customs.values()].map((f) => ({
      id: f.ruleId,
      name: f.ruleId,
      shortDescription: { text: f.title },
      fullDescription: { text: f.title },
      help: { text: f.remediation ?? f.title },
      defaultConfiguration: { level: LEVEL[f.severity] },
      properties: { tags: ["terraform", "custom"], "security-severity": SECURITY_SEVERITY[f.severity] },
    })),
  ];
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const results = reports.flatMap((report) =>
    report.findings.map((f) => {
      const loc = opts.locate?.(f, report) ?? { uri: opts.fallbackUri?.(report) ?? report.name, line: 1 };
      const details = f.details.filter((d) => !d.includes("```")).map(plain);
      return {
        ruleId: f.ruleId,
        ruleIndex: ruleIndex.get(f.ruleId),
        level: LEVEL[f.severity],
        message: { text: [plain(f.message), ...details].join("\n") },
        locations: [
          {
            physicalLocation: { artifactLocation: { uri: loc.uri.replace(/\\/g, "/") }, region: { startLine: Math.max(1, loc.line) } },
            logicalLocations: [{ name: f.address, kind: "resource", fullyQualifiedName: `${report.name}::${f.address}` }],
          },
        ],
        partialFingerprints: { "planlens/v1": fnv1a(`${report.name}|${f.ruleId}|${f.address}`) },
        properties: { severity: f.severity, address: f.address, plan: report.name, "security-severity": SECURITY_SEVERITY[f.severity] },
      };
    }),
  );

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "planlens",
            semanticVersion: reports[0]?.tool.version ?? "0.0.0",
            informationUri: DOCS_URL,
            rules,
          },
        },
        results,
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}
