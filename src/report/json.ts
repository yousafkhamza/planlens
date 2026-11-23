import type { Report } from "../core/types.js";
import { overallPassed } from "./common.js";

export interface JsonEnvelope {
  schemaVersion: 1;
  tool: Report["tool"];
  passed: boolean;
  maxScore: number;
  reports: Report[];
}

/** Stable machine-readable output. Always an envelope, even for a single plan. */
export function toJson(reports: Report[]): JsonEnvelope {
  return {
    schemaVersion: 1,
    tool: reports[0]?.tool ?? { name: "planlens", version: "0.0.0" },
    passed: overallPassed(reports),
    maxScore: reports.reduce((m, r) => Math.max(m, r.score), 0),
    reports,
  };
}

export function renderJson(reports: Report[]): string {
  return `${JSON.stringify(toJson(reports), null, 2)}\n`;
}
