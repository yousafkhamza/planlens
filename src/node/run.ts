import { dirname, relative, resolve } from "node:path";
import { type AiProvider, summarizeWithAi } from "../ai/providers.js";
import { resolveConfig } from "../core/config.js";
import { analyzePlan } from "../core/engine.js";
import { normalizePlan } from "../core/plan.js";
import type { FailOn, Report } from "../core/types.js";
import type { SarifOptions } from "../report/sarif.js";
import { loadConfig, loadPlan } from "./load.js";
import { SourceLocator } from "./locate.js";

export interface RunOptions {
  plans: string[];
  configPath?: string;
  failOn?: FailOn;
  /** Only used when a single plan is given. */
  name?: string;
  /** Terraform root module dir used to map findings to .tf lines. Defaults to each plan's directory. */
  sourceDir?: string;
  ai?: AiProvider;
  aiModel?: string;
  cwd?: string;
  now?: Date;
}

export interface RunResult {
  reports: Report[];
  configPath?: string;
  sarif: SarifOptions;
}

function label(path: string, cwd: string): string {
  if (path === "-") return "stdin";
  return relative(cwd, resolve(cwd, path)).replace(/\\/g, "/") || path;
}

export async function runPlans(o: RunOptions): Promise<RunResult> {
  const cwd = o.cwd ?? process.cwd();
  const { config, path: configPath } = loadConfig(o.configPath, cwd);
  const resolved = resolveConfig(config, { failOn: o.failOn, now: o.now });
  const reports: Report[] = [];
  const locators = new Map<Report, SourceLocator>();
  const planUris = new Map<Report, string>();

  for (const p of o.plans) {
    const raw = loadPlan(p === "-" ? p : resolve(cwd, p));
    const name = o.plans.length === 1 && o.name ? o.name : label(p, cwd);
    const report = analyzePlan(raw, { config: resolved, name });
    reports.push(report);
    const srcDir = o.sourceDir ? resolve(cwd, o.sourceDir) : p === "-" ? cwd : dirname(resolve(cwd, p));
    locators.set(report, new SourceLocator(srcDir, normalizePlan(raw).moduleSources, cwd));
    planUris.set(report, p === "-" ? "plan.json" : label(p, cwd));
  }

  if (o.ai) {
    for (const r of reports) {
      if (r.summary.total === 0 && r.findings.length === 0) continue;
      try {
        r.aiSummary = await summarizeWithAi(r, { provider: o.ai, model: o.aiModel });
      } catch (e) {
        r.warnings.push(`AI summary skipped: ${(e as Error).message}`);
      }
    }
  }

  return {
    reports,
    configPath,
    sarif: {
      locate: (f, r) => (f.address.startsWith("output.") || f.address === "(plan)" ? undefined : locators.get(r)?.locate(f.address)),
      fallbackUri: (r) => planUris.get(r) ?? r.name,
    },
  };
}
