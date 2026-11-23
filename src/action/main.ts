import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { AI_PROVIDERS, type AiProvider } from "../ai/providers.js";
import { type FailOn, SEVERITIES } from "../core/types.js";
import { expandPatterns } from "../node/glob.js";
import { runPlans } from "../node/run.js";
import { countBySeverity, overallPassed } from "../report/common.js";
import { renderJson } from "../report/json.js";
import { renderMarkdown } from "../report/markdown.js";
import { renderSarif } from "../report/sarif.js";
import { renderText } from "../report/text.js";
import { GitHubError, upsertComment } from "./github.js";

export interface ActionEnv {
  env: NodeJS.ProcessEnv;
  log: (s: string) => void;
  fetchImpl?: typeof fetch;
}

/** GitHub passes inputs as INPUT_<NAME> with the name upper-cased (hyphens kept). */
export function input(env: NodeJS.ProcessEnv, name: string, fallback = ""): string {
  const v = env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`];
  return v === undefined || v.trim() === "" ? fallback : v.trim();
}

function bool(v: string): boolean {
  return ["true", "yes", "1", "on"].includes(v.toLowerCase());
}

function escapeData(s: string): string {
  return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function escapeProp(s: string): string {
  return escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

function setOutput(env: NodeJS.ProcessEnv, name: string, value: string): void {
  if (!env.GITHUB_OUTPUT) return;
  const delim = `planlens_${Math.random().toString(36).slice(2)}`;
  appendFileSync(env.GITHUB_OUTPUT, `${name}<<${delim}\n${value}\n${delim}\n`);
}

function write(path: string, content: string): void {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  writeFileSync(path, content);
}

interface PrInfo {
  number: number;
  labels: string[];
}

function readPr(env: NodeJS.ProcessEnv): PrInfo | undefined {
  const path = env.GITHUB_EVENT_PATH;
  if (!path || !existsSync(path)) return undefined;
  try {
    const ev = JSON.parse(readFileSync(path, "utf8")) as { pull_request?: { number?: number; labels?: Array<{ name?: string }> } };
    if (!ev.pull_request?.number) return undefined;
    return { number: ev.pull_request.number, labels: (ev.pull_request.labels ?? []).map((l) => String(l.name ?? "")) };
  } catch {
    return undefined;
  }
}

/** Returns the process exit code. */
export async function runAction({ env, log, fetchImpl }: ActionEnv): Promise<number> {
  const planInput = input(env, "plan");
  if (!planInput) {
    log("::error::planlens: the `plan` input is required (path or glob to `terraform show -json` output).");
    return 2;
  }
  const failOn = input(env, "fail-on", "") as FailOn | "";
  if (failOn && ![...SEVERITIES, "none"].includes(failOn)) {
    log(`::error::planlens: fail-on must be one of ${[...SEVERITIES, "none"].join(", ")}`);
    return 2;
  }
  const ai = input(env, "ai") as AiProvider | "";
  if (ai && !AI_PROVIDERS.includes(ai)) {
    log(`::error::planlens: ai must be one of ${AI_PROVIDERS.join(", ")}`);
    return 2;
  }
  const cwd = resolve(env.GITHUB_WORKSPACE ?? process.cwd(), input(env, "working-directory", "."));
  const plans = expandPatterns(planInput, cwd);
  if (plans.length === 0) {
    log(`::error::planlens: no plan files matched "${planInput}" (in ${cwd}).`);
    return 2;
  }

  let result: Awaited<ReturnType<typeof runPlans>>;
  try {
    result = await runPlans({
      plans,
      cwd,
      configPath: input(env, "config") || undefined,
      failOn: failOn || undefined,
      sourceDir: input(env, "source-dir") || undefined,
      ai: ai || undefined,
      aiModel: input(env, "ai-model") || undefined,
    });
  } catch (e) {
    log(`::error::planlens: ${escapeData((e as Error).message)}`);
    return 2;
  }
  const { reports } = result;
  log(renderText(reports, { color: true }));

  const pr = readPr(env);
  const acceptLabel = input(env, "accept-risk-label", "planlens:accept-risk");
  const accepted = !!pr && !!acceptLabel && pr.labels.includes(acceptLabel);
  const passed = overallPassed(reports) || accepted;

  const runUrl =
    env.GITHUB_SERVER_URL && env.GITHUB_REPOSITORY && env.GITHUB_RUN_ID
      ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`
      : undefined;
  const marker = `planlens:${input(env, "comment-id", "default")}`;
  const md = renderMarkdown(reports, { marker, acceptedBy: accepted ? acceptLabel : undefined, runUrl });

  // Files
  const sarifFile = input(env, "sarif-file", "planlens.sarif");
  const jsonFile = input(env, "json-file", "planlens.json");
  const mdFile = input(env, "markdown-file", "planlens.md");
  write(resolve(cwd, sarifFile), renderSarif(reports, result.sarif));
  write(resolve(cwd, jsonFile), renderJson(reports));
  write(resolve(cwd, mdFile), md);

  // Annotations (GitHub shows up to 10 per level per step)
  for (const r of reports) {
    for (const f of r.findings.filter((x) => x.severity === "critical" || x.severity === "high").slice(0, 10)) {
      const loc = result.sarif.locate?.(f, r);
      const props = [`title=${escapeProp(`planlens ${f.ruleId}: ${f.title}`)}`, ...(loc ? [`file=${escapeProp(loc.uri)}`, `line=${loc.line}`] : [])];
      log(`::${f.severity === "critical" ? "error" : "warning"} ${props.join(",")}::${escapeData(f.message.replace(/`/g, ""))}`);
    }
  }

  // Job summary
  if (bool(input(env, "step-summary", "true")) && env.GITHUB_STEP_SUMMARY) {
    appendFileSync(env.GITHUB_STEP_SUMMARY, renderMarkdown(reports, { acceptedBy: accepted ? acceptLabel : undefined }));
  }

  // Sticky PR comment
  const commentMode = input(env, "comment", "always").toLowerCase();
  if (pr && commentMode !== "never" && commentMode !== "false") {
    const token = input(env, "github-token") || env.GITHUB_TOKEN || "";
    const hasChanges = reports.some((r) => r.summary.total > 0 || r.findings.length > 0);
    if (!token) log("::warning::planlens: no github-token — skipping PR comment.");
    else if (!env.GITHUB_REPOSITORY) log("::warning::planlens: GITHUB_REPOSITORY not set — skipping PR comment.");
    else {
      try {
        const outcome = await upsertComment(
          { apiUrl: env.GITHUB_API_URL ?? "https://api.github.com", token, repo: env.GITHUB_REPOSITORY, fetchImpl },
          pr.number,
          marker,
          md,
          { createIfMissing: commentMode !== "changes" || hasChanges },
        );
        log(`planlens: PR comment ${outcome}.`);
      } catch (e) {
        const status = e instanceof GitHubError ? e.status : 0;
        const hint =
          status === 403 || status === 404
            ? " The token cannot write comments — add `permissions: pull-requests: write` to the job. Pull requests from forks only get a read-only token; use the job summary or a `workflow_run` follow-up job for those."
            : "";
        log(`::warning::planlens: could not post PR comment: ${escapeData((e as Error).message)}${hint}`);
      }
    }
  }

  // Outputs
  const counts = reports.reduce(
    (acc, r) => {
      const c = countBySeverity(r);
      for (const k of SEVERITIES) acc[k] += c[k];
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  );
  const worst = reports.reduce((a, b) => (b.score > a.score ? b : a));
  setOutput(env, "passed", String(passed));
  setOutput(env, "risk-score", String(worst.score));
  setOutput(env, "risk-level", worst.level);
  setOutput(env, "findings", String(reports.reduce((n, r) => n + r.findings.length, 0)));
  setOutput(env, "critical", String(counts.critical));
  setOutput(env, "high", String(counts.high));
  setOutput(env, "sarif-file", sarifFile);
  setOutput(env, "json-file", jsonFile);
  setOutput(env, "markdown-file", mdFile);

  if (!passed) {
    log(
      `::error::planlens: gate failed — findings at or above "${worst.failOn}". Fix them, add an ignore with a reason in .planlens.yml, or apply the "${acceptLabel}" label to accept the risk.`,
    );
    return 1;
  }
  if (accepted && !overallPassed(reports)) log(`::notice::planlens: risk accepted via label "${acceptLabel}".`);
  return 0;
}
