import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { parseArgs } from "node:util";
import { AI_PROVIDERS, type AiProvider } from "./ai/providers.js";
import { ConfigError } from "./core/config.js";
import { RULES } from "./core/rules/index.js";
import { type FailOn, SEVERITIES } from "./core/types.js";
import { InputError } from "./node/load.js";
import { runPlans } from "./node/run.js";
import { overallPassed } from "./report/common.js";
import { renderJson } from "./report/json.js";
import { renderMarkdown } from "./report/markdown.js";
import { renderSarif } from "./report/sarif.js";
import { renderText } from "./report/text.js";
import { VERSION } from "./version.js";

export const EXIT = { OK: 0, GATE_FAILED: 1, ERROR: 2 } as const;

const FORMATS = ["text", "markdown", "json", "sarif"] as const;
type Format = (typeof FORMATS)[number];

export const HELP = `planlens ${VERSION} — review what a Terraform plan will really do

Usage:
  planlens [options] <plan> [<plan>...]

  <plan> is the output of \`terraform show -json tf.plan\`, a binary plan file
  (converted with terraform/tofu automatically), or "-" for stdin.

Options:
  -f, --format <fmt>     text (default) | markdown | json | sarif
  -o, --output <file>    write the --format output to a file instead of stdout
      --out <fmt=file>   also write another format to a file (repeatable)
                         e.g. --out sarif=planlens.sarif --out markdown=comment.md
  -c, --config <file>    config file (default: .planlens.yml/.yaml/.json in cwd)
      --fail-on <sev>    critical | high | medium | low | info | none  (default: high)
      --name <label>     label for the plan in reports (single plan only)
      --source-dir <dir> Terraform root dir, used to point SARIF results at .tf lines
                         (default: the plan file's directory)
      --ai <provider>    add an advisory AI summary: anthropic | openai | ollama
      --ai-model <name>  model for --ai (required for openai/ollama)
  -v, --verbose          show low/info findings and every change (text format)
      --no-color         disable ANSI colors (also honours NO_COLOR)
  -q, --quiet            print nothing to stdout (use with --out / --output)
      --list-rules       print the built-in rule catalog
  -h, --help             show this help
      --version          print the version

Exit codes:
  0  gate passed     1  findings at/above --fail-on     2  usage or input error

Examples:
  terraform plan -out=tf.plan && terraform show -json tf.plan > plan.json
  planlens plan.json
  planlens tf.plan --fail-on critical
  planlens envs/*/plan.json --format markdown -o comment.md --out sarif=planlens.sarif
`;

export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  isTTY: boolean;
  env: NodeJS.ProcessEnv;
  cwd: string;
}

function writeFile(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function listRules(format: string): string {
  if (format === "json") {
    return `${JSON.stringify(
      RULES.map((r) => ({ id: r.id, title: r.title, severity: r.severity, category: r.category, description: r.description, remediation: r.remediation })),
      null,
      2,
    )}\n`;
  }
  if (format === "markdown") {
    return `| ID | Severity | Category | Rule |\n|---|---|---|---|\n${RULES.map((r) => `| ${r.id} | ${r.severity} | ${r.category} | ${r.title} |`).join("\n")}\n`;
  }
  return `${RULES.map((r) => `${r.id}  ${r.severity.padEnd(8)} ${r.category.padEnd(12)} ${r.title}`).join("\n")}\n`;
}

export async function main(argv: string[], io: Io): Promise<number> {
  let args: ReturnType<typeof parse>;
  function parse() {
    return parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        format: { type: "string", short: "f" },
        output: { type: "string", short: "o" },
        out: { type: "string", multiple: true },
        config: { type: "string", short: "c" },
        "fail-on": { type: "string" },
        name: { type: "string" },
        "source-dir": { type: "string" },
        ai: { type: "string" },
        "ai-model": { type: "string" },
        verbose: { type: "boolean", short: "v" },
        "no-color": { type: "boolean" },
        quiet: { type: "boolean", short: "q" },
        "list-rules": { type: "boolean" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean" },
      },
    });
  }
  try {
    args = parse();
  } catch (e) {
    io.stderr(`planlens: ${(e as Error).message}\nRun "planlens --help" for usage.\n`);
    return EXIT.ERROR;
  }
  const v = args.values;
  if (v.help) {
    io.stdout(HELP);
    return EXIT.OK;
  }
  if (v.version) {
    io.stdout(`${VERSION}\n`);
    return EXIT.OK;
  }
  const format = (v.format ?? "text") as Format;
  if (!FORMATS.includes(format)) {
    io.stderr(`planlens: --format must be one of ${FORMATS.join(", ")}\n`);
    return EXIT.ERROR;
  }
  if (v["list-rules"]) {
    io.stdout(listRules(format));
    return EXIT.OK;
  }

  const failOn = v["fail-on"] as FailOn | undefined;
  if (failOn !== undefined && ![...SEVERITIES, "none"].includes(failOn)) {
    io.stderr(`planlens: --fail-on must be one of ${[...SEVERITIES, "none"].join(", ")}\n`);
    return EXIT.ERROR;
  }
  const ai = v.ai as AiProvider | undefined;
  if (ai !== undefined && !AI_PROVIDERS.includes(ai)) {
    io.stderr(`planlens: --ai must be one of ${AI_PROVIDERS.join(", ")}\n`);
    return EXIT.ERROR;
  }
  const extra: Array<{ format: Format; path: string }> = [];
  for (const spec of v.out ?? []) {
    const m = /^([a-z]+)=(.+)$/.exec(spec);
    if (!m || !FORMATS.includes(m[1] as Format)) {
      io.stderr(`planlens: --out expects <format>=<file> with format in ${FORMATS.join(", ")} (got "${spec}")\n`);
      return EXIT.ERROR;
    }
    extra.push({ format: m[1] as Format, path: m[2] as string });
  }
  if (args.positionals.length === 0) {
    io.stderr(`planlens: no plan given.\n\n${HELP}`);
    return EXIT.ERROR;
  }

  try {
    const result = await runPlans({
      plans: args.positionals,
      configPath: v.config,
      failOn,
      name: v.name,
      sourceDir: v["source-dir"],
      ai,
      aiModel: v["ai-model"],
      cwd: io.cwd,
    });
    const { reports } = result;
    const color = !v["no-color"] && !io.env.NO_COLOR && io.isTTY && !v.output;
    const render = (f: Format, forColor: boolean): string => {
      switch (f) {
        case "markdown":
          return renderMarkdown(reports);
        case "json":
          return renderJson(reports);
        case "sarif":
          return renderSarif(reports, result.sarif);
        default:
          return renderText(reports, { color: forColor, verbose: v.verbose });
      }
    };
    for (const e of extra) writeFile(e.path, render(e.format, false));
    const primary = render(format, color);
    if (v.output) writeFile(v.output, primary);
    else if (!v.quiet) io.stdout(primary);
    if (v.output && !v.quiet && format !== "text") io.stderr(renderText(reports, { color: false }));
    return overallPassed(reports) ? EXIT.OK : EXIT.GATE_FAILED;
  } catch (e) {
    if (e instanceof InputError || e instanceof ConfigError) {
      io.stderr(`planlens: ${e.message}\n`);
      return EXIT.ERROR;
    }
    io.stderr(`planlens: unexpected error: ${(e as Error).stack ?? String(e)}\n`);
    return EXIT.ERROR;
  }
}
