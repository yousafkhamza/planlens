import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { validateConfig } from "../core/config.js";
import { PlanParseError, parsePlanText } from "../core/plan.js";
import type { PlanlensConfig, RawPlan } from "../core/types.js";

export class InputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InputError";
  }
}

export const CONFIG_FILES = [".planlens.yml", ".planlens.yaml", ".planlens.json"];

function readStdin(): string {
  try {
    return readFileSync(0, "utf8");
  } catch (e) {
    throw new InputError(`Could not read plan from stdin: ${(e as Error).message}`);
  }
}

/** Run `terraform show -json` (or OpenTofu) on a binary plan file. */
export function showBinaryPlan(planPath: string, env: NodeJS.ProcessEnv = process.env): string {
  const candidates = env.TERRAFORM_BINARY ? [env.TERRAFORM_BINARY] : ["terraform", "tofu"];
  const errors: string[] = [];
  for (const bin of candidates) {
    const res = spawnSync(bin, ["show", "-json", "-no-color", resolve(planPath)], {
      cwd: dirname(resolve(planPath)),
      encoding: "utf8",
      maxBuffer: 1024 * 1024 * 1024,
      shell: false,
      env,
    });
    if (res.error) {
      errors.push(`${bin}: ${res.error.message}`);
      continue;
    }
    if (res.status === 0 && res.stdout.trim().startsWith("{")) return res.stdout;
    errors.push(`${bin} exited ${res.status}: ${res.stderr.trim().split("\n").slice(-3).join(" ")}`);
  }
  throw new InputError(
    `"${planPath}" is a binary plan file and converting it failed.\n` +
      `  ${errors.join("\n  ")}\n` +
      "Run planlens from the initialized Terraform directory, set TERRAFORM_BINARY, or convert it yourself:\n" +
      "  terraform show -json tf.plan > plan.json",
  );
}

/** Load a plan from a JSON file, a binary plan file, or stdin ("-"). */
export function loadPlan(path: string): RawPlan {
  let text: string;
  if (path === "-") text = readStdin();
  else {
    if (!existsSync(path)) throw new InputError(`Plan file not found: ${path}`);
    const buf = readFileSync(path);
    // Binary plans are zip archives ("PK\x03\x04").
    if (buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b) text = showBinaryPlan(path);
    else text = buf.toString("utf8");
  }
  if (text.trim() === "") throw new InputError(`Plan input "${path}" is empty.`);
  try {
    return parsePlanText(text);
  } catch (e) {
    if (e instanceof PlanParseError) throw new InputError(`${path}: ${e.message}`);
    throw e;
  }
}

/** Load + validate config. Explicit path must exist; otherwise discover in `cwd`. */
export function loadConfig(explicit: string | undefined, cwd = process.cwd()): { config: PlanlensConfig; path?: string } {
  let path = explicit;
  if (!path) {
    path = CONFIG_FILES.map((f) => resolve(cwd, f)).find((f) => existsSync(f));
    if (!path) return { config: {} };
  } else if (!existsSync(path)) {
    throw new InputError(`Config file not found: ${path}`);
  }
  const text = readFileSync(path, "utf8");
  let data: unknown;
  try {
    data = path.endsWith(".json") ? JSON.parse(text) : parseYaml(text);
  } catch (e) {
    throw new InputError(`Could not parse ${path}: ${(e as Error).message}`);
  }
  return { config: validateConfig(data), path };
}
