// Generates REAL plan JSON fixtures by running Terraform.
//
//   test/fixtures/scenarios/<name>/v1/*.tf   applied first (optional)
//   test/fixtures/scenarios/<name>/v2/*.tf   then planned
//   test/fixtures/scenarios/<name>/between.mjs  optional hook run after apply (e.g. cause drift)
//
// Output: test/fixtures/real/<name>.json. With E2E_BINARY=1 also checks the CLI on the binary plan.
// Requires `terraform` on PATH (or TERRAFORM_BINARY) and network access for providers.
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const scenariosDir = join(root, "test/fixtures/scenarios");
const outDir = join(root, "test/fixtures/real");
const tf = process.env.TERRAFORM_BINARY || "terraform";
const only = process.argv.slice(2);
const cache = join(tmpdir(), "planlens-tf-plugin-cache");
mkdirSync(cache, { recursive: true });
mkdirSync(outDir, { recursive: true });

const env = { ...process.env, TF_IN_AUTOMATION: "1", TF_INPUT: "0", TF_PLUGIN_CACHE_DIR: cache, CHECKPOINT_DISABLE: "1" };

function run(args, cwd, { capture = false } = {}) {
  const res = spawnSync(tf, args, { cwd, env, encoding: "utf8", maxBuffer: 512 * 1024 * 1024, stdio: capture ? "pipe" : ["ignore", "pipe", "pipe"] });
  if (res.status !== 0) {
    console.error(res.stdout, res.stderr);
    throw new Error(`terraform ${args.join(" ")} failed in ${cwd}`);
  }
  return res.stdout;
}

function copyTf(src, dst) {
  for (const f of readdirSync(dst)) if (f.endsWith(".tf")) rmSync(join(dst, f));
  for (const f of readdirSync(src)) cpSync(join(src, f), join(dst, f));
}

for (const name of readdirSync(scenariosDir)) {
  if (only.length && !only.includes(name)) continue;
  const dir = join(scenariosDir, name);
  const work = join(tmpdir(), "planlens-fixtures", name);
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });
  console.log(`▶ ${name}`);

  if (existsSync(join(dir, "v1"))) {
    copyTf(join(dir, "v1"), work);
    run(["init", "-no-color"], work);
    run(["apply", "-auto-approve", "-no-color"], work);
  }
  copyTf(join(dir, "v2"), work);
  run(["init", "-no-color", "-upgrade=false"], work);
  if (existsSync(join(dir, "between.mjs"))) {
    const hook = await import(pathToFileURL(join(dir, "between.mjs")).href);
    await hook.default(work);
  }
  run(["plan", "-no-color", "-out=tf.plan"], work);
  let json = run(["show", "-json", "-no-color", "tf.plan"], work, { capture: true });
  // Make fixtures machine-independent.
  const workJson = JSON.stringify(work).slice(1, -1);
  json = json.split(workJson).join(".").split(work.replace(/\\/g, "/")).join(".");
  const pretty = `${JSON.stringify(JSON.parse(json), null, 2)}\n`;
  writeFileSync(join(outDir, `${name}.json`), pretty);
  console.log(`  ✓ test/fixtures/real/${name}.json`);

  // E2E: the CLI must give identical findings for the binary plan (auto-converted
  // via `terraform show`) and for the JSON we just wrote.
  if (process.env.E2E_BINARY) {
    const cli = join(root, "dist/cli.mjs");
    const findings = (args, cwd) => {
      const r = spawnSync(process.execPath, [cli, ...args, "--format", "json", "--fail-on", "none"], { cwd, env, encoding: "utf8" });
      if (r.status !== 0) throw new Error(`planlens failed (${r.status}): ${r.stderr}`);
      return JSON.parse(r.stdout)
        .reports[0].findings.map((f) => `${f.ruleId} ${f.address}`)
        .sort();
    };
    const fromBinary = findings(["tf.plan"], work);
    const fromJson = findings([join(outDir, `${name}.json`)], root);
    if (JSON.stringify(fromBinary) !== JSON.stringify(fromJson)) {
      console.error({ fromBinary, fromJson });
      throw new Error(`binary vs JSON findings differ for ${name}`);
    }
    console.log(`  ✓ binary plan e2e (${fromBinary.length} findings match)`);
  }
}
