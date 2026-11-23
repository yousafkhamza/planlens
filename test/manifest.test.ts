import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (p: string) => readFileSync(`${root}${p}`, "utf8");

interface ActionManifest {
  name: string;
  description: string;
  inputs: Record<string, { description: string; required?: boolean; default?: string }>;
  outputs: Record<string, { description: string }>;
  runs: { using: string; main: string };
}

describe("action.yml", () => {
  const manifest = parse(read("action.yml"), { strict: true, uniqueKeys: true }) as ActionManifest;

  it("is valid YAML with string descriptions (GitHub's runner rejects nested mappings)", () => {
    expect(typeof manifest.name).toBe("string");
    expect(typeof manifest.description).toBe("string");
    for (const [name, def] of Object.entries(manifest.inputs)) expect(typeof def.description, `inputs.${name}.description`).toBe("string");
    for (const [name, def] of Object.entries(manifest.outputs)) expect(typeof def.description, `outputs.${name}.description`).toBe("string");
  });

  it("runs the committed bundle on a supported runtime", () => {
    expect(manifest.runs.using).toBe("node24");
    expect(manifest.runs.main).toBe("dist/action.cjs");
    expect(existsSync(`${root}dist/action.cjs`)).toBe(true);
  });

  it("declares every input the action reads and every output it sets", () => {
    const src = read("src/action/main.ts");
    const used = new Set([...src.matchAll(/input\(env, "([a-z-]+)"/g)].map((m) => m[1]));
    expect([...used].sort()).toEqual(Object.keys(manifest.inputs).sort());
    const set = new Set([...src.matchAll(/setOutput\(env, "([a-z-]+)"/g)].map((m) => m[1]));
    expect([...set].sort()).toEqual(Object.keys(manifest.outputs).sort());
  });
});

describe("workflows and examples", () => {
  const files = [
    ...readdirSync(`${root}.github/workflows`).map((f) => `.github/workflows/${f}`),
    ".github/dependabot.yml",
    "examples/github-actions/terraform-pr.yml",
    "examples/github-actions/multi-env-matrix.yml",
    "examples/gitlab/.gitlab-ci.yml",
    "examples/github-actions/with-infracost.yml",
    "examples/atlantis/repos.yaml",
    "examples/azure-devops/azure-pipelines.yml",
  ];
  it.each(files)("%s is valid YAML", (f) => {
    expect(() => parse(read(f), { strict: true, uniqueKeys: true })).not.toThrow();
  });
});
