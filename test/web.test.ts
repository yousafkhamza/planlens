import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { describe, expect, it } from "vitest";

const docs = fileURLToPath(new URL("../docs/", import.meta.url));
const bundlePath = `${docs}assets/planlens.js`;

interface PlanLensApi {
  analyzePlan: (p: unknown, o?: unknown) => { level: string; findings: Array<{ ruleId: string }>; passed: boolean };
  parsePlanText: (t: string) => unknown;
  parseConfigText: (t: string) => unknown;
  renderMarkdown: (r: unknown[]) => string;
  renderSarif: (r: unknown[]) => string;
  RULES: Array<{ id: string }>;
  VERSION: string;
}

function loadBundle(): PlanLensApi {
  const window: { PlanLens?: PlanLensApi } = {};
  vm.runInNewContext(readFileSync(bundlePath, "utf8"), { window, atob, console });
  if (!window.PlanLens) throw new Error("bundle did not register window.PlanLens");
  return window.PlanLens;
}

describe.runIf(existsSync(bundlePath))("browser bundle (docs/assets/planlens.js)", () => {
  it("exposes the engine and makes no network calls", () => {
    const src = readFileSync(bundlePath, "utf8");
    expect(src).not.toMatch(/\bfetch\(|XMLHttpRequest|sendBeacon|WebSocket/);
    const api = loadBundle();
    expect(api.RULES.length).toBeGreaterThan(35);
    expect(api.VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("analyzes every demo sample", () => {
    const api = loadBundle();
    const levels: Record<string, string> = {};
    for (const f of readdirSync(`${docs}samples`)) {
      const plan = api.parsePlanText(readFileSync(`${docs}samples/${f}`, "utf8"));
      levels[f] = api.analyzePlan(plan, { name: f }).level;
    }
    expect(levels).toEqual({ "aws-create.json": "critical", "lifecycle.json": "high", "noop.json": "none", "prod-change.json": "critical" });
  });

  it("parses YAML config and renders markdown/SARIF", () => {
    const api = loadBundle();
    const cfg = api.parseConfigText("fail_on: none\ndisable: [PL201]\n");
    const plan = api.parsePlanText(readFileSync(`${docs}samples/prod-change.json`, "utf8"));
    const r = api.analyzePlan(plan, { config: cfg });
    expect(r.passed).toBe(true);
    expect(r.findings.some((f) => f.ruleId === "PL201")).toBe(false);
    expect(api.renderMarkdown([r])).toContain("planlens");
    expect(JSON.parse(api.renderSarif([r])).version).toBe("2.1.0");
    expect(() => api.parseConfigText("fail_on: nope")).toThrow(/fail_on must be/);
    expect(api.parseConfigText("  ")).toEqual({});
  });
});
