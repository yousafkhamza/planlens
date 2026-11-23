import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";
import { describe, expect, it } from "vitest";

const docs = fileURLToPath(new URL("../docs/", import.meta.url));
const bundle = `${docs}assets/planlens.js`;

/** Boot docs/index.html with the real bundle + app.js in jsdom. */
function boot() {
  const dom = new JSDOM(readFileSync(`${docs}index.html`, "utf8").replace(/<script src=[^>]+><\/script>/g, ""), {
    url: "https://yousafkhamza.github.io/planlens/",
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const w = dom.window as unknown as Window & typeof globalThis & { eval: (s: string) => unknown };
  const copied: string[] = [];
  Object.assign(w, {
    matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {} }),
    fetch: async (url: string) => {
      const name = String(url).split("/").pop() ?? "";
      const path = `${docs}samples/${name}`;
      return existsSync(path) ? new Response(readFileSync(path, "utf8")) : new Response("nope", { status: 404 });
    },
  });
  Object.defineProperty(w.navigator, "clipboard", { value: { writeText: async (t: string) => void copied.push(t) } });
  w.URL.createObjectURL = () => "blob:x";
  w.URL.revokeObjectURL = () => {};
  w.HTMLElement.prototype.scrollIntoView = () => {};
  w.eval(readFileSync(bundle, "utf8"));
  w.eval(readFileSync(`${docs}app.js`, "utf8"));
  const $ = <T extends Element = HTMLElement>(s: string) => w.document.querySelector(s) as unknown as T;
  const tick = () => new Promise((r) => setTimeout(r, 20));
  return { w, $, tick, copied };
}

describe.runIf(existsSync(bundle))("web UI (docs/index.html + app.js)", () => {
  it("renders the rule catalog with working filters", () => {
    const { $, w } = boot();
    const count = () => w.document.querySelectorAll("#rule-grid .rule").length;
    expect(count()).toBeGreaterThan(35);
    const search = $<HTMLInputElement>("#rule-search");
    search.value = "oidc";
    search.dispatchEvent(new w.Event("input"));
    expect(count()).toBe(1);
    expect($("#rule-grid").textContent).toContain("PL306");
    search.value = "zzzz-no-match";
    search.dispatchEvent(new w.Event("input"));
    expect($("#rule-grid").textContent).toContain("No rules match");
    expect($("#ver").textContent).toMatch(/^v\d/);
  });

  it("loads a sample and renders score, gate, findings and moved-block code", async () => {
    const { $, w, tick, copied } = boot();
    $<HTMLButtonElement>('[data-sample="prod-change.json"]').click();
    await tick();
    const result = $("#result");
    expect(result.textContent).toContain("CRITICAL");
    expect(result.textContent).toContain("Gate failed (fail-on: high)");
    expect(result.querySelectorAll(".finding").length).toBeGreaterThan(8);
    expect(result.querySelector(".finding pre code")?.textContent).toContain("moved {");
    expect(result.querySelector(".ring")?.getAttribute("aria-label")).toMatch(/Risk score \d+ out of 100/);
    // copy PR comment
    const btn = [...result.querySelectorAll("button")].find((b) => b.textContent?.startsWith("Copy PR comment")) as HTMLButtonElement;
    btn.click();
    await tick();
    expect(copied[0]).toContain("planlens");
    // changing fail-on re-runs the review
    const sel = $<HTMLSelectElement>("#failon");
    sel.value = "none";
    sel.dispatchEvent(new w.Event("change"));
    expect($("#result").textContent).toContain("Gate passed (fail-on: none)");
  });

  it("shows a clean state for a no-op plan", async () => {
    const { $, tick } = boot();
    $<HTMLButtonElement>('[data-sample="noop.json"]').click();
    await tick();
    expect($("#result").textContent).toContain("No changes");
  });

  it("applies YAML config from the options panel and shows accepted risks", async () => {
    const { $, tick } = boot();
    $<HTMLTextAreaElement>("#config").value = "ignore:\n  - rule: PL201\n    reason: debugging window\n";
    $<HTMLButtonElement>('[data-sample="prod-change.json"]').click();
    await tick();
    expect($("#result").textContent).toContain("accepted risks (1)");
    expect($("#result").textContent).toContain("Reason: debugging window");
  });

  it("reports parse and config errors without rendering", () => {
    const { $ } = boot();
    $<HTMLButtonElement>("#run").click();
    expect($("#error").textContent).toMatch(/Paste a plan/);
    $<HTMLTextAreaElement>("#paste").value = "{ not json";
    $<HTMLButtonElement>("#run").click();
    expect($("#error").textContent).toMatch(/not valid JSON/);
    $<HTMLTextAreaElement>("#paste").value = JSON.stringify({ format_version: "1.0", values: {} });
    $<HTMLButtonElement>("#run").click();
    expect($("#error").textContent).toMatch(/state/);
    $<HTMLTextAreaElement>("#config").value = "fail_on: sometimes";
    $<HTMLButtonElement>("#run").click();
    expect($("#error").textContent).toMatch(/fail_on must be/);
    $<HTMLButtonElement>("#clear").click();
    expect($("#error").hidden).toBe(true);
  });

  it("never interprets plan content as HTML (XSS-safe)", () => {
    const { $ } = boot();
    const evil = '<img src=x onerror="window.__pwned=1">';
    const plan = {
      format_version: "1.2",
      terraform_version: evil,
      resource_changes: [
        {
          address: `aws_db_instance.${evil}`,
          type: "aws_db_instance",
          name: evil,
          mode: "managed",
          change: { actions: ["delete"], before: { identifier: evil }, after: null },
        },
      ],
    };
    $<HTMLTextAreaElement>("#paste").value = JSON.stringify(plan);
    $<HTMLButtonElement>("#run").click();
    const result = $("#result");
    expect(result.querySelector("img")).toBeNull();
    expect(result.textContent).toContain("<img src=x");
    expect((globalThis as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("switches install tabs with mouse and keyboard, and toggles the theme", () => {
    const { $, w } = boot();
    $<HTMLButtonElement>("#t-cli").click();
    expect($("#tab-cli").hidden).toBe(false);
    expect($("#tab-gha").hidden).toBe(true);
    $("#t-cli").dispatchEvent(new w.KeyboardEvent("keydown", { key: "ArrowRight" }));
    expect($("#tab-gitlab").hidden).toBe(false);
    $<HTMLButtonElement>("#theme").click();
    expect(w.document.documentElement.dataset.theme).toBe("dark");
  });
});
