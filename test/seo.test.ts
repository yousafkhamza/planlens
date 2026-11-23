import { existsSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";
import { describe, expect, it } from "vitest";
import { RULES } from "../src/core/rules/index.js";

const docs = fileURLToPath(new URL("../docs/", import.meta.url));
const BASE = "https://yousafkhamza.github.io/planlens/";
const doc = (f: string) => new JSDOM(readFileSync(`${docs}${f}`, "utf8")).window.document;
const meta = (d: Document, key: string) => d.querySelector(`meta[property="${key}"], meta[name="${key}"]`)?.getAttribute("content") ?? "";

/** Read width/height from a PNG IHDR chunk. */
function pngSize(path: string): { w: number; h: number } {
  const b = readFileSync(path);
  expect(b.subarray(1, 4).toString()).toBe("PNG");
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) };
}

describe("SEO + social sharing (docs/index.html)", () => {
  const d = doc("index.html");

  it("has a descriptive title, description, canonical and robots", () => {
    expect(d.title.length).toBeGreaterThan(30);
    expect(d.title.length).toBeLessThanOrEqual(90);
    const desc = meta(d, "description");
    expect(desc.length).toBeGreaterThan(110);
    expect(desc.length).toBeLessThanOrEqual(170);
    expect(d.querySelector('link[rel="canonical"]')?.getAttribute("href")).toBe(BASE);
    expect(meta(d, "robots")).toContain("index");
    expect(d.documentElement.lang).toBe("en");
    expect(d.querySelectorAll("h1")).toHaveLength(1);
  });

  it("has complete Open Graph + Twitter tags with an absolute, correctly sized share image", () => {
    for (const k of ["og:title", "og:description", "og:url", "og:image", "og:image:alt", "og:type", "og:site_name", "twitter:card", "twitter:image"]) {
      expect(meta(d, k), k).not.toBe("");
    }
    expect(meta(d, "og:image")).toBe(`${BASE}assets/og.png`);
    expect(meta(d, "twitter:card")).toBe("summary_large_image");
    const { w, h } = pngSize(`${docs}assets/og.png`);
    expect([w, h, meta(d, "og:image:width"), meta(d, "og:image:height")]).toEqual([1200, 630, "1200", "630"]);
    expect(statSync(`${docs}assets/og.png`).size).toBeLessThan(5 * 1024 * 1024); // LinkedIn limit
    expect(pngSize(`${docs}assets/github-social.png`)).toEqual({ w: 1280, h: 640 });
  });

  it("ships valid structured data, icons, manifest and sitemap", () => {
    const ld = JSON.parse(d.querySelector('script[type="application/ld+json"]')?.textContent ?? "{}");
    const app = ld["@graph"].find((x: { "@type": string }) => x["@type"] === "SoftwareApplication");
    expect(app.url).toBe(BASE);
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    expect(app.softwareVersion).toBe(pkg.version);
    for (const href of ["assets/icon.svg", "assets/icon-192.png", "assets/apple-touch-icon.png", "site.webmanifest", "sitemap.xml"]) {
      expect(existsSync(`${docs}${href}`), href).toBe(true);
    }
    const manifest = JSON.parse(readFileSync(`${docs}site.webmanifest`, "utf8"));
    for (const i of manifest.icons) expect(existsSync(`${docs}${i.src}`), i.src).toBe(true);
    const locs = [...readFileSync(`${docs}sitemap.xml`, "utf8").matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1] ?? "");
    for (const loc of locs) {
      const file = loc.replace(BASE, "") || "index.html";
      expect(existsSync(`${docs}${file}`), loc).toBe(true);
    }
  });
});

describe("rules.html", () => {
  const d = doc("rules.html");
  it("is a self-contained, indexable page with every rule anchored", () => {
    expect(d.querySelector('link[rel="canonical"]')?.getAttribute("href")).toBe(`${BASE}rules.html`);
    expect(meta(d, "og:image")).toBe(`${BASE}assets/og.png`);
    expect(d.querySelectorAll("h1")).toHaveLength(1);
    for (const r of RULES) expect(d.getElementById(r.id.toLowerCase()), r.id).not.toBeNull();
    expect(d.querySelector("script:not([type])")).toBeNull();
  });
});
