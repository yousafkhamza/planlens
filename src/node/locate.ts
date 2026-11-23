import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import type { SourceLocation } from "../report/sarif.js";

/** Split a Terraform address into segments, respecting quoted keys: module.a["x.y"].aws_s3_bucket.b[0] */
export function splitAddress(address: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let depth = 0;
  let inStr = false;
  for (let i = 0; i < address.length; i++) {
    const ch = address[i] as string;
    if (inStr) {
      cur += ch;
      if (ch === "\\") {
        cur += address[++i] ?? "";
      } else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    if (ch === "[") depth++;
    if (ch === "]") depth--;
    if (ch === "." && depth === 0) {
      parts.push(cur);
      cur = "";
    } else cur += ch;
  }
  if (cur) parts.push(cur);
  return parts.map((p) => p.replace(/\[.*\]$/, ""));
}

export interface ParsedAddress {
  modules: string[];
  mode: "managed" | "data";
  type?: string;
  name?: string;
}

export function parseAddress(address: string): ParsedAddress {
  const seg = splitAddress(address);
  const modules: string[] = [];
  let i = 0;
  while (seg[i] === "module" && seg[i + 1] !== undefined) {
    modules.push(seg[i + 1] as string);
    i += 2;
  }
  let mode: "managed" | "data" = "managed";
  if (seg[i] === "data") {
    mode = "data";
    i++;
  }
  return { modules, mode, type: seg[i], name: seg[i + 1] };
}

/**
 * Maps resource addresses to `.tf` file + line so SARIF results show up
 * inline in pull requests. Only local module sources can be followed.
 */
export class SourceLocator {
  private cache = new Map<string, Array<{ file: string; lines: string[] }>>();

  constructor(
    private readonly rootDir: string,
    private readonly moduleSources: Record<string, string>,
    private readonly repoRoot: string = process.cwd(),
  ) {}

  private tfFiles(dir: string): Array<{ file: string; lines: string[] }> {
    const hit = this.cache.get(dir);
    if (hit) return hit;
    let files: Array<{ file: string; lines: string[] }> = [];
    try {
      files = readdirSync(dir)
        .filter((f) => f.endsWith(".tf"))
        .map((f) => join(dir, f))
        .filter((f) => statSync(f).isFile())
        .map((f) => ({ file: f, lines: readFileSync(f, "utf8").split(/\r?\n/) }));
    } catch {
      files = [];
    }
    this.cache.set(dir, files);
    return files;
  }

  private find(dir: string, re: RegExp): SourceLocation | undefined {
    for (const { file, lines } of this.tfFiles(dir)) {
      const idx = lines.findIndex((l) => re.test(l));
      if (idx >= 0) return { uri: relative(this.repoRoot, file).replace(/\\/g, "/"), line: idx + 1 };
    }
    return undefined;
  }

  locate(address: string): SourceLocation | undefined {
    if (!existsSync(this.rootDir)) return undefined;
    const p = parseAddress(address);
    let dir = resolve(this.rootDir);
    let modAddr = "";
    let lastCall: SourceLocation | undefined;
    for (const m of p.modules) {
      const callRe = new RegExp(`^\\s*module\\s+"${escapeRe(m)}"\\s*\\{`);
      lastCall = this.find(dir, callRe) ?? lastCall;
      modAddr = modAddr ? `${modAddr}.module.${m}` : `module.${m}`;
      const src = this.moduleSources[modAddr];
      if (!src || !(src.startsWith("./") || src.startsWith("../"))) return lastCall; // registry/git module → point at the module call
      dir = resolve(dir, src);
    }
    if (!p.type || !p.name) return lastCall;
    const kw = p.mode === "data" ? "data" : "resource";
    const re = new RegExp(`^\\s*${kw}\\s+"${escapeRe(p.type)}"\\s+"${escapeRe(p.name)}"`);
    return this.find(dir, re) ?? lastCall;
  }
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
