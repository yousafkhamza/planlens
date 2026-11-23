import { existsSync, readdirSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

const SKIP_DIRS = new Set([".git", "node_modules", ".terraform", ".terragrunt-cache"]);

export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] as string;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += glob[i + 2] === "/" ? "(?:.*/)?" : ".*";
        i += glob[i + 2] === "/" ? 2 : 1;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

function walk(dir: string, out: string[]): void {
  let entries: import("node:fs").Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) walk(join(dir, e.name), out);
    } else if (e.isFile()) out.push(join(dir, e.name));
  }
}

/**
 * Expand newline/comma separated patterns. Plain paths are passed through
 * unchanged (so missing files produce a clear error later).
 */
export function expandPatterns(input: string, cwd = process.cwd()): string[] {
  const patterns = input
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
  const out: string[] = [];
  for (const pattern of patterns) {
    if (!/[*?]/.test(pattern)) {
      out.push(pattern);
      continue;
    }
    const norm = pattern.replace(/\\/g, "/");
    const firstGlob = norm.search(/[*?]/);
    const baseRel = norm.slice(0, norm.lastIndexOf("/", firstGlob) + 1) || ".";
    const base = resolve(cwd, baseRel);
    if (!existsSync(base)) continue;
    const files: string[] = [];
    walk(base, files);
    const re = globToRegExp(norm.replace(/^\.\//, ""));
    for (const f of files) {
      const rel = relative(cwd, f).split(sep).join("/");
      if (re.test(rel)) out.push(rel);
    }
  }
  return [...new Set(out)].sort();
}
