export type PathStep = string | number;

export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** ["ingress", 0, "cidr_blocks"] -> "ingress[0].cidr_blocks" */
export function formatPath(steps: readonly PathStep[]): string {
  let out = "";
  for (const s of steps) {
    if (typeof s === "number") out += `[${s}]`;
    else out += out === "" ? s : `.${s}`;
  }
  return out;
}

/** "ingress[0].cidr_blocks" -> ["ingress", 0, "cidr_blocks"]; "tags.Name" -> ["tags","Name"] */
export function parsePath(path: string): PathStep[] {
  const steps: PathStep[] = [];
  const re = /([^.[\]]+)|\[(\d+|\*)\]/g;
  for (const m of path.matchAll(re)) {
    if (m[1] !== undefined) steps.push(m[1]);
    else if (m[2] === "*") steps.push("*");
    else if (m[2] !== undefined) steps.push(Number(m[2]));
  }
  return steps;
}

/**
 * Resolve a path and return every value it reaches. Terraform renders nested
 * blocks as arrays, so a string key applied to an array fans out over its
 * elements: `vpc_config.endpoint_public_access` works without `[0]`.
 * `*` matches every element/key.
 */
export function getAll(root: unknown, path: string | readonly PathStep[]): unknown[] {
  const steps = typeof path === "string" ? parsePath(path) : path;
  let current: unknown[] = [root];
  for (const step of steps) {
    const next: unknown[] = [];
    for (const node of current) {
      if (node === null || node === undefined) continue;
      if (step === "*") {
        if (Array.isArray(node)) next.push(...node);
        else if (isRecord(node)) next.push(...Object.values(node));
      } else if (typeof step === "number") {
        if (Array.isArray(node) && step < node.length) next.push(node[step]);
      } else if (Array.isArray(node)) {
        for (const el of node) if (isRecord(el) && step in el) next.push(el[step]);
      } else if (isRecord(node) && step in node) {
        next.push(node[step]);
      }
    }
    current = next;
  }
  return current.filter((v) => v !== undefined);
}

export function getOne(root: unknown, path: string | readonly PathStep[]): unknown {
  return getAll(root, path)[0];
}

/** Is the value at `steps` marked sensitive by a Terraform *_sensitive mask? */
export function isSensitiveAt(mask: unknown, steps: readonly PathStep[]): boolean {
  let node = mask;
  if (node === true) return true;
  for (const step of steps) {
    if (node === true) return true;
    if (Array.isArray(node) && typeof step === "number") node = node[step];
    else if (Array.isArray(node) && typeof step === "string") {
      // fan-out: sensitive if any element marks the key sensitive
      return node.some((el) => isSensitiveAt(el, [step]));
    } else if (isRecord(node) && typeof step === "string") node = node[step];
    else return false;
  }
  return node === true;
}

/** True if the mask has any `true` anywhere inside. */
export function containsSensitive(mask: unknown): boolean {
  if (mask === true) return true;
  if (Array.isArray(mask)) return mask.some(containsSensitive);
  if (isRecord(mask)) return Object.values(mask).some(containsSensitive);
  return false;
}

export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a)) {
    if (!Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  if (isRecord(a) && isRecord(b)) {
    const ka = Object.keys(a).filter((k) => a[k] !== null && a[k] !== undefined);
    const kb = Object.keys(b).filter((k) => b[k] !== null && b[k] !== undefined);
    if (ka.length !== kb.length) return false;
    return ka.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

/**
 * Leaf paths that differ between before and after, plus paths that become
 * unknown ("known after apply"). Depth-limited to keep output readable.
 */
export function changedPaths(before: unknown, after: unknown, afterUnknown: unknown, maxDepth = 4): string[] {
  const out = new Set<string>();
  const walk = (b: unknown, a: unknown, u: unknown, steps: PathStep[]): void => {
    if (u === true) {
      if (b !== null && b !== undefined) out.add(formatPath(steps));
      return;
    }
    if (deepEqual(b, a) && !containsTrue(u)) return;
    if (steps.length >= maxDepth) {
      out.add(formatPath(steps));
      return;
    }
    if (isRecord(b) || isRecord(a)) {
      const br = isRecord(b) ? b : {};
      const ar = isRecord(a) ? a : {};
      const ur = isRecord(u) ? u : {};
      const keys = new Set([...Object.keys(br), ...Object.keys(ar), ...Object.keys(ur)]);
      for (const k of keys) walk(br[k], ar[k], ur[k], [...steps, k]);
      return;
    }
    if (Array.isArray(b) && Array.isArray(a) && b.length === a.length && b.length > 0) {
      const ua = Array.isArray(u) ? u : [];
      for (let i = 0; i < a.length; i++) walk(b[i], a[i], ua[i], [...steps, i]);
      return;
    }
    if (steps.length > 0) out.add(formatPath(steps));
  };
  walk(before, after, afterUnknown, []);
  return [...out].sort();
}

function containsTrue(v: unknown): boolean {
  return containsSensitive(v);
}

const regexCache = new Map<string, RegExp>();

/** Glob match: `*` = any run of characters, `?` = one character. Case-sensitive. */
export function globMatch(pattern: string, value: string): boolean {
  let re = regexCache.get(pattern);
  if (!re) {
    const src = pattern
      .split("")
      .map((c) => {
        if (c === "*") return ".*";
        if (c === "?") return ".";
        return c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
      })
      .join("");
    re = new RegExp(`^${src}$`);
    regexCache.set(pattern, re);
  }
  return re.test(value);
}

export function anyGlob(patterns: string | string[] | undefined, value: string): boolean {
  if (patterns === undefined) return true;
  const list = Array.isArray(patterns) ? patterns : [patterns];
  return list.some((p) => globMatch(p, value));
}

/** Short, single-line rendering of an attribute value for reports. */
export function show(v: unknown, max = 80): string {
  let s: string;
  if (v === undefined) s = "(unset)";
  else if (typeof v === "string") s = JSON.stringify(v);
  else s = JSON.stringify(v) ?? String(v);
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

export const SENSITIVE = "(sensitive)";
export const UNKNOWN = "(known after apply)";

export function truthy(v: unknown): boolean {
  return v === true || v === "true";
}

export function asArray<T = unknown>(v: unknown): T[] {
  if (v === null || v === undefined) return [];
  return (Array.isArray(v) ? v : [v]) as T[];
}

export function plural(n: number, word: string, pluralWord = `${word}s`): string {
  return `${n} ${n === 1 ? word : pluralWord}`;
}
