import { managedChanges } from "../plan.js";
import type { ResourceChange, Rule, Severity } from "../types.js";
import { asArray, getAll, isRecord, isSensitiveAt, type PathStep } from "../util.js";
import { type Hit, writes } from "./helpers.js";

const SECRET_KEY =
  /(passw(or)?d|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|client[_-]?secret|credential|conn(ection)?[_-]?str(ing)?|\bdsn\b)/i;
const NOT_SECRET_KEY = /(_?arn|_?name|_?id|_?url|_?uri|_?path|_?param(eter)?|_?file|_?ref|_?key_?id|_?length|_?ttl|_?enabled|_?expir\w*|_?header|_?type)$/i;
const REFERENCE_VALUE = /^(arn:|\$\{|\/|ssm:|secretsmanager:|vault:|projects\/|https?:\/\/|\{\{|@Microsoft\.KeyVault)|\{\{resolve:/;

export function looksLikeSecretKey(key: string): boolean {
  return SECRET_KEY.test(key) && !NOT_SECRET_KEY.test(key);
}

export function looksLikeLiteralSecret(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const s = value.trim();
  if (s.length < 6 || REFERENCE_VALUE.test(s)) return false;
  if (/^(true|false|null|none|enabled|disabled|\d+)$/i.test(s)) return false;
  return true;
}

interface TokenPattern {
  name: string;
  re: RegExp;
  severity: Severity;
}

export const TOKEN_PATTERNS: TokenPattern[] = [
  { name: "private key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----/, severity: "critical" },
  { name: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, severity: "high" },
  { name: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/, severity: "critical" },
  { name: "GitLab token", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/, severity: "critical" },
  { name: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, severity: "high" },
  { name: "Stripe live key", re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/, severity: "critical" },
  { name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: "high" },
  { name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, severity: "critical" },
  { name: "OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/, severity: "critical" },
];

function article(noun: string): string {
  return `${/^[aeiou]/i.test(noun) ? "an" : "a"} ${noun}`;
}

export function findTokens(text: string): TokenPattern[] {
  return TOKEN_PATTERNS.filter((p) => p.re.test(text));
}

function tryBase64(s: string): string | undefined {
  if (s.length < 16 || !/^[A-Za-z0-9+/=\s]+$/.test(s)) return undefined;
  try {
    const bin = atob(s.replace(/\s+/g, ""));
    // Only accept mostly-printable output.
    const printable = bin.split("").filter((c) => c >= " " || c === "\n" || c === "\r" || c === "\t").length;
    return printable / Math.max(bin.length, 1) > 0.9 ? bin : undefined;
  } catch {
    return undefined;
  }
}

/** Walk non-sensitive string leaves of an object. */
function walkStrings(node: unknown, mask: unknown, steps: PathStep[], visit: (s: string, steps: PathStep[]) => void): void {
  if (isSensitiveAt(mask, steps)) return;
  if (typeof node === "string") visit(node, steps);
  else if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) walkStrings(node[i], mask, [...steps, i], visit);
  } else if (isRecord(node)) for (const [k, val] of Object.entries(node)) walkStrings(val, mask, [...steps, k], visit);
}

function tokenSet(rc: ResourceChange, side: "before" | "after"): Map<string, TokenPattern> {
  const out = new Map<string, TokenPattern>();
  const obj = side === "before" ? rc.before : rc.after;
  const mask = side === "before" ? rc.beforeSensitive : rc.afterSensitive;
  walkStrings(obj, mask, [], (s, steps) => {
    const top = String(steps[0] ?? "");
    const candidates = [s];
    if (/user_data/.test(top)) {
      const decoded = tryBase64(s);
      if (decoded) candidates.push(decoded);
    }
    for (const c of candidates) for (const p of findTokens(c)) out.set(`${top}|${p.name}`, p);
  });
  return out;
}

/** (env var name, value) pairs from the places apps usually get configuration. */
function envPairs(rc: ResourceChange, side: "before" | "after"): Array<{ key: string; value: unknown; where: string; sensitive: boolean }> {
  const obj = side === "before" ? rc.before : rc.after;
  const mask = side === "before" ? rc.beforeSensitive : rc.afterSensitive;
  if (!obj) return [];
  const out: Array<{ key: string; value: unknown; where: string; sensitive: boolean }> = [];
  const fromMap = (path: string, where: string) => {
    getAll(obj, path).forEach((m) => {
      if (!isRecord(m)) return;
      for (const [k, val] of Object.entries(m)) {
        const sensitive = isSensitiveAt(mask, [...path.split("."), k]) || isSensitiveAt(mask, [path.split(".")[0] ?? ""]);
        out.push({ key: k, value: val, where, sensitive });
      }
    });
  };
  const fromList = (list: unknown[], where: string, sensitive: boolean) => {
    for (const e of list) {
      if (isRecord(e) && typeof e.name === "string") out.push({ key: e.name, value: e.value, where, sensitive });
    }
  };
  switch (rc.type) {
    case "aws_lambda_function":
      fromMap("environment.variables", "environment variables");
      break;
    case "azurerm_linux_web_app":
    case "azurerm_windows_web_app":
    case "azurerm_linux_function_app":
    case "azurerm_windows_function_app":
    case "azurerm_app_service":
    case "azurerm_function_app":
      fromMap("app_settings", "app_settings");
      break;
    case "aws_ecs_task_definition": {
      const cd = obj.container_definitions;
      if (typeof cd === "string" && !isSensitiveAt(mask, ["container_definitions"])) {
        try {
          const defs = JSON.parse(cd) as unknown[];
          for (const d of asArray<unknown>(defs)) if (isRecord(d)) fromList(asArray(d.environment), `container "${String(d.name)}" environment`, false);
        } catch {
          /* unknown at plan time or invalid */
        }
      }
      break;
    }
    case "google_cloud_run_v2_service":
    case "google_cloud_run_v2_job":
      fromList(
        getAll(obj, "template.containers.env").flatMap((x) => asArray(x)),
        "container env",
        false,
      );
      fromList(
        getAll(obj, "template.template.containers.env").flatMap((x) => asArray(x)),
        "container env",
        false,
      );
      break;
    case "google_cloud_run_service":
      fromList(
        getAll(obj, "template.spec.containers.env").flatMap((x) => asArray(x)),
        "container env",
        false,
      );
      break;
    case "kubernetes_deployment":
    case "kubernetes_deployment_v1":
    case "kubernetes_stateful_set":
    case "kubernetes_stateful_set_v1":
    case "kubernetes_cron_job_v1":
    case "kubernetes_pod":
    case "kubernetes_pod_v1":
      fromList(
        getAll(obj, "spec.template.spec.container.env").flatMap((x) => asArray(x)),
        "container env",
        false,
      );
      fromList(
        getAll(obj, "spec.container.env").flatMap((x) => asArray(x)),
        "container env",
        false,
      );
      break;
    default:
      break;
  }
  return out;
}

export const hardcodedSecrets: Rule = {
  id: "PL401",
  title: "Plaintext secret in resource configuration",
  severity: "high",
  category: "secrets",
  description:
    "A credential-looking value (API key, token, private key, password-named environment variable) is set as plain text. It ends up in the plan, the state file, CI logs and the provider's console.",
  remediation:
    "Reference secrets from Secrets Manager / SSM SecureString / Key Vault / Secret Manager at runtime (ECS `secrets`, Lambda extension, CSI driver) instead of literal values, and rotate any value that was already committed.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (!writes(rc)) continue;
      // 1. Known token formats anywhere in non-sensitive attributes.
      const before = rc.kind === "create" ? new Map() : tokenSet(rc, "before");
      for (const [key, p] of tokenSet(rc, "after")) {
        if (before.has(key)) continue;
        const attr = key.split("|")[0];
        hits.push({
          severity: p.severity,
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\`: \`${attr}\` contains what looks like ${article(p.name)} in plain text.`,
          details: ["Value not shown."],
        });
      }
      // 2. Secret-named environment variables with literal values.
      const prev = new Set(rc.kind === "create" ? [] : envPairs(rc, "before").map((e) => `${e.key}=${String(e.value)}`));
      const flagged = envPairs(rc, "after").filter(
        (e) =>
          !e.sensitive &&
          looksLikeSecretKey(e.key) &&
          looksLikeLiteralSecret(e.value) &&
          findTokens(String(e.value)).length === 0 && // already reported above with a precise type
          !prev.has(`${e.key}=${String(e.value)}`),
      );
      if (flagged.length) {
        hits.push({
          severity: "high",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` sets ${flagged.map((e) => `\`${e.key}\``).join(", ")} as plain-text ${flagged[0]?.where ?? "values"}.`,
          details: ["Values not shown."],
        });
      }
      // 3. SSM parameters with secret-looking names stored as String.
      if (rc.type === "aws_ssm_parameter" && rc.after && rc.after.type !== "SecureString" && looksLikeSecretKey(String(rc.after.name ?? ""))) {
        if (rc.kind === "create" || rc.before?.type === "SecureString") {
          hits.push({
            severity: "medium",
            address: rc.address,
            resourceType: rc.type,
            message: `\`${rc.address}\` (\`${String(rc.after.name)}\`) stores a secret-looking parameter as \`${String(rc.after.type)}\` instead of \`SecureString\`.`,
            details: [],
          });
        }
      }
    }
    return hits;
  },
};

export const outputSecrets: Rule = {
  id: "PL402",
  title: "Output exposes a secret without `sensitive = true`",
  severity: "high",
  category: "secrets",
  description:
    "An output whose name or value looks like a credential is not marked sensitive, so it is printed in CI logs and readable via `terraform output`.",
  remediation: "Add `sensitive = true` to the output, or stop exporting the secret and have consumers read it from a secret store.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const o of plan.outputs) {
      if (o.sensitive || (o.kind !== "create" && o.kind !== "update")) continue;
      if ((o.after === null || o.after === undefined) && !o.afterUnknown) continue;
      const text = typeof o.after === "string" ? o.after : (JSON.stringify(o.after) ?? "");
      const tokens = findTokens(text);
      if (tokens.length) {
        hits.push({
          severity: "critical",
          address: `output.${o.name}`,
          message: `Output \`${o.name}\` contains what looks like ${article(tokens[0]?.name ?? "secret")} and is not marked sensitive.`,
          details: [],
        });
      } else if (looksLikeSecretKey(o.name) && (o.afterUnknown || looksLikeLiteralSecret(o.after))) {
        hits.push({
          severity: "high",
          address: `output.${o.name}`,
          message: `Output \`${o.name}\` looks like a secret but is not marked \`sensitive = true\`.`,
          details: [],
        });
      }
    }
    return hits;
  },
};
