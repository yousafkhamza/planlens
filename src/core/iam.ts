import { asArray, globMatch, isRecord } from "./util.js";

export interface Statement {
  sid?: string;
  effect: "Allow" | "Deny";
  actions: string[];
  notActions: string[];
  resources: string[];
  notResources: string[];
  /** Normalized principal: map of type -> values. `"*"` becomes {"*": ["*"]}. */
  principals: Record<string, string[]>;
  hasPrincipal: boolean;
  condition: Record<string, Record<string, unknown>>;
  /** Stable key used to detect statements that are new in `after`. */
  key: string;
}

/** Parse an IAM policy document from a JSON string or object. Returns null if unparseable/unknown. */
export function parsePolicy(doc: unknown): Statement[] | null {
  let obj: unknown = doc;
  if (typeof doc === "string") {
    if (doc.trim() === "") return null;
    try {
      obj = JSON.parse(doc);
    } catch {
      return null;
    }
  }
  if (!isRecord(obj)) return null;
  const raw = asArray<unknown>(obj.Statement);
  const out: Statement[] = [];
  for (const s of raw) {
    if (!isRecord(s)) continue;
    const principals: Record<string, string[]> = {};
    let hasPrincipal = false;
    if (s.Principal !== undefined) {
      hasPrincipal = true;
      if (s.Principal === "*") principals["*"] = ["*"];
      else if (isRecord(s.Principal)) {
        for (const [k, v] of Object.entries(s.Principal)) principals[k] = asArray<unknown>(v).map(String);
      }
    }
    const condition: Record<string, Record<string, unknown>> = {};
    if (isRecord(s.Condition)) {
      for (const [op, kv] of Object.entries(s.Condition)) if (isRecord(kv)) condition[op] = kv;
    }
    const st: Omit<Statement, "key"> = {
      sid: typeof s.Sid === "string" ? s.Sid : undefined,
      effect: s.Effect === "Deny" ? "Deny" : "Allow",
      actions: asArray<unknown>(s.Action).map(String),
      notActions: asArray<unknown>(s.NotAction).map(String),
      resources: asArray<unknown>(s.Resource).map(String),
      notResources: asArray<unknown>(s.NotResource).map(String),
      principals,
      hasPrincipal,
      condition,
    };
    out.push({ ...st, key: statementKey(st) });
  }
  return out;
}

function sortedDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortedDeep).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  if (isRecord(v)) {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) o[k] = sortedDeep(v[k]);
    return o;
  }
  return v;
}

function statementKey(s: Omit<Statement, "key">): string {
  const { sid: _sid, ...rest } = s;
  return JSON.stringify(sortedDeep({ ...rest, actions: rest.actions.map((a) => a.toLowerCase()) }));
}

/** Statements present in `after` but not in `before` (by content, ignoring Sid/order). */
export function newStatements(before: unknown, after: unknown): Statement[] {
  const a = parsePolicy(after);
  if (!a) return [];
  const b = parsePolicy(before) ?? [];
  const seen = new Set(b.map((s) => s.key));
  return a.filter((s) => !seen.has(s.key));
}

/** Does any action pattern in the statement grant `action` (case-insensitive glob)? */
export function grants(st: Statement, action: string): boolean {
  if (st.effect !== "Allow") return false;
  const target = action.toLowerCase();
  if (st.notActions.length > 0) {
    // NotAction + Allow grants everything not listed.
    return !st.notActions.some((p) => globMatch(p.toLowerCase(), target));
  }
  return st.actions.some((p) => globMatch(p.toLowerCase(), target));
}

export function allResources(st: Statement): boolean {
  return st.notResources.length > 0 || st.resources.includes("*");
}

export function isFullAdmin(st: Statement): boolean {
  if (st.effect !== "Allow") return false;
  const allActions = st.actions.includes("*") || (st.notActions.length > 0 && st.actions.length === 0);
  return allActions && allResources(st);
}

/** Service-level wildcards like `s3:*`, `iam:*`. */
export function serviceWildcards(st: Statement): string[] {
  if (st.effect !== "Allow") return [];
  return st.actions.filter((a) => /^[a-z0-9-]+:\*$/i.test(a));
}

/** Actions that let a principal grant itself more privileges. */
export const ESCALATION_ACTIONS = [
  "iam:PassRole",
  "iam:CreatePolicyVersion",
  "iam:SetDefaultPolicyVersion",
  "iam:AttachUserPolicy",
  "iam:AttachRolePolicy",
  "iam:AttachGroupPolicy",
  "iam:PutUserPolicy",
  "iam:PutRolePolicy",
  "iam:PutGroupPolicy",
  "iam:CreateAccessKey",
  "iam:CreateLoginProfile",
  "iam:UpdateLoginProfile",
  "iam:UpdateAssumeRolePolicy",
  "iam:AddUserToGroup",
  "iam:CreateRole",
  "sts:AssumeRole",
];

export function escalationActions(st: Statement): string[] {
  if (!allResources(st)) return [];
  return ESCALATION_ACTIONS.filter((a) => grants(st, a));
}

/** True when the statement's principal includes everyone. */
export function isPublicPrincipal(st: Statement): boolean {
  for (const [type, values] of Object.entries(st.principals)) {
    if (type === "*" || ((type === "AWS" || type === "CanonicalUser") && values.includes("*"))) return true;
  }
  return false;
}

export function hasConditions(st: Statement): boolean {
  return Object.keys(st.condition).length > 0;
}

/** All condition keys (lower-cased) mapped to their values, across operators. */
export function conditionValues(st: Statement): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const kv of Object.values(st.condition)) {
    for (const [k, v] of Object.entries(kv)) {
      const key = k.toLowerCase();
      out[key] = [...(out[key] ?? []), ...asArray<unknown>(v).map(String)];
    }
  }
  return out;
}

/** AWS managed policies that are effectively admin. */
export const ADMIN_MANAGED_POLICIES: Record<string, "critical" | "high"> = {
  "arn:aws:iam::aws:policy/AdministratorAccess": "critical",
  "arn:aws:iam::aws:policy/IAMFullAccess": "critical",
  "arn:aws:iam::aws:policy/PowerUserAccess": "high",
  "arn:aws:iam::aws:policy/AmazonS3FullAccess": "high",
  "arn:aws:iam::aws:policy/AmazonEC2FullAccess": "high",
  "arn:aws:iam::aws:policy/SecretsManagerReadWrite": "high",
  "arn:aws:iam::aws:policy/AWSLambda_FullAccess": "high",
  "arn:aws:iam::aws:policy/AmazonRDSFullAccess": "high",
  "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess": "high",
};

/** Matches managed policy ARNs across partitions (aws, aws-us-gov, aws-cn). */
export function managedPolicySeverity(arn: string): "critical" | "high" | undefined {
  const normalized = arn.replace(/^arn:aws-[a-z-]+:/, "arn:aws:");
  return ADMIN_MANAGED_POLICIES[normalized];
}
