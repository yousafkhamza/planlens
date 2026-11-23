import {
  allResources,
  conditionValues,
  escalationActions,
  grants,
  hasConditions,
  isFullAdmin,
  isPublicPrincipal,
  managedPolicySeverity,
  newStatements,
  type Statement,
  serviceWildcards,
} from "../iam.js";
import { managedChanges } from "../plan.js";
import type { ResourceChange, Rule } from "../types.js";
import { asArray, getAll, isRecord } from "../util.js";
import { type Hit, introduced, isUnknown, writes } from "./helpers.js";

/** Identity-policy attributes by resource type. */
const IDENTITY_POLICY_PATHS: Record<string, string[]> = {
  aws_iam_policy: ["policy"],
  aws_iam_role_policy: ["policy"],
  aws_iam_user_policy: ["policy"],
  aws_iam_group_policy: ["policy"],
  aws_iam_role: ["inline_policy.policy"],
  aws_ssoadmin_permission_set_inline_policy: ["inline_policy"],
};

/** Resource-based policy attributes by resource type. */
const RESOURCE_POLICY_PATHS: Record<string, string> = {
  aws_s3_bucket_policy: "policy",
  aws_s3_bucket: "policy",
  aws_sqs_queue_policy: "policy",
  aws_sqs_queue: "policy",
  aws_sns_topic_policy: "policy",
  aws_sns_topic: "policy",
  aws_kms_key: "policy",
  aws_ecr_repository_policy: "policy",
  aws_secretsmanager_secret_policy: "policy",
  aws_secretsmanager_secret: "policy",
  aws_opensearch_domain_policy: "access_policies",
  aws_opensearch_domain: "access_policies",
  aws_elasticsearch_domain_policy: "access_policies",
  aws_elasticsearch_domain: "access_policies",
  aws_efs_file_system_policy: "policy",
  aws_api_gateway_rest_api_policy: "policy",
  aws_backup_vault_policy: "policy",
  aws_glacier_vault: "access_policy",
};

function joinDocs(values: unknown[]): unknown {
  // Several inline policies → merge statements into one synthetic document.
  const statements: unknown[] = [];
  for (const val of values) {
    let doc: unknown = val;
    if (typeof val === "string") {
      try {
        doc = JSON.parse(val);
      } catch {
        continue;
      }
    }
    if (isRecord(doc)) statements.push(...asArray(doc.Statement));
  }
  return { Statement: statements };
}

/** New statements in identity policies of this change (empty if policy is unknown until apply). */
function newIdentityStatements(rc: ResourceChange): Statement[] {
  const paths = IDENTITY_POLICY_PATHS[rc.type];
  if (!paths || !writes(rc)) return [];
  const out: Statement[] = [];
  for (const p of paths) {
    if (isUnknown(rc, p)) continue;
    const after = joinDocs(getAll(rc.after, p));
    const before = rc.kind === "create" ? { Statement: [] } : joinDocs(getAll(rc.before, p));
    out.push(...newStatements(before, after));
  }
  return out;
}

function describe(st: Statement): string {
  const act = st.notActions.length
    ? `NotAction ${JSON.stringify(st.notActions)}`
    : `Action ${JSON.stringify(st.actions.length === 1 ? st.actions[0] : st.actions)}`;
  const res = st.notResources.length
    ? `NotResource ${JSON.stringify(st.notResources)}`
    : `Resource ${JSON.stringify(st.resources.length === 1 ? st.resources[0] : st.resources)}`;
  return `${st.sid ? `Sid "${st.sid}": ` : ""}${act} on ${res}`;
}

export const fullAdmin: Rule = {
  id: "PL301",
  title: "IAM policy grants full admin (*:*)",
  severity: "critical",
  category: "iam",
  description: "A new policy statement allows every action on every resource (or uses NotAction with Allow).",
  remediation:
    "Grant only the actions and resources the workload needs. Use IAM Access Analyzer policy generation to derive least-privilege policies from CloudTrail.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      for (const st of newIdentityStatements(rc)) {
        if (!isFullAdmin(st)) continue;
        hits.push({
          severity: "critical",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` grants full administrator access.`,
          details: [describe(st)],
        });
      }
    }
    return hits;
  },
};

export const serviceWildcard: Rule = {
  id: "PL302",
  title: "IAM policy grants service-wide wildcard on all resources",
  severity: "high",
  category: "iam",
  description: 'A new statement allows `service:*` on `Resource: "*"` (e.g. `s3:*` on every bucket in the account).',
  remediation: "List the specific actions needed and scope `Resource` to specific ARNs.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      for (const st of newIdentityStatements(rc)) {
        if (isFullAdmin(st) || !allResources(st)) continue;
        const wild = serviceWildcards(st);
        if (wild.length === 0) continue;
        const sev = wild.some((w) => /^(iam|sts|organizations|kms):\*$/i.test(w)) ? "critical" : "high";
        hits.push({
          severity: sev,
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` grants ${wild.map((w) => `\`${w}\``).join(", ")} on all resources.`,
          details: [describe(st)],
        });
      }
    }
    return hits;
  },
};

export const privilegeEscalation: Rule = {
  id: "PL303",
  title: "IAM policy allows privilege escalation",
  severity: "high",
  category: "iam",
  description:
    "A new statement grants actions that let the principal give itself more permissions (iam:PassRole, iam:CreatePolicyVersion, iam:Attach*Policy, iam:Put*Policy, iam:CreateAccessKey, iam:UpdateAssumeRolePolicy…) on all resources.",
  remediation: "Scope these actions to specific role/user ARNs, and constrain iam:PassRole with an `iam:PassedToService` condition.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      for (const st of newIdentityStatements(rc)) {
        if (isFullAdmin(st) || serviceWildcards(st).some((w) => /^iam:\*$/i.test(w))) continue;
        let actions = escalationActions(st);
        const cond = conditionValues(st);
        if (cond["iam:passedtoservice"]) actions = actions.filter((a) => a !== "iam:PassRole");
        if (actions.length === 0) continue;
        hits.push({
          severity: "high",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` allows privilege escalation via ${actions
            .slice(0, 5)
            .map((a) => `\`${a}\``)
            .join(", ")}${actions.length > 5 ? "…" : ""} on all resources.`,
          details: [describe(st)],
        });
      }
    }
    return hits;
  },
};

export const adminManagedPolicy: Rule = {
  id: "PL304",
  title: "Admin-level AWS managed policy attached",
  severity: "critical",
  category: "iam",
  description: "AdministratorAccess, IAMFullAccess, PowerUserAccess or another *FullAccess managed policy is attached.",
  remediation: "Replace with a customer-managed least-privilege policy. Reserve AdministratorAccess for break-glass roles behind MFA.",
  run({ plan }) {
    const hits: Hit[] = [];
    const attachTypes: Record<string, string> = {
      aws_iam_role_policy_attachment: "policy_arn",
      aws_iam_user_policy_attachment: "policy_arn",
      aws_iam_group_policy_attachment: "policy_arn",
      aws_iam_policy_attachment: "policy_arn",
      aws_ssoadmin_managed_policy_attachment: "managed_policy_arn",
      aws_iam_role: "managed_policy_arns",
    };
    for (const rc of managedChanges(plan)) {
      const path = attachTypes[rc.type];
      if (!path || !writes(rc)) continue;
      const before = new Set(
        rc.kind === "create"
          ? []
          : getAll(rc.before, path)
              .flatMap((x) => asArray(x))
              .map(String),
      );
      for (const arn of getAll(rc.after, path)
        .flatMap((x) => asArray(x))
        .map(String)) {
        if (before.has(arn)) continue;
        const sev = managedPolicySeverity(arn);
        if (!sev) continue;
        hits.push({
          severity: sev,
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` attaches \`${arn.split("/").pop()}\`.`,
          details: [arn],
        });
      }
    }
    return hits;
  },
};

export const publicResourcePolicy: Rule = {
  id: "PL305",
  title: 'Resource policy allows anyone (Principal "*")',
  severity: "critical",
  category: "iam",
  description:
    'A bucket/queue/topic/key/secret policy statement allows `Principal: "*"` without any Condition — the resource is public to every AWS account and often the internet.',
  remediation: "Name explicit principals, or add conditions such as `aws:PrincipalOrgID`, `aws:SourceVpce` or `aws:SourceArn`.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      const path = RESOURCE_POLICY_PATHS[rc.type];
      if (!path || !writes(rc) || isUnknown(rc, path)) continue;
      const before = rc.kind === "create" ? undefined : rc.before?.[path];
      for (const st of newStatements(before, rc.after?.[path])) {
        if (st.effect !== "Allow" || !isPublicPrincipal(st) || hasConditions(st)) continue;
        hits.push({
          severity: "critical",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` allows \`Principal: "*"\` with no conditions.`,
          details: [describe(st)],
        });
      }
    }
    return hits;
  },
};

function federatedProviders(st: Statement): string[] {
  return (st.principals.Federated ?? []).map(String);
}

export const oidcTrust: Rule = {
  id: "PL306",
  title: "OIDC trust policy not restricted to a subject",
  severity: "critical",
  category: "iam",
  description:
    "A role trusts a web-identity provider (GitHub Actions, EKS IRSA, GitLab, Terraform Cloud…) without restricting the token subject (`:sub`). For GitHub, that means any repository on github.com can assume the role.",
  remediation:
    "Add a `StringEquals`/`StringLike` condition on `<provider>:sub`, e.g. `token.actions.githubusercontent.com:sub = repo:my-org/my-repo:ref:refs/heads/main`, and on `:aud`.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (rc.type !== "aws_iam_role" || !writes(rc) || isUnknown(rc, "assume_role_policy")) continue;
      const before = rc.kind === "create" ? undefined : rc.before?.assume_role_policy;
      for (const st of newStatements(before, rc.after?.assume_role_policy)) {
        if (!grants(st, "sts:AssumeRoleWithWebIdentity")) continue;
        const providers = federatedProviders(st);
        if (providers.length === 0) continue;
        const isGithub = providers.some((p) => p.includes("token.actions.githubusercontent.com"));
        const cond = conditionValues(st);
        const subKeys = Object.keys(cond).filter((k) => k.endsWith(":sub"));
        const subs = subKeys.flatMap((k) => cond[k] ?? []);
        const provider = providers[0]?.split("/").slice(1).join("/") || providers[0];
        if (subs.length === 0) {
          hits.push({
            severity: isGithub ? "critical" : "high",
            address: rc.address,
            resourceType: rc.type,
            message: isGithub
              ? `\`${rc.address}\` trusts GitHub Actions OIDC with no \`sub\` condition — any GitHub repository can assume it.`
              : `\`${rc.address}\` trusts OIDC provider \`${provider}\` with no \`sub\` condition — any identity from that issuer can assume it.`,
            details: [],
          });
          continue;
        }
        const tooBroad = subs.filter((s) => s === "*" || /^repo:\*/.test(s) || /^system:serviceaccount:\*/.test(s));
        if (tooBroad.length) {
          hits.push({
            severity: "critical",
            address: rc.address,
            resourceType: rc.type,
            message: `\`${rc.address}\` trusts OIDC subject ${tooBroad.map((s) => `\`${s}\``).join(", ")} — effectively unrestricted.`,
            details: [],
          });
        }
      }
    }
    return hits;
  },
};

export const trustAnyPrincipal: Rule = {
  id: "PL307",
  title: "Role trust policy allows any AWS principal",
  severity: "critical",
  category: "iam",
  description: 'An IAM role can be assumed by `Principal: {"AWS": "*"}` — every AWS account in the world.',
  remediation: "Name the exact accounts/roles that may assume it, and require `sts:ExternalId` for third parties.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (rc.type !== "aws_iam_role" || !writes(rc) || isUnknown(rc, "assume_role_policy")) continue;
      const before = rc.kind === "create" ? undefined : rc.before?.assume_role_policy;
      for (const st of newStatements(before, rc.after?.assume_role_policy)) {
        if (st.effect !== "Allow" || !isPublicPrincipal(st)) continue;
        hits.push({
          severity: hasConditions(st) ? "medium" : "critical",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` can be assumed by any AWS principal${hasConditions(st) ? " (conditions apply — verify them)" : ""}.`,
          details: [],
        });
      }
    }
    return hits;
  },
};

export const accessKey: Rule = {
  id: "PL308",
  title: "Long-lived IAM access key created",
  severity: "medium",
  category: "secrets",
  description: "A static IAM access key is created. The secret ends up in Terraform state.",
  remediation:
    "Prefer IAM roles (IRSA, instance profiles, OIDC federation for CI). If a key is unavoidable, rotate it and keep state encrypted with restricted access.",
  run({ plan }) {
    return managedChanges(plan)
      .filter((rc) => rc.type === "aws_iam_access_key" && rc.kind === "create")
      .map((rc) => ({
        severity: "medium" as const,
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\` creates a long-lived access key (secret stored in state).`,
        details: [],
      }));
  },
};

export const publicLambda: Rule = {
  id: "PL309",
  title: "Lambda callable by anyone",
  severity: "high",
  category: "iam",
  description: "A Lambda permission allows principal `*` without `source_arn`/`source_account`/`principal_org_id`, or a function URL has no auth.",
  remediation: "Restrict the permission with `source_arn` (the calling service resource) or use `AWS_IAM` auth on function URLs.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (rc.type === "aws_lambda_permission" && introduced(rc, (o) => o.principal === "*" && !o.source_arn && !o.source_account && !o.principal_org_id)) {
        hits.push({
          severity: "high",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` lets any principal invoke the function.`,
          details: [],
        });
      }
      if (rc.type === "aws_lambda_function_url" && introduced(rc, (o) => o.authorization_type === "NONE")) {
        hits.push({
          severity: "medium",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` exposes a public function URL with no authentication.`,
          details: [],
        });
      }
    }
    return hits;
  },
};

const AZURE_PRIV_ROLES = new Set(["Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"]);

export const azurePrivilegedRole: Rule = {
  id: "PL310",
  title: "Privileged Azure role assigned",
  severity: "high",
  category: "iam",
  description: "Owner / Contributor / User Access Administrator is assigned at subscription or management-group scope (high) or resource-group scope (medium).",
  remediation: "Use built-in least-privilege roles or custom roles, assign at the narrowest scope, and use PIM for just-in-time elevation.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (rc.type !== "azurerm_role_assignment" || !writes(rc) || !rc.after) continue;
      const role = String(rc.after.role_definition_name ?? "");
      if (!AZURE_PRIV_ROLES.has(role)) continue;
      if (rc.kind !== "create" && rc.before?.role_definition_name === role && rc.before?.scope === rc.after.scope) continue;
      const scope = String(rc.after.scope ?? "");
      const broad = /^\/subscriptions\/[^/]+\/?$/i.test(scope) || /managementGroups\//i.test(scope);
      hits.push({
        severity: broad ? "high" : "medium",
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\` assigns **${role}** at ${broad ? "subscription/management-group" : "resource"} scope.`,
        details: scope ? [`Scope: \`${scope}\``] : [],
      });
    }
    return hits;
  },
};

const GCP_PUBLIC = new Set(["allUsers", "allAuthenticatedUsers"]);
const GCP_PRIMITIVE: Record<string, "high" | "medium"> = {
  "roles/owner": "high",
  "roles/editor": "high",
  "roles/iam.securityAdmin": "high",
  "roles/resourcemanager.projectIamAdmin": "high",
  "roles/iam.serviceAccountTokenCreator": "medium",
  "roles/iam.serviceAccountUser": "medium",
  "roles/iam.serviceAccountKeyAdmin": "medium",
};

function gcpBindings(o: Record<string, unknown>): Array<{ role: string; members: string[] }> {
  if (typeof o.policy_data === "string") {
    try {
      const doc = JSON.parse(o.policy_data) as { bindings?: Array<{ role?: string; members?: string[] }> };
      return (doc.bindings ?? []).map((b) => ({ role: String(b.role ?? ""), members: asArray<string>(b.members).map(String) }));
    } catch {
      return [];
    }
  }
  const members = [...asArray(o.member), ...asArray(o.members)].map(String);
  return [{ role: String(o.role ?? ""), members }];
}

export const gcpIam: Rule = {
  id: "PL311",
  title: "GCP IAM grants public or primitive role",
  severity: "high",
  category: "iam",
  description:
    "A GCP IAM binding grants access to `allUsers`/`allAuthenticatedUsers` (critical) or a primitive/admin role such as roles/owner or roles/editor (high).",
  remediation: "Grant predefined least-privilege roles to specific groups/service accounts. Never bind allUsers to non-public data.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (!/^google_.*_iam_(member|binding|policy)$/.test(rc.type) || !writes(rc) || !rc.after) continue;
      const before = new Set((rc.kind === "create" || !rc.before ? [] : gcpBindings(rc.before)).flatMap((b) => b.members.map((m) => `${b.role}|${m}`)));
      for (const b of gcpBindings(rc.after)) {
        const fresh = b.members.filter((m) => !before.has(`${b.role}|${m}`));
        if (fresh.length === 0) continue;
        const pub = fresh.filter((m) => GCP_PUBLIC.has(m));
        if (pub.length) {
          hits.push({
            severity: "critical",
            address: rc.address,
            resourceType: rc.type,
            message: `\`${rc.address}\` grants \`${b.role}\` to ${pub.join(", ")} (public).`,
            details: [],
          });
          continue;
        }
        const sev = GCP_PRIMITIVE[b.role];
        if (sev) {
          hits.push({
            severity: sev,
            address: rc.address,
            resourceType: rc.type,
            message: `\`${rc.address}\` grants \`${b.role}\` to ${fresh.slice(0, 3).join(", ")}${fresh.length > 3 ? "…" : ""}.`,
            details: [],
          });
        }
      }
    }
    return hits;
  },
};
