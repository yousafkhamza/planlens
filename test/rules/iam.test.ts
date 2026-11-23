import { describe, expect, it } from "vitest";
import { grants, managedPolicySeverity, newStatements, parsePolicy } from "../../src/core/iam.js";
import { analyze, byRule, policy, rc } from "../helpers.js";

describe("policy parsing", () => {
  it("parses strings and objects, single and list statements", () => {
    expect(parsePolicy(policy({ Effect: "Allow", Action: "s3:GetObject", Resource: "*" }))?.[0]?.actions).toEqual(["s3:GetObject"]);
    expect(parsePolicy({ Statement: { Effect: "Deny", Action: ["a:b"], Principal: "*" } })?.[0]?.effect).toBe("Deny");
    expect(parsePolicy("not json")).toBeNull();
    expect(parsePolicy("")).toBeNull();
    expect(parsePolicy(42)).toBeNull();
  });
  it("detects new statements ignoring Sid and ordering", () => {
    const a = { Sid: "One", Effect: "Allow", Action: ["s3:GetObject", "s3:PutObject"], Resource: "*" };
    const b = { Sid: "Renamed", Effect: "Allow", Action: ["s3:PutObject", "s3:GetObject"], Resource: "*" };
    expect(newStatements(policy(a), policy(b))).toHaveLength(0);
    expect(newStatements(policy(a), policy(a, { Effect: "Allow", Action: "iam:*", Resource: "*" }))).toHaveLength(1);
  });
  it("matches actions case-insensitively with wildcards and NotAction", () => {
    const [s] = parsePolicy(policy({ Effect: "Allow", Action: "IAM:Put*", Resource: "*" })) ?? [];
    expect(s && grants(s, "iam:PutRolePolicy")).toBe(true);
    const [n] = parsePolicy(policy({ Effect: "Allow", NotAction: "iam:*", Resource: "*" })) ?? [];
    expect(n && grants(n, "s3:GetObject")).toBe(true);
    expect(n && grants(n, "iam:PassRole")).toBe(false);
  });
  it("normalizes managed policy partitions", () => {
    expect(managedPolicySeverity("arn:aws-us-gov:iam::aws:policy/AdministratorAccess")).toBe("critical");
    expect(managedPolicySeverity("arn:aws:iam::aws:policy/ReadOnlyAccess")).toBeUndefined();
  });
});

describe("PL301–PL303 identity policies", () => {
  it("flags admin, service wildcards and escalation — only for new statements", () => {
    const r = analyze([
      rc("aws_iam_policy.admin", "create", { after: { policy: policy({ Effect: "Allow", Action: "*", Resource: "*" }) } }),
      rc("aws_iam_policy.notaction", "create", { after: { policy: policy({ Effect: "Allow", NotAction: ["iam:*"], Resource: "*" }) } }),
      rc("aws_iam_role_policy.s3", "update", {
        before: { policy: policy({ Effect: "Allow", Action: "s3:GetObject", Resource: "*" }) },
        after: { policy: policy({ Effect: "Allow", Action: "s3:GetObject", Resource: "*" }, { Effect: "Allow", Action: "s3:*", Resource: "*" }) },
      }),
      rc("aws_iam_user_policy.iamstar", "create", { after: { policy: policy({ Effect: "Allow", Action: "iam:*", Resource: "*" }) } }),
      rc("aws_iam_role.inline", "create", {
        after: { inline_policy: [{ policy: policy({ Effect: "Allow", Action: ["iam:PassRole", "iam:CreateAccessKey"], Resource: "*" }) }] },
      }),
      rc("aws_iam_policy.scoped", "create", { after: { policy: policy({ Effect: "Allow", Action: "s3:*", Resource: "arn:aws:s3:::b/*" }) } }),
      rc("aws_iam_policy.passrole_ok", "create", {
        after: {
          policy: policy({
            Effect: "Allow",
            Action: "iam:PassRole",
            Resource: "*",
            Condition: { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } },
          }),
        },
      }),
      rc("aws_iam_policy.unchanged", "update", {
        before: { policy: policy({ Effect: "Allow", Action: "*", Resource: "*" }) },
        after: { policy: policy({ Effect: "Allow", Action: "*", Resource: "*" }) },
      }),
      rc("aws_iam_policy.unknown", "create", { after: { policy: null }, afterUnknown: { policy: true } }),
      rc("aws_iam_policy.deny", "create", { after: { policy: policy({ Effect: "Deny", Action: "*", Resource: "*" }) } }),
    ]);
    expect(byRule(r, "PL301").map((f) => f.address)).toEqual(["aws_iam_policy.admin", "aws_iam_policy.notaction"]);
    expect(byRule(r, "PL302").map((f) => [f.address, f.severity])).toEqual([
      ["aws_iam_user_policy.iamstar", "critical"],
      ["aws_iam_role_policy.s3", "high"],
    ]);
    expect(byRule(r, "PL303").map((f) => f.address)).toEqual(["aws_iam_role.inline"]);
    expect(byRule(r, "PL303")[0]?.message).toMatch(/iam:PassRole.*iam:CreateAccessKey/);
  });
});

describe("PL304 managed policies", () => {
  it("flags newly attached admin policies", () => {
    const r = analyze([
      rc("aws_iam_role_policy_attachment.a", "create", { after: { policy_arn: "arn:aws:iam::aws:policy/AdministratorAccess" } }),
      rc("aws_iam_role.r", "update", {
        before: { managed_policy_arns: ["arn:aws:iam::aws:policy/PowerUserAccess"] },
        after: { managed_policy_arns: ["arn:aws:iam::aws:policy/PowerUserAccess", "arn:aws:iam::aws:policy/AmazonS3FullAccess"] },
      }),
      rc("aws_iam_role_policy_attachment.ro", "create", { after: { policy_arn: "arn:aws:iam::aws:policy/ReadOnlyAccess" } }),
    ]);
    expect(byRule(r, "PL304").map((f) => [f.address, f.severity, f.message])).toEqual([
      ["aws_iam_role_policy_attachment.a", "critical", expect.stringContaining("AdministratorAccess")],
      ["aws_iam_role.r", "high", expect.stringContaining("AmazonS3FullAccess")],
    ]);
  });
});

describe("PL305 resource policies", () => {
  it("flags Principal * without conditions only", () => {
    const pub = { Effect: "Allow", Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*" };
    const r = analyze([
      rc("aws_s3_bucket_policy.pub", "create", { after: { policy: policy(pub) } }),
      rc("aws_sqs_queue_policy.aws_star", "create", {
        after: { policy: policy({ Effect: "Allow", Principal: { AWS: ["*"] }, Action: "sqs:SendMessage", Resource: "*" }) },
      }),
      rc("aws_s3_bucket_policy.cond", "create", { after: { policy: policy({ ...pub, Condition: { StringEquals: { "aws:PrincipalOrgID": "o-123" } } }) } }),
      rc("aws_kms_key.k", "create", {
        after: { policy: policy({ Effect: "Allow", Principal: { AWS: "arn:aws:iam::111122223333:root" }, Action: "kms:*", Resource: "*" }) },
      }),
      rc("aws_s3_bucket_policy.deny", "create", { after: { policy: policy({ ...pub, Effect: "Deny" }) } }),
    ]);
    expect(byRule(r, "PL305").map((f) => f.address)).toEqual(["aws_s3_bucket_policy.pub", "aws_sqs_queue_policy.aws_star"]);
  });
});

describe("PL306/PL307 trust policies", () => {
  const gh = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com";
  const trust = (cond?: Record<string, unknown>, federated = gh) =>
    policy({ Effect: "Allow", Action: "sts:AssumeRoleWithWebIdentity", Principal: { Federated: federated }, ...(cond ? { Condition: cond } : {}) });

  it("flags GitHub OIDC without sub, with wildcard sub, and other OIDC without sub", () => {
    const r = analyze([
      rc("aws_iam_role.nosub", "create", {
        after: { assume_role_policy: trust({ StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" } }) },
      }),
      rc("aws_iam_role.wild", "create", { after: { assume_role_policy: trust({ StringLike: { "token.actions.githubusercontent.com:sub": "repo:*" } }) } }),
      rc("aws_iam_role.good", "create", {
        after: { assume_role_policy: trust({ StringEquals: { "token.actions.githubusercontent.com:sub": "repo:acme/infra:ref:refs/heads/main" } }) },
      }),
      rc("aws_iam_role.eks", "create", {
        after: { assume_role_policy: trust(undefined, "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC") },
      }),
    ]);
    expect(byRule(r, "PL306").map((f) => [f.address, f.severity])).toEqual([
      ["aws_iam_role.nosub", "critical"],
      ["aws_iam_role.wild", "critical"],
      ["aws_iam_role.eks", "high"],
    ]);
    expect(byRule(r, "PL306")[0]?.message).toMatch(/any GitHub repository/);
  });

  it("flags roles assumable by anyone", () => {
    const r = analyze([
      rc("aws_iam_role.open", "create", { after: { assume_role_policy: policy({ Effect: "Allow", Action: "sts:AssumeRole", Principal: { AWS: "*" } }) } }),
      rc("aws_iam_role.cond", "create", {
        after: {
          assume_role_policy: policy({
            Effect: "Allow",
            Action: "sts:AssumeRole",
            Principal: { AWS: "*" },
            Condition: { StringEquals: { "sts:ExternalId": "x" } },
          }),
        },
      }),
      rc("aws_iam_role.svc", "create", {
        after: { assume_role_policy: policy({ Effect: "Allow", Action: "sts:AssumeRole", Principal: { Service: "ec2.amazonaws.com" } }) },
      }),
    ]);
    expect(byRule(r, "PL307").map((f) => [f.address, f.severity])).toEqual([
      ["aws_iam_role.open", "critical"],
      ["aws_iam_role.cond", "medium"],
    ]);
  });
});

describe("PL308–PL311", () => {
  it("access keys and public lambdas", () => {
    const r = analyze([
      rc("aws_iam_access_key.k", "create"),
      rc("aws_lambda_permission.pub", "create", { after: { principal: "*" } }),
      rc("aws_lambda_permission.ok", "create", { after: { principal: "s3.amazonaws.com", source_arn: "arn:aws:s3:::b" } }),
      rc("aws_lambda_function_url.u", "create", { after: { authorization_type: "NONE" } }),
    ]);
    expect(byRule(r, "PL308")).toHaveLength(1);
    expect(byRule(r, "PL309").map((f) => [f.address, f.severity])).toEqual([
      ["aws_lambda_permission.pub", "high"],
      ["aws_lambda_function_url.u", "medium"],
    ]);
  });
  it("Azure privileged role assignments by scope", () => {
    const r = analyze([
      rc("azurerm_role_assignment.sub", "create", { after: { role_definition_name: "Owner", scope: "/subscriptions/0000" } }),
      rc("azurerm_role_assignment.rg", "create", { after: { role_definition_name: "Contributor", scope: "/subscriptions/0000/resourceGroups/rg" } }),
      rc("azurerm_role_assignment.reader", "create", { after: { role_definition_name: "Reader", scope: "/subscriptions/0000" } }),
      rc("azurerm_role_assignment.same", "update", {
        before: { role_definition_name: "Owner", scope: "/subscriptions/0000" },
        after: { role_definition_name: "Owner", scope: "/subscriptions/0000" },
      }),
    ]);
    expect(byRule(r, "PL310").map((f) => [f.address, f.severity])).toEqual([
      ["azurerm_role_assignment.sub", "high"],
      ["azurerm_role_assignment.rg", "medium"],
    ]);
  });
  it("GCP public members, primitive roles and policy documents", () => {
    const r = analyze([
      rc("google_storage_bucket_iam_member.pub", "create", { after: { role: "roles/storage.objectViewer", member: "allUsers" } }),
      rc("google_project_iam_binding.owner", "update", {
        before: { role: "roles/owner", members: ["user:a@x.com"] },
        after: { role: "roles/owner", members: ["user:a@x.com", "user:b@x.com"] },
      }),
      rc("google_project_iam_policy.p", "create", {
        after: { policy_data: JSON.stringify({ bindings: [{ role: "roles/editor", members: ["group:devs@x.com"] }] }) },
      }),
      rc("google_project_iam_member.ok", "create", { after: { role: "roles/viewer", member: "user:c@x.com" } }),
      rc("google_project_iam_policy.bad", "create", { after: { policy_data: "{" } }),
    ]);
    expect(byRule(r, "PL311").map((f) => [f.address, f.severity])).toEqual([
      ["google_storage_bucket_iam_member.pub", "critical"],
      ["google_project_iam_binding.owner", "high"],
      ["google_project_iam_policy.p", "high"],
    ]);
    expect(byRule(r, "PL311")[1]?.message).toContain("user:b@x.com");
    expect(byRule(r, "PL311")[1]?.message).not.toContain("user:a@x.com");
  });
});
