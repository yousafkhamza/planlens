// Writes docs/samples/prod-change.json — a realistic "Friday afternoon" prod
// change with updates/replaces (things a create-only real fixture cannot show).
// Shapes follow the AWS provider schema as rendered by `terraform show -json`.
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const AWS = "registry.terraform.io/hashicorp/aws";

const rc = (address, type, name, actions, before, after, extra = {}) => ({
  address,
  module_address: address.startsWith("module.") ? address.split(".").slice(0, 2).join(".") : undefined,
  mode: "managed",
  type,
  name,
  provider_name: AWS,
  ...extra.top,
  change: {
    actions,
    before,
    after,
    after_unknown: extra.unknown ?? {},
    before_sensitive: extra.beforeSensitive ?? (before ? {} : false),
    after_sensitive: extra.afterSensitive ?? (after ? {} : false),
    ...(extra.replace ? { replace_paths: extra.replace } : {}),
  },
  ...(extra.reason ? { action_reason: extra.reason } : {}),
});

const trust = (cond) =>
  JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: "sts:AssumeRoleWithWebIdentity",
        Principal: { Federated: "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" },
        Condition: cond,
      },
    ],
  });

const dbBefore = {
  identifier: "payments-prod",
  engine: "postgres",
  engine_version: "15.7",
  instance_class: "db.r6g.xlarge",
  storage_encrypted: false,
  deletion_protection: true,
  skip_final_snapshot: true,
  backup_retention_period: 14,
  multi_az: true,
  password: "redacted-in-real-plans-too",
  id: "db-ABC123",
};

const plan = {
  format_version: "1.2",
  terraform_version: "1.9.8",
  resource_changes: [
    rc(
      "module.data.aws_db_instance.payments",
      "aws_db_instance",
      "payments",
      ["delete", "create"],
      dbBefore,
      { ...dbBefore, engine_version: "16.3", storage_encrypted: true, deletion_protection: false, backup_retention_period: 1, id: null },
      {
        replace: [["storage_encrypted"]],
        reason: "replace_because_cannot_update",
        unknown: { id: true, arn: true, endpoint: true },
        beforeSensitive: { password: true },
        afterSensitive: { password: true },
      },
    ),
    rc(
      "module.network.aws_subnet.private[1]",
      "aws_subnet",
      "private",
      ["delete", "create"],
      { cidr_block: "10.0.2.0/24", availability_zone: "eu-west-1b", id: "subnet-2" },
      { cidr_block: "10.0.3.0/24", availability_zone: "eu-west-1c", id: null },
      { top: { index: 1 }, replace: [["cidr_block"], ["availability_zone"]], reason: "replace_because_cannot_update", unknown: { id: true } },
    ),
    rc(
      "module.network.aws_subnet.private[2]",
      "aws_subnet",
      "private",
      ["delete"],
      { cidr_block: "10.0.3.0/24", availability_zone: "eu-west-1c", id: "subnet-3" },
      null,
      { top: { index: 2 }, reason: "delete_because_count_index" },
    ),
    rc(
      "aws_security_group.api",
      "aws_security_group",
      "api",
      ["update"],
      { name: "api", ingress: [{ from_port: 443, to_port: 443, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"] }] },
      {
        name: "api",
        ingress: [
          { from_port: 443, to_port: 443, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"] },
          { from_port: 5432, to_port: 5432, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"], description: "temp debug" },
        ],
      },
    ),
    rc(
      "aws_iam_role.github_deploy",
      "aws_iam_role",
      "github_deploy",
      ["update"],
      {
        name: "github-deploy",
        assume_role_policy: trust({ StringEquals: { "token.actions.githubusercontent.com:sub": "repo:acme/infra:ref:refs/heads/main" } }),
      },
      { name: "github-deploy", assume_role_policy: trust({ StringLike: { "token.actions.githubusercontent.com:sub": "repo:*" } }) },
    ),
    rc(
      "aws_cloudtrail.org",
      "aws_cloudtrail",
      "org",
      ["update"],
      { name: "org-trail", enable_logging: true, is_multi_region_trail: true },
      { name: "org-trail", enable_logging: false, is_multi_region_trail: true },
    ),
    rc("aws_eks_cluster.main", "aws_eks_cluster", "main", ["update"], { name: "main", version: "1.30" }, { name: "main", version: "1.31" }),
    rc("aws_s3_bucket.reports_old", "aws_s3_bucket", "reports_old", ["delete"], { bucket: "acme-reports", force_destroy: false, id: "acme-reports" }, null, {
      reason: "delete_because_no_resource_config",
    }),
    rc(
      "module.storage.aws_s3_bucket.reports",
      "aws_s3_bucket",
      "reports",
      ["create"],
      null,
      { bucket: "acme-reports", force_destroy: false, id: null },
      { unknown: { id: true, arn: true } },
    ),
    rc(
      "aws_ecs_service.worker",
      "aws_ecs_service",
      "worker",
      ["update"],
      { name: "worker", desired_count: 3 },
      { name: "worker", desired_count: 3, task_definition: null },
      { unknown: { task_definition: true } },
    ),
  ],
  output_changes: {
    db_endpoint: {
      actions: ["update"],
      before: "payments-prod.abc.eu-west-1.rds.amazonaws.com:5432",
      after: null,
      after_unknown: true,
      before_sensitive: false,
      after_sensitive: false,
    },
  },
  applyable: true,
  complete: true,
  errored: false,
};

mkdirSync(`${root}/docs/samples`, { recursive: true });
writeFileSync(`${root}/docs/samples/prod-change.json`, `${JSON.stringify(plan, null, 2)}\n`);
for (const n of ["aws-create", "lifecycle", "noop"]) copyFileSync(`${root}/test/fixtures/real/${n}.json`, `${root}/docs/samples/${n}.json`);
console.log("samples written");
