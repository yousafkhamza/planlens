import { managedChanges } from "../plan.js";
import type { ResourceChange, Rule, Severity } from "../types.js";
import { anyGlob } from "../util.js";
import { display, type Hit, isUnknown, v, writes } from "./helpers.js";

type Pred = (value: unknown) => boolean;

interface Guard {
  types: string[];
  path: string;
  /** Returns true when the value is the unsafe state. */
  bad: Pred;
  /** Severity when an existing resource flips from safe to unsafe. */
  onUpdate: Severity;
  /** Severity when a new resource is created in the unsafe state; null = do not report creates. */
  onCreate: Severity | null;
  label: string;
}

const isFalse: Pred = (x) => x === false || x === "false";
const isTrue: Pred = (x) => x === true || x === "true";

/**
 * Evaluate a guard against one change. Returns a hit when the PR introduces the
 * unsafe state (create in unsafe state, or safe → unsafe on update/replace).
 */
function evalGuard(rc: ResourceChange, g: Guard): Hit | undefined {
  if (!writes(rc) || !anyGlob(g.types, rc.type)) return undefined;
  if (isUnknown(rc, g.path)) return undefined;
  const after = v(rc, "after", g.path);
  if (after === undefined || after === null || !g.bad(after)) return undefined;
  if (rc.kind === "create") {
    if (!g.onCreate) return undefined;
    return {
      severity: g.onCreate,
      address: rc.address,
      resourceType: rc.type,
      message: `\`${rc.address}\` is created with ${g.label} (\`${g.path} = ${display(rc, "after", g.path)}\`).`,
      details: [],
    };
  }
  const before = v(rc, "before", g.path);
  if (before !== undefined && before !== null && g.bad(before)) return undefined; // pre-existing
  return {
    severity: g.onUpdate,
    address: rc.address,
    resourceType: rc.type,
    message: `\`${rc.address}\`: ${g.label} (\`${g.path}\`: ${display(rc, "before", g.path)} → ${display(rc, "after", g.path)}).`,
    details: [],
  };
}

function guardRule(meta: Omit<Rule, "run">, guards: Guard[]): Rule {
  return {
    ...meta,
    run({ plan }) {
      const hits: Hit[] = [];
      for (const rc of managedChanges(plan)) {
        for (const g of guards) {
          const h = evalGuard(rc, g);
          if (h) {
            hits.push(h);
            break;
          }
        }
      }
      return hits;
    },
  };
}

export const deletionProtection = guardRule(
  {
    id: "PL101",
    title: "Deletion protection disabled",
    severity: "high",
    category: "data-loss",
    description: "Deletion/termination protection is turned off on an existing resource — usually the first step before an accidental destroy.",
    remediation: "Keep deletion protection on in production. If you really need to destroy the resource, disable protection in a separate, reviewed change.",
  },
  [
    {
      types: ["aws_db_instance", "aws_rds_cluster", "aws_docdb_cluster", "aws_neptune_cluster", "aws_qldb_ledger"],
      path: "deletion_protection",
      bad: isFalse,
      onUpdate: "high",
      onCreate: null,
      label: "deletion protection disabled",
    },
    {
      types: ["aws_dynamodb_table"],
      path: "deletion_protection_enabled",
      bad: isFalse,
      onUpdate: "high",
      onCreate: null,
      label: "deletion protection disabled",
    },
    { types: ["aws_lb", "aws_alb"], path: "enable_deletion_protection", bad: isFalse, onUpdate: "high", onCreate: null, label: "deletion protection disabled" },
    { types: ["aws_instance"], path: "disable_api_termination", bad: isFalse, onUpdate: "medium", onCreate: null, label: "termination protection disabled" },
    {
      types: ["aws_cognito_user_pool"],
      path: "deletion_protection",
      bad: (x) => x === "INACTIVE",
      onUpdate: "high",
      onCreate: null,
      label: "deletion protection disabled",
    },
    {
      types: ["google_sql_database_instance", "google_container_cluster", "google_bigquery_table", "google_compute_instance", "google_alloydb_cluster"],
      path: "deletion_protection",
      bad: isFalse,
      onUpdate: "high",
      onCreate: null,
      label: "deletion protection disabled",
    },
  ],
);

export const finalSnapshot = guardRule(
  {
    id: "PL102",
    title: "Final snapshot disabled on database",
    severity: "medium",
    category: "data-loss",
    description: "`skip_final_snapshot` is switched on, so destroying the database later will not leave a snapshot behind.",
    remediation: "Keep `skip_final_snapshot = false` and set `final_snapshot_identifier` for production databases.",
  },
  [
    {
      types: ["aws_db_instance", "aws_rds_cluster", "aws_docdb_cluster", "aws_neptune_cluster", "aws_redshift_cluster"],
      path: "skip_final_snapshot",
      bad: isTrue,
      onUpdate: "medium",
      onCreate: null,
      label: "final snapshot will be skipped on destroy",
    },
  ],
);

export const backups: Rule = {
  id: "PL103",
  title: "Backups disabled or retention reduced",
  severity: "high",
  category: "data-loss",
  description: "Automated backups are turned off or their retention is shortened.",
  remediation: "Keep automated backups enabled with a retention that meets your RPO/compliance requirements (commonly ≥ 7 days in production).",
  run({ plan }) {
    const hits: Hit[] = [];
    const specs: Array<{ types: string[]; path: string }> = [
      { types: ["aws_db_instance", "aws_rds_cluster", "aws_docdb_cluster", "aws_neptune_cluster"], path: "backup_retention_period" },
      { types: ["aws_elasticache_replication_group", "aws_elasticache_cluster"], path: "snapshot_retention_limit" },
      { types: ["azurerm_postgresql_flexible_server", "azurerm_mysql_flexible_server"], path: "backup_retention_days" },
    ];
    for (const rc of managedChanges(plan)) {
      if (!writes(rc)) continue;
      for (const s of specs) {
        if (!s.types.includes(rc.type) || isUnknown(rc, s.path)) continue;
        const after = Number(v(rc, "after", s.path));
        const beforeRaw = v(rc, "before", s.path);
        const before = beforeRaw === undefined || beforeRaw === null ? undefined : Number(beforeRaw);
        if (Number.isNaN(after)) continue;
        if (rc.kind === "create") {
          if (after === 0 && rc.type === "aws_db_instance") {
            hits.push({
              severity: "medium",
              address: rc.address,
              resourceType: rc.type,
              message: `\`${rc.address}\` is created with automated backups disabled (\`${s.path} = 0\`).`,
              details: [],
            });
          }
        } else if (before !== undefined && after < before) {
          hits.push({
            severity: after === 0 ? "high" : "medium",
            address: rc.address,
            resourceType: rc.type,
            message:
              after === 0
                ? `\`${rc.address}\`: automated backups disabled (\`${s.path}\`: ${before} → 0).`
                : `\`${rc.address}\`: backup retention reduced (\`${s.path}\`: ${before} → ${after}).`,
            details: [],
          });
        }
      }
      if (rc.type === "google_sql_database_instance") {
        const b = v(rc, "before", "settings.backup_configuration.enabled");
        const a = v(rc, "after", "settings.backup_configuration.enabled");
        if (a === false && (b === true || rc.kind === "create")) {
          hits.push({
            severity: rc.kind === "create" ? "medium" : "high",
            address: rc.address,
            resourceType: rc.type,
            message: `\`${rc.address}\`: automated backups disabled.`,
            details: [],
          });
        }
      }
    }
    return hits;
  },
};

export const encryption = guardRule(
  {
    id: "PL104",
    title: "Encryption disabled",
    severity: "high",
    category: "security",
    description: "Encryption at rest or in transit is off. For most storage services this cannot be enabled later without replacing the resource.",
    remediation: "Enable encryption (ideally with a customer-managed KMS key). Required by PCI DSS 3.5, ISO 27001 A.8.24 and most internal baselines.",
  },
  [
    {
      types: ["aws_db_instance", "aws_rds_cluster", "aws_docdb_cluster", "aws_neptune_cluster"],
      path: "storage_encrypted",
      bad: isFalse,
      onUpdate: "high",
      onCreate: "high",
      label: "storage encryption disabled",
    },
    {
      types: ["aws_ebs_volume", "aws_efs_file_system", "aws_redshift_cluster"],
      path: "encrypted",
      bad: isFalse,
      onUpdate: "high",
      onCreate: "high",
      label: "encryption disabled",
    },
    { types: ["aws_instance"], path: "root_block_device.encrypted", bad: isFalse, onUpdate: "medium", onCreate: "medium", label: "unencrypted root volume" },
    {
      types: ["aws_launch_template"],
      path: "block_device_mappings.ebs.encrypted",
      bad: isFalse,
      onUpdate: "medium",
      onCreate: "medium",
      label: "unencrypted EBS volumes",
    },
    {
      types: ["aws_elasticache_replication_group"],
      path: "at_rest_encryption_enabled",
      bad: isFalse,
      onUpdate: "high",
      onCreate: "medium",
      label: "at-rest encryption disabled",
    },
    {
      types: ["aws_elasticache_replication_group"],
      path: "transit_encryption_enabled",
      bad: isFalse,
      onUpdate: "high",
      onCreate: "medium",
      label: "in-transit encryption disabled",
    },
    {
      types: ["aws_opensearch_domain", "aws_elasticsearch_domain"],
      path: "encrypt_at_rest.enabled",
      bad: isFalse,
      onUpdate: "high",
      onCreate: "high",
      label: "encryption at rest disabled",
    },
    {
      types: ["aws_opensearch_domain", "aws_elasticsearch_domain"],
      path: "node_to_node_encryption.enabled",
      bad: isFalse,
      onUpdate: "high",
      onCreate: "medium",
      label: "node-to-node encryption disabled",
    },
    {
      types: ["aws_opensearch_domain", "aws_elasticsearch_domain"],
      path: "domain_endpoint_options.enforce_https",
      bad: isFalse,
      onUpdate: "high",
      onCreate: "medium",
      label: "HTTPS not enforced",
    },
    {
      types: ["azurerm_storage_account"],
      path: "https_traffic_only_enabled",
      bad: isFalse,
      onUpdate: "high",
      onCreate: "high",
      label: "HTTP (non-TLS) traffic allowed",
    },
    {
      types: ["azurerm_storage_account"],
      path: "enable_https_traffic_only",
      bad: isFalse,
      onUpdate: "high",
      onCreate: "high",
      label: "HTTP (non-TLS) traffic allowed",
    },
    {
      types: ["azurerm_storage_account", "azurerm_mssql_server", "azurerm_redis_cache"],
      path: "min_tls_version",
      bad: (x) => x === "TLS1_0" || x === "TLS1_1" || x === "1.0" || x === "1.1",
      onUpdate: "medium",
      onCreate: "medium",
      label: "legacy TLS allowed",
    },
  ],
);

export const versioning: Rule = {
  id: "PL105",
  title: "S3 versioning suspended",
  severity: "medium",
  category: "data-loss",
  description: "Object versioning protects against accidental overwrites and deletes (and is required for replication and Object Lock).",
  remediation: "Keep versioning enabled on buckets that hold important data; use lifecycle rules to expire old versions instead of suspending versioning.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (rc.type === "aws_s3_bucket_versioning") {
        if (rc.kind === "delete" && v(rc, "before", "versioning_configuration.status") === "Enabled") {
          hits.push({
            severity: "medium",
            address: rc.address,
            resourceType: rc.type,
            message: `\`${rc.address}\` is destroyed — the AWS provider suspends versioning on the bucket when this resource is removed.`,
            details: [],
          });
          continue;
        }
        const a = v(rc, "after", "versioning_configuration.status");
        const b = v(rc, "before", "versioning_configuration.status");
        if ((a === "Suspended" || a === "Disabled") && rc.kind !== "create" && b === "Enabled") {
          hits.push({
            severity: "medium",
            address: rc.address,
            resourceType: rc.type,
            message: `\`${rc.address}\`: versioning ${b} → ${String(a)}.`,
            details: [],
          });
        }
      }
      if (rc.type === "aws_s3_bucket" && rc.kind === "update") {
        if (v(rc, "before", "versioning.enabled") === true && v(rc, "after", "versioning.enabled") === false) {
          hits.push({ severity: "medium", address: rc.address, resourceType: rc.type, message: `\`${rc.address}\`: versioning disabled.`, details: [] });
        }
      }
    }
    return hits;
  },
};

export const forceDestroy = guardRule(
  {
    id: "PL106",
    title: "Force-destroy / immediate deletion enabled",
    severity: "medium",
    category: "data-loss",
    description: "Lets Terraform delete a non-empty bucket/repository/zone, or deletes a secret without a recovery window.",
    remediation: "Only enable force-destroy on ephemeral (dev/test) resources. Keep a recovery window on secrets.",
  },
  [
    {
      types: ["aws_s3_bucket", "google_storage_bucket", "aws_route53_zone"],
      path: "force_destroy",
      bad: isTrue,
      onUpdate: "medium",
      onCreate: "low",
      label: "force_destroy enabled — non-empty contents will be deleted with it",
    },
    {
      types: ["aws_ecr_repository"],
      path: "force_delete",
      bad: isTrue,
      onUpdate: "medium",
      onCreate: "low",
      label: "force_delete enabled — images will be deleted with it",
    },
    {
      types: ["aws_secretsmanager_secret"],
      path: "recovery_window_in_days",
      bad: (x) => x === 0 || x === "0",
      onUpdate: "medium",
      onCreate: "low",
      label: "no recovery window — deletion is immediate and irreversible",
    },
  ],
);

export const pitr = guardRule(
  {
    id: "PL107",
    title: "Point-in-time recovery disabled",
    severity: "medium",
    category: "data-loss",
    description: "DynamoDB point-in-time recovery is switched off.",
    remediation: "Keep PITR enabled on production tables.",
  },
  [
    {
      types: ["aws_dynamodb_table"],
      path: "point_in_time_recovery.enabled",
      bad: isFalse,
      onUpdate: "medium",
      onCreate: null,
      label: "point-in-time recovery disabled",
    },
  ],
);

export const keyRotation = guardRule(
  {
    id: "PL108",
    title: "KMS key rotation disabled",
    severity: "low",
    category: "security",
    description: "Automatic key rotation is switched off on a KMS key.",
    remediation: "Enable `enable_key_rotation` on customer-managed symmetric keys.",
  },
  [{ types: ["aws_kms_key"], path: "enable_key_rotation", bad: isFalse, onUpdate: "low", onCreate: null, label: "automatic key rotation disabled" }],
);

export const multiAz = guardRule(
  {
    id: "PL109",
    title: "High availability reduced",
    severity: "medium",
    category: "availability",
    description: "Multi-AZ / automatic failover / regional availability is turned off.",
    remediation: "Keep production databases and caches Multi-AZ.",
  },
  [
    { types: ["aws_db_instance"], path: "multi_az", bad: isFalse, onUpdate: "medium", onCreate: null, label: "Multi-AZ disabled" },
    {
      types: ["aws_elasticache_replication_group"],
      path: "automatic_failover_enabled",
      bad: isFalse,
      onUpdate: "medium",
      onCreate: null,
      label: "automatic failover disabled",
    },
    { types: ["aws_elasticache_replication_group"], path: "multi_az_enabled", bad: isFalse, onUpdate: "medium", onCreate: null, label: "Multi-AZ disabled" },
    {
      types: ["google_sql_database_instance"],
      path: "settings.availability_type",
      bad: (x) => x === "ZONAL",
      onUpdate: "medium",
      onCreate: null,
      label: "regional HA disabled",
    },
  ],
);

export const securityLogging: Rule = {
  id: "PL110",
  title: "Security monitoring or logging removed",
  severity: "high",
  category: "security",
  description:
    "An audit/detection control (CloudTrail, GuardDuty, AWS Config, Security Hub, VPC Flow Logs, WAF association, diagnostic settings) is disabled or destroyed.",
  remediation: "Security controls should only be removed through an explicit, approved change. Required by ISO 27001 A.8.15/A.8.16, PCI DSS 10 and SOC 2 CC7.",
  run({ plan }) {
    const hits: Hit[] = [];
    const destroyedTypes: Record<string, Severity> = {
      aws_cloudtrail: "high",
      aws_guardduty_detector: "high",
      aws_config_configuration_recorder: "high",
      aws_securityhub_account: "high",
      aws_wafv2_web_acl_association: "high",
      aws_flow_log: "medium",
      aws_macie2_account: "medium",
      aws_inspector2_enabler: "medium",
      azurerm_monitor_diagnostic_setting: "medium",
      azurerm_security_center_subscription_pricing: "medium",
      google_logging_project_sink: "medium",
    };
    const toggles: Array<{ type: string; path: string; label: string }> = [
      { type: "aws_cloudtrail", path: "enable_logging", label: "CloudTrail logging stopped" },
      { type: "aws_cloudtrail", path: "is_multi_region_trail", label: "CloudTrail no longer multi-region" },
      { type: "aws_guardduty_detector", path: "enable", label: "GuardDuty detector disabled" },
      { type: "aws_config_configuration_recorder_status", path: "is_enabled", label: "AWS Config recorder stopped" },
    ];
    for (const rc of managedChanges(plan)) {
      const sev = destroyedTypes[rc.type];
      if (sev && rc.kind === "delete") {
        hits.push({ severity: sev, address: rc.address, resourceType: rc.type, message: `\`${rc.address}\` (${rc.type}) will be destroyed.`, details: [] });
        continue;
      }
      if (rc.kind !== "update" && rc.kind !== "replace") continue;
      for (const t of toggles) {
        if (rc.type === t.type && v(rc, "before", t.path) === true && v(rc, "after", t.path) === false) {
          hits.push({ severity: "high", address: rc.address, resourceType: rc.type, message: `\`${rc.address}\`: ${t.label}.`, details: [] });
        }
      }
    }
    return hits;
  },
};

function majorOf(version: string): string {
  const parts = version.split(".");
  // MySQL 5.7 → 8.0 and MariaDB 10.x → 11.x use the first component; Postgres 9.6 used two.
  if (parts[0] === "5" || parts[0] === "9") return parts.slice(0, 2).join(".");
  return parts[0] ?? version;
}

export const versionUpgrade: Rule = {
  id: "PL111",
  title: "Major engine or cluster version upgrade",
  severity: "medium",
  category: "availability",
  description:
    "A database major version or Kubernetes control-plane version changes. These upgrades are one-way, can take minutes of downtime, and may break clients.",
  remediation:
    "Test the upgrade on a snapshot/staging first, check deprecated APIs/extensions/parameter groups, and schedule a maintenance window. Kubernetes can only move one minor version at a time.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (rc.kind !== "update" && rc.kind !== "replace") continue;
      const dbTypes = [
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_elasticache_replication_group",
        "aws_elasticache_cluster",
        "aws_docdb_cluster",
        "aws_opensearch_domain",
        "aws_msk_cluster",
      ];
      const k8s: Record<string, string> = {
        aws_eks_cluster: "version",
        azurerm_kubernetes_cluster: "kubernetes_version",
        google_container_cluster: "min_master_version",
      };
      const path = dbTypes.includes(rc.type) ? (rc.type === "aws_msk_cluster" ? "kafka_version" : "engine_version") : k8s[rc.type];
      if (!path) continue;
      const b = v(rc, "before", path);
      const a = v(rc, "after", path);
      if (typeof b !== "string" || typeof a !== "string" || a === b || a === "") continue;
      const isK8s = path !== "engine_version" && path !== "kafka_version";
      if (!isK8s && majorOf(a) === majorOf(b)) continue;
      const details: string[] = [];
      if (rc.type === "aws_db_instance" || rc.type === "aws_rds_cluster") {
        if (v(rc, "after", "allow_major_version_upgrade") !== true) details.push("`allow_major_version_upgrade` is not true — the apply will fail.");
        if (v(rc, "after", "apply_immediately") === true)
          details.push("`apply_immediately = true` — the upgrade happens during apply, not in the maintenance window.");
      }
      hits.push({
        severity: "medium",
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\`: ${isK8s ? "Kubernetes version" : "major version"} upgrade ${b} → ${a}.`,
        details,
      });
    }
    return hits;
  },
};

export const scaledToZero: Rule = {
  id: "PL112",
  title: "Capacity scaled to zero",
  severity: "medium",
  category: "availability",
  description: "An Auto Scaling group, node group or service is scaled down to zero.",
  remediation: "Make sure nothing is still serving traffic from this capacity.",
  run({ plan }) {
    const hits: Hit[] = [];
    const specs: Array<{ type: string; path: string }> = [
      { type: "aws_autoscaling_group", path: "desired_capacity" },
      { type: "aws_autoscaling_group", path: "max_size" },
      { type: "aws_eks_node_group", path: "scaling_config.desired_size" },
      { type: "aws_eks_node_group", path: "scaling_config.max_size" },
      { type: "aws_ecs_service", path: "desired_count" },
      { type: "azurerm_kubernetes_cluster_node_pool", path: "node_count" },
      { type: "google_container_node_pool", path: "node_count" },
    ];
    for (const rc of managedChanges(plan)) {
      if (rc.kind !== "update") continue;
      for (const s of specs) {
        if (rc.type !== s.type) continue;
        const b = Number(v(rc, "before", s.path));
        const a = v(rc, "after", s.path);
        if (b > 0 && (a === 0 || a === "0")) {
          hits.push({ severity: "medium", address: rc.address, resourceType: rc.type, message: `\`${rc.address}\`: \`${s.path}\` ${b} → 0.`, details: [] });
          break;
        }
      }
    }
    return hits;
  },
};
