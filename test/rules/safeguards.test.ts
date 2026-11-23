import { describe, expect, it } from "vitest";
import { analyze, byRule, rc } from "../helpers.js";

describe("PL101 deletion protection", () => {
  it("flags true → false and ignores creates and pre-existing state", () => {
    const r = analyze([
      rc("aws_db_instance.a", "update", { before: { deletion_protection: true }, after: { deletion_protection: false } }),
      rc("aws_db_instance.b", "update", { before: { deletion_protection: false }, after: { deletion_protection: false } }),
      rc("aws_db_instance.c", "create", { after: { deletion_protection: false } }),
      rc("aws_lb.d", "update", { before: { enable_deletion_protection: true }, after: { enable_deletion_protection: false } }),
      rc("aws_cognito_user_pool.e", "update", { before: { deletion_protection: "ACTIVE" }, after: { deletion_protection: "INACTIVE" } }),
      rc("aws_instance.f", "update", { before: { disable_api_termination: true }, after: { disable_api_termination: false } }),
    ]);
    expect(byRule(r, "PL101").map((f) => [f.address, f.severity])).toEqual([
      ["aws_cognito_user_pool.e", "high"],
      ["aws_db_instance.a", "high"],
      ["aws_lb.d", "high"],
      ["aws_instance.f", "medium"],
    ]);
  });
  it("skips values that are unknown until apply", () => {
    const r = analyze([
      rc("aws_db_instance.a", "update", {
        before: { deletion_protection: true },
        after: { deletion_protection: null },
        afterUnknown: { deletion_protection: true },
      }),
    ]);
    expect(byRule(r, "PL101")).toHaveLength(0);
  });
});

describe("PL102 final snapshot", () => {
  it("flags skip_final_snapshot switched on", () => {
    const r = analyze([rc("aws_rds_cluster.c", "update", { before: { skip_final_snapshot: false }, after: { skip_final_snapshot: true } })]);
    expect(byRule(r, "PL102")[0]?.severity).toBe("medium");
  });
});

describe("PL103 backups", () => {
  it("flags disabled and reduced retention", () => {
    const r = analyze([
      rc("aws_db_instance.a", "update", { before: { backup_retention_period: 7 }, after: { backup_retention_period: 0 } }),
      rc("aws_db_instance.b", "update", { before: { backup_retention_period: 14 }, after: { backup_retention_period: 1 } }),
      rc("aws_db_instance.c", "create", { after: { backup_retention_period: 0 } }),
      rc("aws_db_instance.d", "update", { before: { backup_retention_period: 1 }, after: { backup_retention_period: 7 } }),
      rc("google_sql_database_instance.g", "update", {
        before: { settings: [{ backup_configuration: [{ enabled: true }] }] },
        after: { settings: [{ backup_configuration: [{ enabled: false }] }] },
      }),
    ]);
    expect(byRule(r, "PL103").map((f) => [f.address, f.severity])).toEqual([
      ["aws_db_instance.a", "high"],
      ["google_sql_database_instance.g", "high"],
      ["aws_db_instance.b", "medium"],
      ["aws_db_instance.c", "medium"],
    ]);
  });
});

describe("PL104 encryption", () => {
  it("flags creates and regressions, nested blocks included", () => {
    const r = analyze([
      rc("aws_db_instance.a", "create", { after: { storage_encrypted: false } }),
      rc("aws_ebs_volume.b", "create", { after: { encrypted: true } }),
      rc("aws_opensearch_domain.c", "update", { before: { encrypt_at_rest: [{ enabled: true }] }, after: { encrypt_at_rest: [{ enabled: false }] } }),
      rc("aws_launch_template.d", "create", { after: { block_device_mappings: [{ ebs: [{ encrypted: "false" }] }] } }),
      rc("azurerm_storage_account.e", "create", { after: { min_tls_version: "TLS1_0", https_traffic_only_enabled: true } }),
    ]);
    expect(byRule(r, "PL104").map((f) => f.address)).toEqual([
      "aws_db_instance.a",
      "aws_opensearch_domain.c",
      "aws_launch_template.d",
      "azurerm_storage_account.e",
    ]);
  });
});

describe("PL105 versioning", () => {
  it("flags suspension and removal of the versioning resource", () => {
    const r = analyze([
      rc("aws_s3_bucket_versioning.a", "update", {
        before: { versioning_configuration: [{ status: "Enabled" }] },
        after: { versioning_configuration: [{ status: "Suspended" }] },
      }),
      rc("aws_s3_bucket_versioning.b", "delete", { before: { versioning_configuration: [{ status: "Enabled" }] } }),
      rc("aws_s3_bucket.c", "update", { before: { versioning: [{ enabled: true }] }, after: { versioning: [{ enabled: false }] } }),
      rc("aws_s3_bucket_versioning.d", "create", { after: { versioning_configuration: [{ status: "Suspended" }] } }),
    ]);
    expect(byRule(r, "PL105").map((f) => f.address)).toEqual(["aws_s3_bucket_versioning.a", "aws_s3_bucket_versioning.b", "aws_s3_bucket.c"]);
  });
});

describe("PL106–PL109", () => {
  it("force destroy: create is low, update is medium", () => {
    const r = analyze([
      rc("aws_s3_bucket.a", "create", { after: { force_destroy: true } }),
      rc("aws_s3_bucket.b", "update", { before: { force_destroy: false }, after: { force_destroy: true } }),
      rc("aws_secretsmanager_secret.c", "update", { before: { recovery_window_in_days: 30 }, after: { recovery_window_in_days: 0 } }),
    ]);
    expect(byRule(r, "PL106").map((f) => f.severity)).toEqual(["medium", "medium", "low"]);
  });
  it("PITR, key rotation and HA", () => {
    const r = analyze([
      rc("aws_dynamodb_table.t", "update", {
        before: { point_in_time_recovery: [{ enabled: true }] },
        after: { point_in_time_recovery: [{ enabled: false }] },
      }),
      rc("aws_kms_key.k", "update", { before: { enable_key_rotation: true }, after: { enable_key_rotation: false } }),
      rc("aws_db_instance.d", "update", { before: { multi_az: true }, after: { multi_az: false } }),
      rc("google_sql_database_instance.g", "update", {
        before: { settings: [{ availability_type: "REGIONAL" }] },
        after: { settings: [{ availability_type: "ZONAL" }] },
      }),
    ]);
    expect(byRule(r, "PL107")).toHaveLength(1);
    expect(byRule(r, "PL108")[0]?.severity).toBe("low");
    expect(byRule(r, "PL109")).toHaveLength(2);
  });
});

describe("PL110 security logging", () => {
  it("flags destroyed controls and disabled toggles", () => {
    const r = analyze([
      rc("aws_cloudtrail.main", "update", { before: { enable_logging: true }, after: { enable_logging: false } }),
      rc("aws_guardduty_detector.d", "delete"),
      rc("aws_flow_log.f", "delete"),
      rc("aws_config_configuration_recorder_status.s", "update", { before: { is_enabled: true }, after: { is_enabled: false } }),
      rc("aws_cloudtrail.other", "update", { before: { enable_logging: true }, after: { enable_logging: true } }),
    ]);
    expect(byRule(r, "PL110").map((f) => [f.address, f.severity])).toEqual([
      ["aws_cloudtrail.main", "high"],
      ["aws_config_configuration_recorder_status.s", "high"],
      ["aws_guardduty_detector.d", "high"],
      ["aws_flow_log.f", "medium"],
    ]);
  });
});

describe("PL111 version upgrades", () => {
  it("flags DB major upgrades with apply hints and any EKS version change", () => {
    const r = analyze([
      rc("aws_db_instance.pg", "update", { before: { engine_version: "14.9" }, after: { engine_version: "16.2", apply_immediately: true } }),
      rc("aws_db_instance.minor", "update", { before: { engine_version: "16.1" }, after: { engine_version: "16.2" } }),
      rc("aws_rds_cluster.mysql", "update", {
        before: { engine_version: "5.7.mysql_aurora.2.11.2" },
        after: { engine_version: "8.0.mysql_aurora.3.05.2", allow_major_version_upgrade: true },
      }),
      rc("aws_eks_cluster.k", "update", { before: { version: "1.29" }, after: { version: "1.30" } }),
      rc("aws_msk_cluster.m", "update", { before: { kafka_version: "2.8.1" }, after: { kafka_version: "3.6.0" } }),
    ]);
    const f = byRule(r, "PL111");
    expect(f.map((x) => x.address)).toEqual(["aws_db_instance.pg", "aws_eks_cluster.k", "aws_msk_cluster.m", "aws_rds_cluster.mysql"]);
    const pg = f.find((x) => x.address === "aws_db_instance.pg");
    expect(pg?.details.join(" ")).toMatch(/allow_major_version_upgrade/);
    expect(pg?.details.join(" ")).toMatch(/apply_immediately/);
    expect(f.find((x) => x.address === "aws_rds_cluster.mysql")?.details).toEqual([]);
  });
});

describe("PL112 scaled to zero", () => {
  it("flags capacity going to zero", () => {
    const r = analyze([
      rc("aws_eks_node_group.ng", "update", {
        before: { scaling_config: [{ desired_size: 3, max_size: 5 }] },
        after: { scaling_config: [{ desired_size: 0, max_size: 5 }] },
      }),
      rc("aws_ecs_service.s", "update", { before: { desired_count: 2 }, after: { desired_count: 1 } }),
    ]);
    expect(byRule(r, "PL112").map((f) => f.address)).toEqual(["aws_eks_node_group.ng"]);
  });
});
