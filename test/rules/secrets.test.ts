import { describe, expect, it } from "vitest";
import { findTokens, looksLikeLiteralSecret, looksLikeSecretKey } from "../../src/core/rules/secrets.js";
import { analyze, byRule, rc } from "../helpers.js";

describe("heuristics", () => {
  it("secret-looking keys", () => {
    for (const k of ["DB_PASSWORD", "api_key", "STRIPE_SECRET", "GITHUB_TOKEN", "client_secret", "DATABASE_CONNECTION_STRING"])
      expect(looksLikeSecretKey(k)).toBe(true);
    for (const k of ["DB_SECRET_ARN", "TOKEN_URL", "PASSWORD_PARAM", "LOG_LEVEL", "KMS_KEY_ID", "SECRET_NAME"]) expect(looksLikeSecretKey(k)).toBe(false);
  });
  it("literal vs reference values", () => {
    expect(looksLikeLiteralSecret("hunter2-real")).toBe(true);
    // biome-ignore lint/suspicious/noTemplateCurlyInString: literal Terraform interpolation syntax under test
    for (const v of ["arn:aws:secretsmanager:x", "${var.x}", "/prod/db/password", "{{resolve:ssm:/x}}", "true", "12345", "short", 42]) {
      expect(looksLikeLiteralSecret(v)).toBe(false);
    }
  });
  it("token patterns", () => {
    expect(findTokens("AKIAIOSFODNN7EXAMPLE").map((t) => t.name)).toEqual(["AWS access key ID"]);
    expect(findTokens("-----BEGIN RSA PRIVATE KEY-----\nabc").map((t) => t.name)).toEqual(["private key"]);
    expect(findTokens(`ghp_${"a".repeat(36)}`).map((t) => t.name)).toEqual(["GitHub token"]);
    expect(findTokens("nothing to see")).toEqual([]);
  });
});

describe("PL401 plaintext secrets", () => {
  it("finds tokens in attributes, decoded user_data, env vars, ECS definitions and app settings", () => {
    const userData = Buffer.from("#!/bin/bash\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n").toString("base64");
    const containers = JSON.stringify([
      {
        name: "app",
        environment: [
          { name: "DB_PASSWORD", value: "s3cr3t-value" },
          { name: "PORT", value: "8080" },
        ],
      },
    ]);
    const r = analyze([
      rc("aws_launch_template.lt", "create", { after: { user_data: userData } }),
      rc("aws_lambda_function.fn", "create", {
        after: { environment: [{ variables: { API_KEY: "abcdef123456", LOG_LEVEL: "debug", SECRET_ARN: "arn:aws:x" } }] },
      }),
      rc("aws_ecs_task_definition.td", "create", { after: { container_definitions: containers } }),
      rc("azurerm_linux_web_app.app", "create", { after: { app_settings: { CLIENT_SECRET: "plain-text-value" } } }),
      rc("kubernetes_deployment_v1.d", "create", {
        after: { spec: [{ template: [{ spec: [{ container: [{ env: [{ name: "REDIS_PASSWORD", value: "redispass1" }] }] }] }] }] },
      }),
      rc("google_cloud_run_v2_service.s", "create", { after: { template: [{ containers: [{ env: [{ name: "JWT_SECRET", value: "jwt-secret-1" }] }] }] } }),
    ]);
    const msgs = byRule(r, "PL401").map((f) => `${f.address}: ${f.message}`);
    expect(msgs).toHaveLength(6);
    expect(msgs.join("\n")).toMatch(/aws_launch_template.lt.*AWS access key ID/);
    expect(msgs.join("\n")).toMatch(/API_KEY/);
    expect(msgs.join("\n")).not.toMatch(/LOG_LEVEL|SECRET_ARN|PORT/);
    expect(msgs.join("\n")).toMatch(/DB_PASSWORD.*container "app"/);
    expect(msgs.join("\n")).not.toContain("s3cr3t-value");
  });

  it("ignores sensitive values, unchanged values and SecureString parameters", () => {
    const r = analyze([
      rc("aws_lambda_function.sens", "create", { after: { environment: [{ variables: { API_KEY: "abcdef123456" } }] }, afterSensitive: { environment: true } }),
      rc("aws_lambda_function.same", "update", {
        before: { environment: [{ variables: { API_KEY: "abcdef123456" } }] },
        after: { environment: [{ variables: { API_KEY: "abcdef123456" } }], memory_size: 256 },
      }),
      rc("aws_ssm_parameter.ok", "create", { after: { name: "/app/db_password", type: "SecureString" } }),
      rc("aws_ssm_parameter.bad", "create", { after: { name: "/app/db_password", type: "String" } }),
      rc("aws_ecs_task_definition.unknown", "create", { after: { container_definitions: null }, afterUnknown: { container_definitions: true } }),
      rc("aws_ecs_task_definition.invalid", "create", { after: { container_definitions: "{" } }),
    ]);
    expect(byRule(r, "PL401").map((f) => [f.address, f.severity])).toEqual([["aws_ssm_parameter.bad", "medium"]]);
  });
});

describe("PL402 outputs", () => {
  it("flags non-sensitive secret outputs", () => {
    const r = analyze(
      [],
      {},
      {
        output_changes: {
          db_password: { actions: ["create"], after: "hunter2-xyz", after_sensitive: false },
          api_token: { actions: ["update"], before: "a", after: null, after_unknown: true, after_sensitive: false },
          key_material: { actions: ["create"], after: { pem: "-----BEGIN PRIVATE KEY-----" }, after_sensitive: false },
          hidden_secret: { actions: ["create"], after: "x", after_sensitive: true },
          vpc_id: { actions: ["create"], after: "vpc-123", after_sensitive: false },
          old_secret: { actions: ["no-op"], before: "s3cret-old", after: "s3cret-old", after_sensitive: false },
        },
      },
    );
    expect(byRule(r, "PL402").map((f) => [f.address, f.severity])).toEqual([
      ["output.key_material", "critical"],
      ["output.api_token", "high"],
      ["output.db_password", "high"],
    ]);
  });
});
