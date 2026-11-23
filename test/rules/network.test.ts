import { describe, expect, it } from "vitest";
import { exposureSeverity, parsePortRange } from "../../src/core/rules/helpers.js";
import { openIngress } from "../../src/core/rules/network.js";
import { analyze, byRule, rc } from "../helpers.js";

describe("port helpers", () => {
  it("parses ranges", () => {
    expect(parsePortRange("22")).toEqual([22, 22]);
    expect(parsePortRange("1000-2000")).toEqual([1000, 2000]);
    expect(parsePortRange("*")).toBeNull();
    expect(parsePortRange("0-65535")).toBeNull();
    expect(parsePortRange("abc")).toBeUndefined();
    expect(parsePortRange(undefined)).toBeUndefined();
  });
  it("rates exposure", () => {
    expect(exposureSeverity([null]).severity).toBe("critical");
    expect(exposureSeverity([[22, 22]]).severity).toBe("critical");
    expect(exposureSeverity([[3000, 4000]]).label).toMatch(/3306 \(MySQL\)/);
    expect(
      exposureSeverity([
        [443, 443],
        [80, 80],
      ]).severity,
    ).toBe("low");
    expect(exposureSeverity([[8443, 8443]]).severity).toBe("high");
  });
});

describe("PL201 internet ingress", () => {
  it("only flags rules introduced by this change", () => {
    const ssh = { from_port: 22, to_port: 22, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"] };
    const web = { from_port: 443, to_port: 443, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"] };
    const r = analyze([
      rc("aws_security_group.a", "update", { before: { ingress: [ssh] }, after: { ingress: [ssh, web] } }),
      rc("aws_security_group.b", "update", { before: { ingress: [web] }, after: { ingress: [web, ssh] } }),
    ]);
    expect(byRule(r, "PL201").map((f) => [f.address, f.severity])).toEqual([
      ["aws_security_group.b", "critical"],
      ["aws_security_group.a", "low"],
    ]);
  });

  it("handles all-protocol, IPv6 and standalone rule resources", () => {
    const r = analyze([
      rc("aws_security_group_rule.all", "create", {
        after: { type: "ingress", protocol: "-1", from_port: 0, to_port: 0, cidr_blocks: [], ipv6_cidr_blocks: ["::/0"] },
      }),
      rc("aws_security_group_rule.egress", "create", { after: { type: "egress", protocol: "-1", from_port: 0, to_port: 0, cidr_blocks: ["0.0.0.0/0"] } }),
      rc("aws_security_group_rule.icmp", "create", { after: { type: "ingress", protocol: "icmp", from_port: -1, to_port: -1, cidr_blocks: ["0.0.0.0/0"] } }),
      rc("aws_security_group_rule.private", "create", { after: { type: "ingress", protocol: "tcp", from_port: 22, to_port: 22, cidr_blocks: ["10.0.0.0/8"] } }),
    ]);
    expect(byRule(r, "PL201").map((f) => [f.address, f.message])).toEqual([["aws_security_group_rule.all", expect.stringMatching(/::\/0 on all ports/)]]);
  });

  it("covers Azure NSGs and GCP firewalls", () => {
    const r = analyze([
      rc("azurerm_network_security_rule.rdp", "create", {
        after: { direction: "Inbound", access: "Allow", protocol: "Tcp", source_address_prefix: "Internet", destination_port_range: "3389" },
      }),
      rc("azurerm_network_security_group.nsg", "create", {
        after: {
          security_rule: [
            { direction: "Inbound", access: "Deny", source_address_prefix: "*", destination_port_range: "*" },
            { direction: "Outbound", access: "Allow", source_address_prefix: "*", destination_port_range: "*" },
            { direction: "Inbound", access: "Allow", source_address_prefixes: ["0.0.0.0/0"], destination_port_ranges: ["8080-8081"], protocol: "Tcp" },
          ],
        },
      }),
      rc("google_compute_firewall.all", "create", { after: { source_ranges: ["0.0.0.0/0"], allow: [{ protocol: "tcp", ports: [] }] } }),
      rc("google_compute_firewall.egress", "create", { after: { direction: "EGRESS", source_ranges: ["0.0.0.0/0"], allow: [{ protocol: "all" }] } }),
      rc("google_compute_firewall.off", "create", { after: { disabled: true, source_ranges: ["0.0.0.0/0"], allow: [{ protocol: "all" }] } }),
      rc("google_compute_firewall.ssh", "create", {
        after: { source_ranges: ["0.0.0.0/0"], allow: [{ protocol: "tcp", ports: ["22"] }, { protocol: "icmp" }] },
      }),
    ]);
    expect(byRule(r, "PL201").map((f) => [f.address, f.severity])).toEqual([
      ["azurerm_network_security_rule.rdp", "critical"],
      ["google_compute_firewall.all", "critical"],
      ["google_compute_firewall.ssh", "critical"],
      ["azurerm_network_security_group.nsg", "high"],
    ]);
  });

  it("openIngress ignores unknown types and null objects", () => {
    expect(openIngress("aws_instance", { a: 1 })).toEqual([]);
    expect(openIngress("aws_security_group", null)).toEqual([]);
  });
});

describe("PL202–PL207", () => {
  it("public databases", () => {
    const r = analyze([
      rc("aws_db_instance.a", "update", { before: { publicly_accessible: false }, after: { publicly_accessible: true } }),
      rc("aws_db_instance.b", "update", { before: { publicly_accessible: true }, after: { publicly_accessible: true } }),
      rc("google_sql_database_instance.g", "create", { after: { settings: [{ ip_configuration: [{ authorized_networks: [{ value: "0.0.0.0/0" }] }] }] } }),
      rc("azurerm_postgresql_flexible_server_firewall_rule.all", "create", { after: { start_ip_address: "0.0.0.0", end_ip_address: "255.255.255.255" } }),
    ]);
    expect(
      byRule(r, "PL202")
        .map((f) => f.address)
        .sort(),
    ).toEqual(["aws_db_instance.a", "azurerm_postgresql_flexible_server_firewall_rule.all", "google_sql_database_instance.g"]);
  });
  it("load balancer becomes internet-facing", () => {
    const r = analyze([rc("aws_lb.alb", "replace", { before: { internal: true }, after: { internal: false } })]);
    expect(byRule(r, "PL203")).toHaveLength(1);
  });
  it("EKS public endpoint", () => {
    const r = analyze([
      rc("aws_eks_cluster.a", "create", { after: { vpc_config: [{ endpoint_public_access: true, public_access_cidrs: ["0.0.0.0/0"] }] } }),
      rc("aws_eks_cluster.b", "create", { after: { vpc_config: [{ endpoint_public_access: true, public_access_cidrs: ["203.0.113.0/24"] }] } }),
      rc("aws_eks_cluster.c", "create", { after: { vpc_config: [{ endpoint_public_access: false }] } }),
    ]);
    expect(byRule(r, "PL204").map((f) => f.address)).toEqual(["aws_eks_cluster.a"]);
  });
  it("S3 public access block weakened or removed", () => {
    const r = analyze([
      rc("aws_s3_bucket_public_access_block.a", "update", {
        before: { block_public_acls: true, block_public_policy: true },
        after: { block_public_acls: true, block_public_policy: false },
      }),
      rc("aws_s3_bucket_public_access_block.b", "delete", { before: { block_public_acls: true } }),
      rc("aws_s3_account_public_access_block.c", "create", {
        after: { block_public_acls: true, block_public_policy: true, ignore_public_acls: true, restrict_public_buckets: true },
      }),
    ]);
    expect(byRule(r, "PL205").map((f) => f.address)).toEqual(["aws_s3_bucket_public_access_block.a", "aws_s3_bucket_public_access_block.b"]);
  });
  it("public storage ACLs", () => {
    const r = analyze([
      rc("aws_s3_bucket_acl.a", "create", { after: { acl: "public-read" } }),
      rc("aws_s3_bucket_acl.b", "create", {
        after: { access_control_policy: [{ grant: [{ grantee: [{ uri: "http://acs.amazonaws.com/groups/global/AllUsers" }] }] }] },
      }),
      rc("azurerm_storage_container.c", "create", { after: { container_access_type: "blob" } }),
      rc("azurerm_storage_container.d", "create", { after: { container_access_type: "private" } }),
    ]);
    expect(byRule(r, "PL206").map((f) => f.address)).toEqual(["aws_s3_bucket_acl.a", "aws_s3_bucket_acl.b", "azurerm_storage_container.c"]);
  });
  it("IMDSv1", () => {
    const r = analyze([
      rc("aws_launch_template.lt", "update", {
        before: { metadata_options: [{ http_tokens: "required" }] },
        after: { metadata_options: [{ http_tokens: "optional" }] },
      }),
      rc("aws_instance.ok", "create", { after: { metadata_options: [{ http_tokens: "required" }] } }),
    ]);
    expect(byRule(r, "PL207").map((f) => f.address)).toEqual(["aws_launch_template.lt"]);
  });
});
