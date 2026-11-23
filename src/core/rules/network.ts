import { OPEN_CIDRS } from "../catalog.js";
import { managedChanges } from "../plan.js";
import type { Rule } from "../types.js";
import { asArray, getAll, isRecord } from "../util.js";
import { exposureSeverity, type Hit, introduced, type PortRange, parsePortRange, v, writes } from "./helpers.js";

interface OpenRule {
  key: string;
  range: PortRange | null;
  source: string;
}

const ICMP = new Set(["icmp", "icmpv6", "1", "58"]);
const ALL_PROTO = new Set(["-1", "all", "*"]);

function awsRange(proto: unknown, from: unknown, to: unknown): PortRange | null | undefined {
  const p = String(proto ?? "").toLowerCase();
  if (ICMP.has(p)) return undefined;
  if (ALL_PROTO.has(p)) return null;
  const f = Number(from);
  const t = Number(to);
  if (Number.isNaN(f) || Number.isNaN(t)) return undefined;
  if ((f <= 1 && t >= 65535) || (f === 0 && t === 0 && ALL_PROTO.has(p))) return null;
  if (f === -1 || t === -1) return null;
  return [f, t];
}

function openCidrs(cidrs: unknown[]): string[] {
  return cidrs.map(String).filter((c) => OPEN_CIDRS.has(c));
}

/** Internet-open ingress rules described by a resource object. */
export function openIngress(type: string, obj: Record<string, unknown> | null): OpenRule[] {
  if (!obj) return [];
  const out: OpenRule[] = [];
  const add = (range: PortRange | null | undefined, sources: string[], proto: unknown) => {
    if (range === undefined) return;
    for (const s of sources) {
      out.push({ key: `${String(proto)}:${range ? range.join("-") : "all"}:${s}`, range, source: s });
    }
  };
  switch (type) {
    case "aws_security_group":
      for (const r of asArray<unknown>(obj.ingress)) {
        if (!isRecord(r)) continue;
        add(awsRange(r.protocol, r.from_port, r.to_port), openCidrs([...asArray(r.cidr_blocks), ...asArray(r.ipv6_cidr_blocks)]), r.protocol);
      }
      break;
    case "aws_security_group_rule":
      if (obj.type === "ingress") {
        add(awsRange(obj.protocol, obj.from_port, obj.to_port), openCidrs([...asArray(obj.cidr_blocks), ...asArray(obj.ipv6_cidr_blocks)]), obj.protocol);
      }
      break;
    case "aws_vpc_security_group_ingress_rule":
      add(awsRange(obj.ip_protocol, obj.from_port, obj.to_port), openCidrs([obj.cidr_ipv4, obj.cidr_ipv6].filter(Boolean)), obj.ip_protocol);
      break;
    case "azurerm_network_security_rule":
    case "azurerm_network_security_group": {
      const rules = type === "azurerm_network_security_rule" ? [obj] : asArray<unknown>(obj.security_rule);
      for (const r of rules) {
        if (!isRecord(r)) continue;
        if (String(r.direction) !== "Inbound" || String(r.access) !== "Allow") continue;
        const sources = openCidrs([r.source_address_prefix, ...asArray(r.source_address_prefixes)].filter((x) => x !== null && x !== undefined && x !== ""));
        const ports = [r.destination_port_range, ...asArray(r.destination_port_ranges)].filter((x) => x !== null && x !== undefined && x !== "");
        const proto = String(r.protocol ?? "*");
        if (ICMP.has(proto.toLowerCase())) continue;
        for (const p of ports.length ? ports : ["*"]) add(parsePortRange(p), sources, proto);
      }
      break;
    }
    case "google_compute_firewall": {
      if (obj.disabled === true) break;
      const dir = obj.direction ?? "INGRESS";
      if (dir !== "INGRESS") break;
      const sources = openCidrs(asArray(obj.source_ranges));
      if (sources.length === 0) break;
      for (const a of asArray<unknown>(obj.allow)) {
        if (!isRecord(a)) continue;
        const proto = String(a.protocol ?? "all").toLowerCase();
        if (ICMP.has(proto)) continue;
        const ports = asArray(a.ports);
        if (proto === "all" || ports.length === 0) add(null, sources, proto);
        else for (const p of ports) add(parsePortRange(p), sources, proto);
      }
      break;
    }
    default:
      break;
  }
  return out;
}

const INGRESS_TYPES = new Set([
  "aws_security_group",
  "aws_security_group_rule",
  "aws_vpc_security_group_ingress_rule",
  "azurerm_network_security_rule",
  "azurerm_network_security_group",
  "google_compute_firewall",
]);

export const internetIngress: Rule = {
  id: "PL201",
  title: "Ingress opened to the internet",
  severity: "critical",
  category: "network",
  description:
    "A firewall / security group rule newly allows inbound traffic from 0.0.0.0/0, ::/0 or `Internet`. Critical for admin, database and cache ports or all ports; low for 80/443.",
  remediation:
    "Restrict the source to known CIDRs, a VPN, or a load balancer security group. For admin access use SSM Session Manager / a bastion / IAP instead of opening SSH/RDP.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (!writes(rc) || !INGRESS_TYPES.has(rc.type)) continue;
      const before = new Set(rc.kind === "create" ? [] : openIngress(rc.type, rc.before).map((r) => r.key));
      const fresh = openIngress(rc.type, rc.after).filter((r) => !before.has(r.key));
      if (fresh.length === 0) continue;
      const exp = exposureSeverity(fresh.map((r) => r.range));
      const sources = [...new Set(fresh.map((r) => r.source))].join(", ");
      hits.push({
        severity: exp.severity,
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\` allows inbound from ${sources} on ${exp.label}.`,
        details: [],
      });
    }
    return hits;
  },
};

export const publicDatabase: Rule = {
  id: "PL202",
  title: "Database publicly accessible",
  severity: "high",
  category: "network",
  description: "A managed database gets a public endpoint, or its firewall allows the whole internet.",
  remediation: "Keep databases in private subnets. Connect through a VPN, bastion, PrivateLink or application tier.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (!writes(rc)) continue;
      if (
        ["aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster", "aws_dms_replication_instance"].includes(rc.type) &&
        introduced(rc, (o) => o.publicly_accessible === true)
      ) {
        hits.push({
          severity: "high",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` will be publicly accessible (\`publicly_accessible = true\`).`,
          details: [],
        });
      }
      if (
        rc.type === "google_sql_database_instance" &&
        introduced(rc, (o) => getAll(o, "settings.ip_configuration.authorized_networks.value").some((x) => OPEN_CIDRS.has(String(x))))
      ) {
        hits.push({
          severity: "critical",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` authorizes 0.0.0.0/0 to connect.`,
          details: [],
        });
      }
      if (
        /^azurerm_(mssql|postgresql|postgresql_flexible|mysql|mysql_flexible|mariadb)_(server_)?firewall_rule$/.test(rc.type) &&
        introduced(rc, (o) => o.start_ip_address === "0.0.0.0" && o.end_ip_address === "255.255.255.255")
      ) {
        hits.push({
          severity: "critical",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` allows every IPv4 address (0.0.0.0 – 255.255.255.255).`,
          details: [],
        });
      }
    }
    return hits;
  },
};

export const lbInternetFacing: Rule = {
  id: "PL203",
  title: "Load balancer becomes internet-facing",
  severity: "medium",
  category: "network",
  description: "An internal load balancer is changed to internet-facing.",
  remediation: "Confirm the service is meant to be public and is protected (WAF, auth, TLS).",
  run({ plan }) {
    return managedChanges(plan)
      .filter((rc) => (rc.type === "aws_lb" || rc.type === "aws_alb") && (rc.kind === "update" || rc.kind === "replace"))
      .filter((rc) => v(rc, "before", "internal") === true && v(rc, "after", "internal") === false)
      .map((rc) => ({
        severity: "medium" as const,
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\` changes from internal to internet-facing.`,
        details: [],
      }));
  },
};

export const k8sApiPublic: Rule = {
  id: "PL204",
  title: "Kubernetes API endpoint open to the internet",
  severity: "medium",
  category: "network",
  description: "The EKS public API endpoint is enabled for 0.0.0.0/0.",
  remediation: "Disable the public endpoint or restrict `public_access_cidrs` to office/VPN/CI egress ranges.",
  run({ plan }) {
    return managedChanges(plan)
      .filter((rc) => rc.type === "aws_eks_cluster" && writes(rc))
      .filter((rc) =>
        introduced(rc, (o) => {
          const vc = asArray<Record<string, unknown>>(o.vpc_config)[0];
          if (vc?.endpoint_public_access !== true) return false;
          const cidrs = asArray(vc.public_access_cidrs);
          return cidrs.length === 0 || cidrs.some((c) => OPEN_CIDRS.has(String(c)));
        }),
      )
      .map((rc) => ({
        severity: "medium" as const,
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\` exposes the Kubernetes API publicly to 0.0.0.0/0.`,
        details: [],
      }));
  },
};

const PAB_FIELDS = ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"];

export const s3PublicAccessBlock: Rule = {
  id: "PL205",
  title: "S3 Block Public Access weakened",
  severity: "high",
  category: "network",
  description: "One or more S3 Block Public Access settings is turned off or the block is removed.",
  remediation: "Keep all four Block Public Access settings enabled. Serve public content through CloudFront with Origin Access Control instead.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (rc.type !== "aws_s3_bucket_public_access_block" && rc.type !== "aws_s3_account_public_access_block") continue;
      if (rc.kind === "delete") {
        if (PAB_FIELDS.some((f) => rc.before?.[f] === true)) {
          hits.push({
            severity: "high",
            address: rc.address,
            resourceType: rc.type,
            message: `\`${rc.address}\` is destroyed — Block Public Access protection is removed.`,
            details: [],
          });
        }
        continue;
      }
      if (!writes(rc) || !rc.after) continue;
      const off = PAB_FIELDS.filter((f) => rc.after?.[f] === false && (rc.kind === "create" || rc.before?.[f] !== false));
      if (off.length) {
        hits.push({
          severity: "high",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` disables ${off.map((f) => `\`${f}\``).join(", ")}.`,
          details: [],
        });
      }
    }
    return hits;
  },
};

const PUBLIC_ACLS = new Set(["public-read", "public-read-write", "authenticated-read"]);

export const publicStorage: Rule = {
  id: "PL206",
  title: "Storage made public",
  severity: "high",
  category: "network",
  description: "A bucket/container ACL grants access to everyone.",
  remediation: "Remove public ACLs. Use signed URLs or a CDN with origin access control for public content.",
  run({ plan }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (!writes(rc)) continue;
      if ((rc.type === "aws_s3_bucket_acl" || rc.type === "aws_s3_bucket") && introduced(rc, (o) => PUBLIC_ACLS.has(String(o.acl)))) {
        hits.push({
          severity: "high",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` sets ACL \`${String(rc.after?.acl)}\`.`,
          details: [],
        });
      }
      if (
        rc.type === "aws_s3_bucket_acl" &&
        introduced(rc, (o) => JSON.stringify(o.access_control_policy ?? "").includes("acs.amazonaws.com/groups/global/AllUsers"))
      ) {
        hits.push({
          severity: "high",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` grants access to the AllUsers group.`,
          details: [],
        });
      }
      if (rc.type === "azurerm_storage_container" && introduced(rc, (o) => o.container_access_type === "blob" || o.container_access_type === "container")) {
        hits.push({
          severity: "high",
          address: rc.address,
          resourceType: rc.type,
          message: `\`${rc.address}\` allows anonymous read access (\`container_access_type = ${String(rc.after?.container_access_type)}\`).`,
          details: [],
        });
      }
    }
    return hits;
  },
};

export const imdsV1: Rule = {
  id: "PL207",
  title: "IMDSv1 allowed on EC2",
  severity: "medium",
  category: "security",
  description: '`http_tokens = "optional"` allows IMDSv1, which is exploitable via SSRF to steal instance role credentials.',
  remediation: 'Set `metadata_options { http_tokens = "required" }`.',
  run({ plan }) {
    return managedChanges(plan)
      .filter((rc) => (rc.type === "aws_instance" || rc.type === "aws_launch_template") && writes(rc))
      .filter((rc) => introduced(rc, (o) => asArray<Record<string, unknown>>(o.metadata_options).some((m) => isRecord(m) && m.http_tokens === "optional")))
      .map((rc) => ({
        severity: "medium" as const,
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\` allows IMDSv1 (\`http_tokens = "optional"\`).`,
        details: [],
      }));
  },
};
