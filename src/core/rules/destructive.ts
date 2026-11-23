import { managedChanges } from "../plan.js";
import type { ResourceChange, Rule } from "../types.js";
import { deepEqual, isRecord, plural } from "../util.js";
import { destroyDetails, destroys, type Hit, isCritical, isStateful, v } from "./helpers.js";

const REMOVED_HINT =
  "If you only want Terraform to stop managing it, use a `removed { from = ... lifecycle { destroy = false } }` block (Terraform ≥ 1.7) instead of deleting the block.";

function dbSnapshotNote(rc: ResourceChange): string | undefined {
  if (v(rc, "before", "skip_final_snapshot") === true) return "`skip_final_snapshot = true` — no final snapshot will be taken.";
  return undefined;
}

export const statefulDestroyed: Rule = {
  id: "PL001",
  title: "Stateful resource will be destroyed",
  severity: "critical",
  category: "data-loss",
  description:
    "A resource that holds data (database, bucket, volume, key, DNS zone, queue…) is deleted. Unless backups exist and were tested, the data is gone.",
  remediation:
    "Confirm the deletion is intended and a backup/snapshot exists. Add `lifecycle { prevent_destroy = true }` to resources that must never be destroyed. " +
    REMOVED_HINT,
  run({ plan, config }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (rc.kind !== "delete" || !isStateful(rc.type, config)) continue;
      const details = destroyDetails(rc);
      const snap = dbSnapshotNote(rc);
      if (snap) details.push(snap);
      details.push("`prevent_destroy` is not set (Terraform would refuse this plan otherwise).");
      if (rc.reason === "delete_because_no_resource_config" || rc.reason === "delete_because_no_module") details.push(REMOVED_HINT);
      hits.push({
        severity: "critical",
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\` (${rc.type}) will be permanently destroyed.`,
        details,
      });
    }
    return hits;
  },
};

export const statefulReplaced: Rule = {
  id: "PL002",
  title: "Stateful resource will be replaced (destroy + create)",
  severity: "critical",
  category: "data-loss",
  description:
    "Terraform must destroy and recreate a resource that holds data because an attribute that cannot be changed in place was modified. The new resource starts empty.",
  remediation:
    "Revert the attribute that forces replacement, or plan a migration (snapshot/restore, blue-green). For RDS, many changes (e.g. engine version) can be done in place; check which attribute is listed under 'Forced by'.",
  run({ plan, config }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (rc.kind !== "replace" || !isStateful(rc.type, config)) continue;
      const details = destroyDetails(rc);
      const snap = dbSnapshotNote(rc);
      if (snap) details.push(snap);
      hits.push({
        severity: "critical",
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\` (${rc.type}) will be REPLACED — existing data will not carry over.`,
        details,
      });
    }
    return hits;
  },
};

export const criticalDestroyed: Rule = {
  id: "PL003",
  title: "High-impact resource will be replaced or destroyed",
  severity: "high",
  category: "availability",
  description:
    "A resource with a large blast radius (cluster, load balancer, network, instance, IAM role, DNS record, generated secret…) is replaced or destroyed. Expect downtime, new IDs/IPs/ARNs, or broken references.",
  remediation:
    "Check the 'Forced by' attribute and whether it can be changed in place. Use `create_before_destroy` for zero-downtime replacement where supported, and schedule the change in a maintenance window.",
  run({ plan, config }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (!destroys(rc) || isStateful(rc.type, config) || !isCritical(rc.type, config)) continue;
      const details = destroyDetails(rc);
      if (rc.type === "random_password" || rc.type === "tls_private_key") {
        details.push("A new secret/key will be generated — everything that uses the old value must be updated.");
      }
      hits.push({
        severity: "high",
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\` (${rc.type}) will be ${rc.kind === "delete" ? "destroyed" : "replaced"}.`,
        details,
      });
    }
    return hits;
  },
};

export const otherDestroyed: Rule = {
  id: "PL004",
  title: "Resource will be replaced or destroyed",
  severity: "low",
  category: "availability",
  description: "Any other destroy or replace. Usually expected, listed so reviewers see every destructive action.",
  remediation: "Confirm each destroy/replace is intended.",
  run({ plan, config }) {
    const hits: Hit[] = [];
    for (const rc of managedChanges(plan)) {
      if (!destroys(rc) || isStateful(rc.type, config) || isCritical(rc.type, config)) continue;
      hits.push({
        severity: "low",
        address: rc.address,
        resourceType: rc.type,
        message: `\`${rc.address}\` will be ${rc.kind === "delete" ? "destroyed" : "replaced"}.`,
        details: destroyDetails(rc),
      });
    }
    return hits;
  },
};

export const massDestroy: Rule = {
  id: "PL005",
  title: "Large number of resources destroyed",
  severity: "high",
  category: "availability",
  description:
    "The plan destroys or replaces more resources than the configured threshold (default 10). This is often caused by a wrong workspace, a renamed module, or a provider/backend misconfiguration.",
  remediation:
    "Double-check the workspace/backend and module addresses. If this is a refactor, use `moved` blocks so Terraform updates addresses instead of recreating resources.",
  run({ plan, config }) {
    const destroyed = managedChanges(plan).filter(destroys);
    if (destroyed.length < config.massDestroyThreshold) return [];
    const byType = new Map<string, number>();
    for (const rc of destroyed) byType.set(rc.type, (byType.get(rc.type) ?? 0) + 1);
    const top = [...byType.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    return [
      {
        severity: "high",
        address: "(plan)",
        message: `${plural(destroyed.length, "resource")} will be destroyed or replaced (threshold: ${config.massDestroyThreshold}).`,
        details: [`By type: ${top.map(([t, n]) => `${t} ×${n}`).join(", ")}`],
      },
    ];
  },
};

// ---------------------------------------------------------------------------
// Refactors: renames and count index shifts that destroy/recreate resources
// ---------------------------------------------------------------------------

const IGNORED_KEYS = new Set(["id", "arn", "tags_all", "timeouts", "owner_id", "unique_id"]);

/** Fraction of known `after` attributes that are identical in `before`. */
export function similarity(before: Record<string, unknown> | null, after: Record<string, unknown> | null, afterUnknown: unknown): number {
  if (!before || !after) return 0;
  const unknown = isRecord(afterUnknown) ? afterUnknown : {};
  let compared = 0;
  let equal = 0;
  for (const [k, val] of Object.entries(after)) {
    if (IGNORED_KEYS.has(k) || val === null || unknown[k] === true) continue;
    if (Array.isArray(val) && val.length === 0) continue;
    compared++;
    if (deepEqual(before[k], val)) equal++;
  }
  return compared === 0 ? 0 : equal / compared;
}

function movedSnippet(from: string, to: string): string {
  return `moved {\n  from = ${from}\n  to   = ${to}\n}`;
}

export const refactorRecreate: Rule = {
  id: "PL006",
  title: "Refactor will destroy and recreate a resource",
  severity: "high",
  category: "refactor",
  description:
    "A resource is destroyed at one address and an identical resource is created at another (rename, moved into a module, count→for_each), or removing an item from a `count` list shifts the indexes of everything after it. Terraform treats these as new resources.",
  remediation:
    "Add a `moved` block from the old address to the new one so Terraform only updates state. For `count` index shifts, switch to `for_each` with stable keys.",
  run({ plan, config }) {
    const hits: Hit[] = [];
    const changes = managedChanges(plan);
    const deletes = changes.filter((c) => c.kind === "delete");
    const creates = changes.filter((c) => c.kind === "create" && !c.importing);
    const used = new Set<string>();

    for (const d of deletes) {
      let best: { rc: ResourceChange; score: number } | undefined;
      for (const c of creates) {
        if (c.type !== d.type || used.has(c.address)) continue;
        let score = similarity(d.before, c.after, c.afterUnknown);
        if (score < 0.6) continue;
        if (c.name === d.name) score += 0.05;
        if (c.moduleAddress === d.moduleAddress) score += 0.02;
        if (!best || score > best.score) best = { rc: c, score };
      }
      if (!best) continue;
      used.add(best.rc.address);
      const important = isStateful(d.type, config) || isCritical(d.type, config);
      hits.push({
        severity: important ? "high" : "medium",
        address: d.address,
        resourceType: d.type,
        message: `\`${d.address}\` is destroyed and an equivalent \`${best.rc.address}\` is created — this looks like a rename/move.`,
        details: [
          `${Math.round(Math.min(best.score, 1) * 100)}% of known attributes are identical.`,
          `Add this to your configuration to keep the existing object:\n\`\`\`hcl\n${movedSnippet(d.address, best.rc.address)}\n\`\`\``,
        ],
      });
    }

    // count index shifts: one index deleted because the list shrank, while
    // later indexes of the same block are updated/replaced.
    const shrunk = new Map<string, ResourceChange[]>();
    for (const d of deletes) {
      if (d.reason === "delete_because_count_index" && !hits.some((h) => h.address === d.address)) {
        shrunk.set(d.baseAddress, [...(shrunk.get(d.baseAddress) ?? []), d]);
      }
    }
    for (const [base, removed] of shrunk) {
      const shifted = changes.filter((c) => c.baseAddress === base && typeof c.index === "number" && (c.kind === "update" || c.kind === "replace"));
      if (shifted.length === 0) continue;
      const replaced = shifted.filter((c) => c.kind === "replace").length;
      const type = removed[0]?.type ?? "";
      const important = isStateful(type, config) || isCritical(type, config);
      hits.push({
        severity: important || replaced > 0 ? "high" : "medium",
        address: base,
        resourceType: type,
        message: `Removing an element from \`${base}\` (count) shifts indexes: ${plural(shifted.length, "other instance")} will be modified${replaced ? ` (${replaced} replaced)` : ""} and ${removed.map((r) => `\`${r.address}\``).join(", ")} destroyed.`,
        details: [
          "Each instance after the removed one inherits its neighbour's configuration.",
          "Use `for_each` with stable keys (e.g. a map keyed by name) so removing one item only affects that item.",
        ],
      });
    }
    return hits;
  },
};

export const driftDetected: Rule = {
  id: "PL007",
  title: "Infrastructure drifted from Terraform state",
  severity: "medium",
  category: "drift",
  description: "Terraform detected changes made outside of Terraform (console, CLI, other automation) during refresh. Applying this plan may revert them.",
  remediation: "Find out who changed what (CloudTrail / activity logs). Either codify the change in Terraform or let this apply revert it — deliberately.",
  run({ plan }) {
    return plan.drift
      .filter((d) => d.mode === "managed")
      .map((d) => ({
        severity: "medium" as const,
        address: d.address,
        resourceType: d.type,
        message: d.kind === "delete" ? `\`${d.address}\` was deleted outside of Terraform.` : `\`${d.address}\` was changed outside of Terraform.`,
        details: d.changedPaths.length
          ? [
              `Changed attributes: ${d.changedPaths
                .slice(0, 10)
                .map((p) => `\`${p}\``)
                .join(", ")}`,
            ]
          : [],
      }));
  },
};

export const importing: Rule = {
  id: "PL008",
  title: "Resource will be imported",
  severity: "info",
  category: "hygiene",
  description: "An existing object is being imported into Terraform state via an `import` block.",
  remediation: "Make sure the configuration matches the real object so the import does not also trigger an update.",
  run({ plan }) {
    return managedChanges(plan)
      .concat(plan.changes.filter((c) => c.kind === "no-op"))
      .filter((c) => c.importing)
      .map((c) => ({
        severity: "info" as const,
        address: c.address,
        resourceType: c.type,
        message: `\`${c.address}\` will be imported${c.kind === "update" ? " and then updated" : ""}.`,
        details:
          c.kind === "update" && c.changedPaths.length
            ? [
                `Will also change: ${c.changedPaths
                  .slice(0, 8)
                  .map((p) => `\`${p}\``)
                  .join(", ")}`,
              ]
            : [],
      }));
  },
};

export const movedResources: Rule = {
  id: "PL009",
  title: "Resource address moved",
  severity: "info",
  category: "refactor",
  description: "A `moved` block changes a resource address without recreating it.",
  remediation: "No action needed — this is the safe way to refactor.",
  run({ plan }) {
    return plan.changes
      .filter((c) => c.mode === "managed" && c.moved)
      .map((c) => ({
        severity: "info" as const,
        address: c.address,
        resourceType: c.type,
        message: `\`${c.previousAddress}\` → \`${c.address}\` (moved, not recreated).`,
        details: [],
      }));
  },
};
