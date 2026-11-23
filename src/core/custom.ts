import type { managedChanges } from "./plan.js";
import type { AttributeCondition, CustomRuleConfig, Finding, ResourceChange } from "./types.js";
import { anyGlob, deepEqual, getAll } from "./util.js";

function testCondition(rc: ResourceChange, c: AttributeCondition): boolean {
  const obj = rc.kind === "delete" ? rc.before : rc.after;
  const values = getAll(obj, c.path).filter((x) => x !== null);
  switch (c.op) {
    case "exists":
      return values.length > 0;
    case "absent":
      return values.length === 0;
    case "equals":
      return values.some((x) => deepEqual(x, c.value) || String(x) === String(c.value));
    case "not_equals":
      return values.length > 0 && values.every((x) => !deepEqual(x, c.value) && String(x) !== String(c.value));
    case "matches":
      return values.some((x) => new RegExp(String(c.value)).test(String(x)));
    case "not_matches":
      return values.length > 0 && values.every((x) => !new RegExp(String(c.value)).test(String(x)));
    case "in":
      return values.some((x) => Array.isArray(c.value) && c.value.map(String).includes(String(x)));
    case "not_in":
      return values.length > 0 && values.every((x) => Array.isArray(c.value) && !c.value.map(String).includes(String(x)));
    case "changed":
      return rc.changedPaths.some((p) => p === c.path || p.startsWith(`${c.path}.`) || p.startsWith(`${c.path}[`));
    default:
      return false;
  }
}

export function matchesCustom(rc: ResourceChange, rule: CustomRuleConfig): boolean {
  const w = rule.when;
  if (w.actions && !w.actions.includes(rc.kind)) return false;
  if (!anyGlob(w.type, rc.type)) return false;
  if (!anyGlob(w.address, rc.address)) return false;
  return (w.attributes ?? []).every((c) => testCondition(rc, c));
}

export function runCustomRules(rules: CustomRuleConfig[], changes: ReturnType<typeof managedChanges>): Finding[] {
  const out: Finding[] = [];
  for (const rule of rules) {
    for (const rc of changes) {
      if (!matchesCustom(rc, rule)) continue;
      out.push({
        ruleId: rule.id,
        severity: rule.severity,
        category: "custom",
        title: rule.title,
        address: rc.address,
        resourceType: rc.type,
        message: rule.message
          ? rule.message.replaceAll("{address}", rc.address).replaceAll("{type}", rc.type).replaceAll("{action}", rc.kind)
          : `\`${rc.address}\` (${rc.kind}) matches custom rule "${rule.title}".`,
        details: [],
        remediation: rule.remediation,
      });
    }
  }
  return out;
}
