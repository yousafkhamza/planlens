/**
 * Core types. The engine is pure (no Node or DOM APIs) so the exact same
 * code runs in the CLI, the GitHub Action and the browser.
 */

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Severity used for gating. "none" means never fail. */
export type FailOn = Severity | "none";

export type ChangeKind = "create" | "update" | "delete" | "replace" | "read" | "no-op";

export type Category = "data-loss" | "availability" | "security" | "iam" | "network" | "secrets" | "refactor" | "drift" | "hygiene" | "cost" | "custom";

/** Raw Terraform JSON plan (subset we rely on). See `terraform show -json` docs. */
export interface RawPlan {
  format_version?: string;
  terraform_version?: string;
  resource_changes?: RawResourceChange[];
  resource_drift?: RawResourceChange[];
  output_changes?: Record<string, RawChange>;
  configuration?: RawConfiguration;
  errored?: boolean;
  applyable?: boolean;
  complete?: boolean;
  variables?: Record<string, { value?: unknown }>;
  [key: string]: unknown;
}

export interface RawChange {
  actions: string[];
  before?: unknown;
  after?: unknown;
  after_unknown?: unknown;
  before_sensitive?: unknown;
  after_sensitive?: unknown;
  replace_paths?: Array<Array<string | number>>;
  importing?: { id?: string; identity?: unknown };
  generated_config?: string;
}

export interface RawResourceChange {
  address: string;
  previous_address?: string;
  module_address?: string;
  mode?: "managed" | "data";
  type: string;
  name: string;
  index?: string | number;
  provider_name?: string;
  deposed?: string;
  change: RawChange;
  action_reason?: string;
}

export interface RawConfiguration {
  root_module?: RawModuleConfig;
}

export interface RawModuleConfig {
  resources?: Array<{ address: string; type: string; name: string; mode?: string }>;
  module_calls?: Record<string, { source?: string; module?: RawModuleConfig }>;
}

/** A normalized resource change — what rules operate on. */
export interface ResourceChange {
  address: string;
  /** Address without the instance key, e.g. `aws_subnet.private` for `aws_subnet.private[2]`. */
  baseAddress: string;
  previousAddress?: string;
  moduleAddress?: string;
  mode: "managed" | "data";
  type: string;
  name: string;
  index?: string | number;
  provider: string;
  /** Short provider name, e.g. `aws`, `azurerm`, `google`. */
  providerShort: string;
  kind: ChangeKind;
  /** For replace: whether Terraform creates the new object before destroying the old one. */
  createBeforeDestroy: boolean;
  reason?: string;
  replacePaths: string[];
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  afterUnknown: unknown;
  beforeSensitive: unknown;
  afterSensitive: unknown;
  importing: boolean;
  moved: boolean;
  deposed?: string;
  /** Top-level/nested attribute paths whose value changes (update/replace only). */
  changedPaths: string[];
}

export interface OutputChange {
  name: string;
  kind: ChangeKind;
  sensitive: boolean;
  before: unknown;
  after: unknown;
  afterUnknown: boolean;
}

export interface NormalizedPlan {
  formatVersion: string;
  terraformVersion: string;
  changes: ResourceChange[];
  drift: ResourceChange[];
  outputs: OutputChange[];
  errored: boolean;
  applyable: boolean;
  complete: boolean;
  /** Absolute module path -> module source string (from configuration). */
  moduleSources: Record<string, string>;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  category: Category;
  title: string;
  /** Resource or output address the finding is about. */
  address: string;
  /** Resource type, if the finding is about a resource. */
  resourceType?: string;
  message: string;
  details: string[];
  remediation?: string;
  /** Set when an `ignore` entry in config suppressed this finding. */
  suppressed?: { reason: string; expires?: string };
}

export interface RuleContext {
  plan: NormalizedPlan;
  config: ResolvedConfig;
  /** Cost estimate for this plan (from Infracost), when provided. */
  cost?: CostSummary;
}

/** Monthly cost estimate, normalized from Infracost JSON. */
export interface CostSummary {
  currency: string;
  /** Monthly cost before the change (prior state), if known. */
  pastMonthly?: number;
  /** Monthly cost after the change. */
  monthly?: number;
  /** after − before. */
  diffMonthly?: number;
  /** Per-resource monthly deltas, largest absolute change first (max 20). */
  resources: Array<{ address: string; diffMonthly: number }>;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: Category;
  description: string;
  /** Plain-text remediation guidance shown in reports and the rule catalog. */
  remediation: string;
  run(ctx: RuleContext): Omit<Finding, "ruleId" | "category" | "title">[];
}

export interface ChangeSummary {
  create: number;
  update: number;
  delete: number;
  replace: number;
  read: number;
  noop: number;
  imported: number;
  moved: number;
  drifted: number;
  /** create + update + delete + replace */
  total: number;
}

export type RiskLevel = Severity | "none";

export interface Report {
  schemaVersion: 1;
  tool: { name: "planlens"; version: string };
  /** Label for this plan (file name, workspace, etc). */
  name: string;
  terraformVersion: string;
  summary: ChangeSummary;
  score: number;
  level: RiskLevel;
  failOn: FailOn;
  passed: boolean;
  /** Active findings (not suppressed), sorted by severity. */
  findings: Finding[];
  suppressed: Finding[];
  /** Warnings about the run itself (expired ignores, plan errors, etc). */
  warnings: string[];
  changes: ResourceChangeSummary[];
  cost?: CostSummary;
  aiSummary?: string;
}

export interface ResourceChangeSummary {
  address: string;
  type: string;
  kind: ChangeKind;
  reason?: string;
  replacePaths: string[];
  changedPaths: string[];
  previousAddress?: string;
  importing: boolean;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface IgnoreEntry {
  rule?: string;
  /** Glob over resource address. */
  address?: string;
  reason: string;
  /** ISO date (YYYY-MM-DD). After this date the ignore stops applying and a warning is emitted. */
  expires?: string;
}

export type AttributeOp = "exists" | "absent" | "equals" | "not_equals" | "matches" | "not_matches" | "in" | "not_in" | "changed";

export interface AttributeCondition {
  path: string;
  op: AttributeOp;
  value?: unknown;
}

export interface CustomRuleConfig {
  id: string;
  title: string;
  severity: Severity;
  message?: string;
  remediation?: string;
  when: {
    actions?: ChangeKind[];
    /** Glob(s) over resource type. */
    type?: string | string[];
    /** Glob(s) over resource address. */
    address?: string | string[];
    /** All conditions must hold (evaluated against `after`, or `before` for deletes). */
    attributes?: AttributeCondition[];
  };
}

export interface PlanlensConfig {
  fail_on?: FailOn;
  mass_destroy_threshold?: number;
  stateful_types?: string[];
  critical_types?: string[];
  disable?: string[];
  severity_overrides?: Record<string, Severity>;
  ignore?: IgnoreEntry[];
  rules?: CustomRuleConfig[];
  cost?: {
    /** PL501 fires when the monthly cost increase is above this amount. */
    max_monthly_increase?: number;
    /** PL501 fires when the monthly cost increase is above this percentage of the previous cost. */
    max_monthly_increase_percent?: number;
  };
}

export interface ResolvedConfig {
  failOn: FailOn;
  massDestroyThreshold: number;
  statefulTypes: Set<string>;
  criticalTypes: Set<string>;
  disable: Set<string>;
  severityOverrides: Record<string, Severity>;
  ignore: IgnoreEntry[];
  rules: CustomRuleConfig[];
  costMaxIncrease?: number;
  costMaxIncreasePercent?: number;
  /** "today" used for ignore expiry — injectable for deterministic tests. */
  now: Date;
}
