/** Programmatic API. */
export { ConfigError, resolveConfig, validateConfig } from "./core/config.js";
export { analyzePlan, gatePasses, riskLevel, riskScore } from "./core/engine.js";
export { normalizePlan, PlanParseError, parsePlanText, summarize } from "./core/plan.js";
export { RULES, ruleById } from "./core/rules/index.js";
export type * from "./core/types.js";
export { renderJson, toJson } from "./report/json.js";
export { renderMarkdown } from "./report/markdown.js";
export { renderSarif } from "./report/sarif.js";
export { renderText } from "./report/text.js";
export { VERSION } from "./version.js";
