/**
 * Browser bundle (docs/assets/planlens.js). Exposes the pure engine on
 * `window.PlanLens`. Nothing here touches the network.
 */
import { parse as parseYaml } from "yaml";
import { ConfigError, validateConfig } from "./core/config.js";
import { describeCostDelta, formatMoney, parseInfracost } from "./core/cost.js";
import { analyzePlan } from "./core/engine.js";
import { PlanParseError, parsePlanText } from "./core/plan.js";
import { RULES } from "./core/rules/index.js";
import { renderMarkdown } from "./report/markdown.js";
import { renderSarif } from "./report/sarif.js";
import { VERSION } from "./version.js";

function parseConfigText(text: string) {
  if (!text.trim()) return {};
  return validateConfig(parseYaml(text));
}

const api = {
  analyzePlan,
  parsePlanText,
  parseConfigText,
  parseInfracost,
  formatMoney,
  describeCostDelta,
  renderMarkdown,
  renderSarif,
  RULES,
  VERSION,
  PlanParseError,
  ConfigError,
};

declare global {
  interface Window {
    PlanLens: typeof api;
  }
}

window.PlanLens = api;
