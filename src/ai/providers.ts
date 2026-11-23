import Anthropic from "@anthropic-ai/sdk";
import type { Report } from "../core/types.js";
import { buildDigest, SYSTEM_PROMPT } from "./digest.js";

export type AiProvider = "anthropic" | "openai" | "ollama";
export const AI_PROVIDERS: readonly AiProvider[] = ["anthropic", "openai", "ollama"];

export interface AiOptions {
  provider: AiProvider;
  model?: string;
  timeoutMs?: number;
  env?: Record<string, string | undefined>;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
}

export const DEFAULT_ANTHROPIC_MODEL = "claude-opus-5-5";

export class AiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AiError";
  }
}

async function anthropic(user: string, o: AiOptions): Promise<string> {
  const env = o.env ?? process.env;
  if (!env.ANTHROPIC_API_KEY && !env.ANTHROPIC_AUTH_TOKEN) throw new AiError("ANTHROPIC_API_KEY is not set.");
  const client = new Anthropic({
    apiKey: env.ANTHROPIC_API_KEY ?? null,
    authToken: env.ANTHROPIC_AUTH_TOKEN ?? null,
    baseURL: env.ANTHROPIC_BASE_URL || undefined,
    timeout: o.timeoutMs ?? 90_000,
    maxRetries: 2,
    fetch: o.fetchImpl,
  });
  try {
    const res = await client.beta.messages.create({
      model: o.model ?? DEFAULT_ANTHROPIC_MODEL,
      max_tokens: 16000,
      betas: ["server-side-fallback-2026-07-01"],
      fallbacks: "default",
      output_config: { effort: "low" },
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: user }],
    });
    if (res.stop_reason === "refusal") throw new AiError("The model declined to summarize this plan.");
    const text = res.content
      .filter((b): b is Extract<typeof b, { type: "text" }> => b.type === "text")
      .map((b) => b.text)
      .join("")
      .trim();
    if (!text) throw new AiError("Empty response from Anthropic API.");
    return text;
  } catch (e) {
    if (e instanceof AiError) throw e;
    if (e instanceof Anthropic.AuthenticationError) throw new AiError("Anthropic API rejected the credentials (401).");
    if (e instanceof Anthropic.RateLimitError) throw new AiError("Anthropic API rate limit hit (429).");
    if (e instanceof Anthropic.APIConnectionError) throw new AiError(`Could not reach the Anthropic API: ${e.message}`);
    if (e instanceof Anthropic.APIError) throw new AiError(`Anthropic API error ${String(e.status)}: ${e.message}`);
    throw e;
  }
}

async function postJson(url: string, body: unknown, headers: Record<string, string>, o: AiOptions): Promise<unknown> {
  const f = o.fetchImpl ?? fetch;
  let res: Response;
  try {
    res = await f(url, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(o.timeoutMs ?? 90_000),
    });
  } catch (e) {
    throw new AiError(`Request to ${new URL(url).origin} failed: ${(e as Error).message}`);
  }
  if (!res.ok) throw new AiError(`${new URL(url).origin} returned HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

/** OpenAI or any OpenAI-compatible endpoint (Azure OpenAI proxy, vLLM, LiteLLM…) via OPENAI_BASE_URL. */
async function openai(user: string, o: AiOptions): Promise<string> {
  const env = o.env ?? process.env;
  if (!env.OPENAI_API_KEY) throw new AiError("OPENAI_API_KEY is not set.");
  if (!o.model) throw new AiError("--ai-model is required for the openai provider.");
  const base = (env.OPENAI_BASE_URL || "https://api.openai.com/v1").replace(/\/$/, "");
  const data = (await postJson(
    `${base}/chat/completions`,
    {
      model: o.model,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: user },
      ],
    },
    { authorization: `Bearer ${env.OPENAI_API_KEY}` },
    o,
  )) as { choices?: Array<{ message?: { content?: string } }> };
  const text = data.choices?.[0]?.message?.content?.trim();
  if (!text) throw new AiError("Empty response from OpenAI-compatible API.");
  return text;
}

/** Local/self-hosted models — nothing leaves your network. */
async function ollama(user: string, o: AiOptions): Promise<string> {
  const env = o.env ?? process.env;
  if (!o.model) throw new AiError("--ai-model is required for the ollama provider (e.g. qwen2.5:7b).");
  const base = (env.OLLAMA_HOST || "http://localhost:11434").replace(/\/$/, "");
  const data = (await postJson(
    `${base.startsWith("http") ? base : `http://${base}`}/api/chat`,
    {
      model: o.model,
      stream: false,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: user },
      ],
    },
    {},
    o,
  )) as { message?: { content?: string } };
  const text = data.message?.content?.trim();
  if (!text) throw new AiError("Empty response from Ollama.");
  return text;
}

/** Returns the summary, or throws AiError. Callers treat failures as non-fatal. */
export async function summarizeWithAi(report: Report, o: AiOptions): Promise<string> {
  const user = buildDigest(report);
  switch (o.provider) {
    case "anthropic":
      return anthropic(user, o);
    case "openai":
      return openai(user, o);
    case "ollama":
      return ollama(user, o);
    default:
      throw new AiError(`Unknown AI provider "${String(o.provider)}". Use one of: ${AI_PROVIDERS.join(", ")}.`);
  }
}
