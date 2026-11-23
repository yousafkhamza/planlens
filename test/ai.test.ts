import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildDigest, maskIdentifiers } from "../src/ai/digest.js";
import { AiError, DEFAULT_ANTHROPIC_MODEL, summarizeWithAi } from "../src/ai/providers.js";
import { analyzePlan } from "../src/core/engine.js";
import { VERSION } from "../src/version.js";
import { fixture } from "./helpers.js";

const report = () => analyzePlan(fixture("real/aws-create.json"));

function fakeFetch(respond: (url: string, body: Record<string, unknown>, headers: Headers) => Response) {
  const seen: Array<{ url: string; body: Record<string, unknown>; headers: Headers }> = [];
  const f = (async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    const headers = new Headers(init?.headers);
    seen.push({ url: u, body, headers });
    return respond(u, body, headers);
  }) as typeof fetch;
  return { f, seen };
}

describe("digest", () => {
  it("never contains attribute values and masks identifiers", () => {
    const d = buildDigest(report());
    expect(d).not.toContain("not-a-real-password");
    expect(d).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(d).not.toContain("123456789012");
    expect(d).toContain("aws_iam_role.github");
    expect(maskIdentifiers("acct 123456789012 me@x.io 10.1.2.3 0.0.0.0/0")).toBe("acct <account-id> <email> <ip> 0.0.0.0/0");
  });
});

describe("providers", () => {
  it("anthropic: uses the SDK with the default model, fallbacks and low effort", async () => {
    const { f, seen } = fakeFetch(() =>
      Response.json({
        id: "msg_1",
        type: "message",
        role: "assistant",
        model: DEFAULT_ANTHROPIC_MODEL,
        content: [{ type: "text", text: "**Biggest risks**: public DB." }],
        stop_reason: "end_turn",
        usage: { input_tokens: 1, output_tokens: 1 },
      }),
    );
    const text = await summarizeWithAi(report(), { provider: "anthropic", env: { ANTHROPIC_API_KEY: "k" }, fetchImpl: f });
    expect(text).toBe("**Biggest risks**: public DB.");
    expect(seen[0]?.url).toContain("/v1/messages");
    expect(seen[0]?.body).toMatchObject({ model: "claude-opus-5-5", fallbacks: "default", output_config: { effort: "low" } });
    expect(seen[0]?.headers.get("anthropic-beta")).toContain("server-side-fallback-2026-07-01");
    expect(JSON.stringify(seen[0]?.body)).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("anthropic: maps refusals and API errors to AiError", async () => {
    const refusal = fakeFetch(() =>
      Response.json({
        id: "m",
        type: "message",
        role: "assistant",
        model: "x",
        content: [],
        stop_reason: "refusal",
        usage: { input_tokens: 1, output_tokens: 0 },
      }),
    );
    await expect(summarizeWithAi(report(), { provider: "anthropic", env: { ANTHROPIC_API_KEY: "k" }, fetchImpl: refusal.f })).rejects.toThrow(/declined/);
    const empty = fakeFetch(() =>
      Response.json({
        id: "m",
        type: "message",
        role: "assistant",
        model: "x",
        content: [],
        stop_reason: "end_turn",
        usage: { input_tokens: 1, output_tokens: 0 },
      }),
    );
    await expect(summarizeWithAi(report(), { provider: "anthropic", env: { ANTHROPIC_API_KEY: "k" }, fetchImpl: empty.f })).rejects.toThrow(/Empty response/);
    const unauthorized = fakeFetch(() => Response.json({ type: "error", error: { type: "authentication_error", message: "bad key" } }, { status: 401 }));
    await expect(summarizeWithAi(report(), { provider: "anthropic", env: { ANTHROPIC_API_KEY: "k" }, fetchImpl: unauthorized.f })).rejects.toThrow(
      /rejected the credentials/,
    );
    const bad = fakeFetch(() => Response.json({ type: "error", error: { type: "invalid_request_error", message: "nope" } }, { status: 400 }));
    await expect(summarizeWithAi(report(), { provider: "anthropic", env: { ANTHROPIC_API_KEY: "k" }, fetchImpl: bad.f })).rejects.toThrow(/API error 400/);
    await expect(summarizeWithAi(report(), { provider: "anthropic", env: {} })).rejects.toThrow(/ANTHROPIC_API_KEY is not set/);
  });

  it("openai-compatible: honours OPENAI_BASE_URL and requires a model", async () => {
    const { f, seen } = fakeFetch(() => Response.json({ choices: [{ message: { content: " summary " } }] }));
    const text = await summarizeWithAi(report(), {
      provider: "openai",
      model: "my-model",
      env: { OPENAI_API_KEY: "k", OPENAI_BASE_URL: "https://llm.internal/v1/" },
      fetchImpl: f,
    });
    expect(text).toBe("summary");
    expect(seen[0]?.url).toBe("https://llm.internal/v1/chat/completions");
    expect(seen[0]?.headers.get("authorization")).toBe("Bearer k");
    await expect(summarizeWithAi(report(), { provider: "openai", env: { OPENAI_API_KEY: "k" } })).rejects.toThrow(/--ai-model is required/);
    await expect(summarizeWithAi(report(), { provider: "openai", model: "m", env: {} })).rejects.toThrow(/OPENAI_API_KEY/);
    const err = fakeFetch(() => new Response("boom", { status: 500 }));
    await expect(summarizeWithAi(report(), { provider: "openai", model: "m", env: { OPENAI_API_KEY: "k" }, fetchImpl: err.f })).rejects.toThrow(/HTTP 500/);
    const empty = fakeFetch(() => Response.json({ choices: [] }));
    await expect(summarizeWithAi(report(), { provider: "openai", model: "m", env: { OPENAI_API_KEY: "k" }, fetchImpl: empty.f })).rejects.toThrow(
      /Empty response/,
    );
  });

  it("ollama: local endpoint, host without scheme", async () => {
    const { f, seen } = fakeFetch(() => Response.json({ message: { content: "ok" } }));
    expect(await summarizeWithAi(report(), { provider: "ollama", model: "qwen2.5:7b", env: { OLLAMA_HOST: "gpu-box:11434" }, fetchImpl: f })).toBe("ok");
    expect(seen[0]?.url).toBe("http://gpu-box:11434/api/chat");
    expect(seen[0]?.body).toMatchObject({ model: "qwen2.5:7b", stream: false });
    const down = (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch;
    await expect(summarizeWithAi(report(), { provider: "ollama", model: "m", env: {}, fetchImpl: down })).rejects.toThrow(
      /localhost:11434 failed: ECONNREFUSED/,
    );
    const empty = fakeFetch(() => Response.json({}));
    await expect(summarizeWithAi(report(), { provider: "ollama", model: "m", env: {}, fetchImpl: empty.f })).rejects.toThrow(/Empty response/);
  });

  it("rejects unknown providers", async () => {
    await expect(summarizeWithAi(report(), { provider: "x" as never })).rejects.toBeInstanceOf(AiError);
  });
});

describe("version", () => {
  it("matches package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });
});
