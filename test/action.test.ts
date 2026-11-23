import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { findComment, upsertComment } from "../src/action/github.js";
import { input, runAction } from "../src/action/main.js";
import { FIXTURES } from "./helpers.js";

interface Call {
  method: string;
  url: string;
  body?: { body?: string };
}

function fakeGitHub(opts: { existing?: Array<{ id: number; body: string }>; status?: number; pages?: number } = {}) {
  const calls: Call[] = [];
  const f = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    const method = init?.method ?? "GET";
    calls.push({ method, url: u, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    if (opts.status) return new Response("forbidden", { status: opts.status });
    if (method === "GET") {
      const page = Number(new URL(u).searchParams.get("page"));
      if (opts.pages && page < opts.pages) return Response.json(Array.from({ length: 100 }, (_, i) => ({ id: page * 1000 + i, body: "other" })));
      return Response.json(opts.existing ?? []);
    }
    return Response.json({ id: 1 }, { status: method === "POST" ? 201 : 200 });
  }) as typeof fetch;
  return { f, calls };
}

function setup(over: Record<string, string> = {}, pr: { number: number; labels?: string[] } | null = { number: 7 }) {
  const ws = mkdtempSync(join(tmpdir(), "planlens-action-"));
  mkdirSync(join(ws, "envs", "prod"), { recursive: true });
  mkdirSync(join(ws, "envs", "dev"), { recursive: true });
  copyFileSync(`${FIXTURES}real/aws-create.json`, join(ws, "envs", "prod", "plan.json"));
  copyFileSync(`${FIXTURES}real/noop.json`, join(ws, "envs", "dev", "plan.json"));
  const event = join(ws, "event.json");
  writeFileSync(event, JSON.stringify(pr ? { pull_request: { number: pr.number, labels: (pr.labels ?? []).map((name) => ({ name })) } } : { push: {} }));
  const output = join(ws, "gh_output");
  const summary = join(ws, "gh_summary");
  writeFileSync(output, "");
  writeFileSync(summary, "");
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: ws,
    GITHUB_EVENT_PATH: event,
    GITHUB_OUTPUT: output,
    GITHUB_STEP_SUMMARY: summary,
    GITHUB_REPOSITORY: "acme/infra",
    GITHUB_API_URL: "https://ghe.example/api/v3",
    GITHUB_SERVER_URL: "https://ghe.example",
    GITHUB_RUN_ID: "42",
    INPUT_PLAN: "envs/*/plan.json",
    "INPUT_GITHUB-TOKEN": "t0ken",
    ...over,
  };
  const logs: string[] = [];
  return { ws, env, logs, log: (s: string) => logs.push(s), outputs: () => readFileSync(output, "utf8"), summary: () => readFileSync(summary, "utf8") };
}

function outputValue(raw: string, name: string): string | undefined {
  const m = new RegExp(`${name}<<(\\S+)\\n([\\s\\S]*?)\\n\\1`).exec(raw);
  return m?.[2];
}

describe("action inputs", () => {
  it("reads INPUT_ vars with hyphens kept and blanks as fallback", () => {
    expect(input({ "INPUT_FAIL-ON": " critical " }, "fail-on")).toBe("critical");
    expect(input({ "INPUT_FAIL-ON": "  " }, "fail-on", "high")).toBe("high");
  });
});

describe("runAction", () => {
  it("analyzes globbed plans, writes files/outputs/summary, annotates and creates the PR comment", async () => {
    const s = setup();
    const gh = fakeGitHub();
    const code = await runAction({ env: s.env, log: s.log, fetchImpl: gh.f });
    expect(code).toBe(1);
    const out = s.outputs();
    expect(outputValue(out, "passed")).toBe("false");
    expect(outputValue(out, "risk-score")).toBe("100");
    expect(outputValue(out, "risk-level")).toBe("critical");
    expect(Number(outputValue(out, "critical"))).toBeGreaterThan(0);
    for (const f of ["planlens.sarif", "planlens.json", "planlens.md"]) expect(existsSync(join(s.ws, f))).toBe(true);
    expect(s.summary()).toContain("2 plans");
    const logs = s.logs.join("\n");
    expect(logs).toMatch(/::error title=planlens PL\d+%3A/);
    expect(logs).toContain("PR comment created");
    expect(logs).toMatch(/::error::planlens: gate failed/);
    const post = gh.calls.find((c) => c.method === "POST");
    expect(post?.url).toBe("https://ghe.example/api/v3/repos/acme/infra/issues/7/comments");
    expect(post?.body?.body).toContain("<!-- planlens:default -->");
    expect(post?.body?.body).not.toContain("not applyable");
  });

  it("updates an existing sticky comment instead of posting a new one", async () => {
    const s = setup({ "INPUT_COMMENT-ID": "prod" });
    const gh = fakeGitHub({ existing: [{ id: 99, body: "<!-- planlens:prod -->\nold" }] });
    await runAction({ env: s.env, log: s.log, fetchImpl: gh.f });
    expect(gh.calls.map((c) => c.method)).toEqual(["GET", "PATCH"]);
    expect(gh.calls[1]?.url).toContain("/issues/comments/99");
  });

  it("passes the gate when the accept-risk label is present", async () => {
    const s = setup({}, { number: 7, labels: ["planlens:accept-risk"] });
    const code = await runAction({ env: s.env, log: s.log, fetchImpl: fakeGitHub().f });
    expect(code).toBe(0);
    expect(outputValue(s.outputs(), "passed")).toBe("true");
    expect(s.logs.join("\n")).toContain("::notice::planlens: risk accepted");
    expect(readFileSync(join(s.ws, "planlens.md"), "utf8")).toContain("Risk accepted via label");
  });

  it("degrades gracefully when the token cannot comment (fork PRs)", async () => {
    const s = setup({ "INPUT_FAIL-ON": "none" });
    const code = await runAction({ env: s.env, log: s.log, fetchImpl: fakeGitHub({ status: 403 }).f });
    expect(code).toBe(0);
    expect(s.logs.join("\n")).toMatch(/::warning::planlens: could not post PR comment.*pull-requests: write/);
  });

  it("skips commenting outside PRs, when disabled, or without a token", async () => {
    const push = setup({}, null);
    const gh1 = fakeGitHub();
    await runAction({ env: push.env, log: push.log, fetchImpl: gh1.f });
    expect(gh1.calls).toHaveLength(0);

    const never = setup({ INPUT_COMMENT: "never" });
    const gh2 = fakeGitHub();
    await runAction({ env: never.env, log: never.log, fetchImpl: gh2.f });
    expect(gh2.calls).toHaveLength(0);

    const noToken = setup({ "INPUT_GITHUB-TOKEN": "" });
    await runAction({ env: noToken.env, log: noToken.log, fetchImpl: fakeGitHub().f });
    expect(noToken.logs.join("\n")).toContain("no github-token");

    const noRepo = setup({ GITHUB_REPOSITORY: "" });
    await runAction({ env: noRepo.env, log: noRepo.log, fetchImpl: fakeGitHub().f });
    expect(noRepo.logs.join("\n")).toContain("GITHUB_REPOSITORY not set");
  });

  it("comment: changes → does not create a comment for a no-op plan", async () => {
    const s = setup({ INPUT_PLAN: "envs/dev/plan.json", INPUT_COMMENT: "changes", "INPUT_STEP-SUMMARY": "false" });
    const gh = fakeGitHub();
    expect(await runAction({ env: s.env, log: s.log, fetchImpl: gh.f })).toBe(0);
    expect(gh.calls.map((c) => c.method)).toEqual(["GET"]);
    expect(s.summary()).toBe("");
  });

  it("validates inputs", async () => {
    const cases: Array<[Record<string, string>, RegExp]> = [
      [{ INPUT_PLAN: "" }, /`plan` input is required/],
      [{ "INPUT_FAIL-ON": "panic" }, /fail-on must be/],
      [{ INPUT_AI: "gpt" }, /ai must be/],
      [{ INPUT_PLAN: "nope/*.json" }, /no plan files matched/],
      [{ INPUT_PLAN: "missing.json" }, /not found/],
    ];
    for (const [over, re] of cases) {
      const s = setup(over);
      expect(await runAction({ env: s.env, log: s.log })).toBe(2);
      expect(s.logs.join("\n")).toMatch(re);
    }
  });
});

describe("github client", () => {
  it("paginates when searching for the marker", async () => {
    const gh = fakeGitHub({ pages: 3, existing: [{ id: 5, body: "<!-- planlens:x -->" }] });
    const c = await findComment({ apiUrl: "https://api.github.com/", token: "t", repo: "a/b", fetchImpl: gh.f }, 1, "planlens:x");
    expect(c?.id).toBe(5);
    expect(gh.calls).toHaveLength(3);
  });
  it("skips creation when asked", async () => {
    const gh = fakeGitHub();
    expect(
      await upsertComment({ apiUrl: "https://api.github.com", token: "t", repo: "a/b", fetchImpl: gh.f }, 1, "m", "body", { createIfMissing: false }),
    ).toBe("skipped");
  });
});
