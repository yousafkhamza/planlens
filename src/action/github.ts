/** Minimal GitHub REST client (no dependencies) for the sticky PR comment. */

export interface GitHubContext {
  apiUrl: string;
  token: string;
  repo: string; // owner/name
  fetchImpl?: typeof fetch;
}

export class GitHubError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "GitHubError";
  }
}

async function gh<T>(ctx: GitHubContext, method: string, path: string, body?: unknown): Promise<T> {
  const f = ctx.fetchImpl ?? fetch;
  const res = await f(`${ctx.apiUrl.replace(/\/$/, "")}${path}`, {
    method,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${ctx.token}`,
      "x-github-api-version": "2022-11-28",
      "user-agent": "planlens-action",
      ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new GitHubError(`GitHub API ${method} ${path} → ${res.status} ${text.slice(0, 200)}`, res.status);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

interface Comment {
  id: number;
  body?: string;
}

export async function findComment(ctx: GitHubContext, pr: number, marker: string): Promise<Comment | undefined> {
  const needle = `<!-- ${marker} -->`;
  for (let page = 1; page <= 30; page++) {
    const list = await gh<Comment[]>(ctx, "GET", `/repos/${ctx.repo}/issues/${pr}/comments?per_page=100&page=${page}`);
    const hit = list.find((c) => c.body?.includes(needle));
    if (hit) return hit;
    if (list.length < 100) return undefined;
  }
  return undefined;
}

/** Create or update the single planlens comment for this PR + marker. */
export async function upsertComment(
  ctx: GitHubContext,
  pr: number,
  marker: string,
  body: string,
  opts: { createIfMissing: boolean },
): Promise<"created" | "updated" | "skipped"> {
  const existing = await findComment(ctx, pr, marker);
  if (existing) {
    await gh(ctx, "PATCH", `/repos/${ctx.repo}/issues/comments/${existing.id}`, { body });
    return "updated";
  }
  if (!opts.createIfMissing) return "skipped";
  await gh(ctx, "POST", `/repos/${ctx.repo}/issues/${pr}/comments`, { body });
  return "created";
}
