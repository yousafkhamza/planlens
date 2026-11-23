import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { EXIT, HELP, type Io, main } from "../src/cli.js";
import { VERSION } from "../src/version.js";
import { FIXTURES } from "./helpers.js";

function io(over: Partial<Io> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const i: Io = { stdout: (s) => out.push(s), stderr: (s) => err.push(s), isTTY: false, env: {}, cwd: FIXTURES, ...over };
  return { io: i, out: () => out.join(""), err: () => err.join("") };
}

const AWS = "real/aws-create.json";
const NOOP = "real/noop.json";

describe("cli", () => {
  it("prints help and version", async () => {
    const h = io();
    expect(await main(["--help"], h.io)).toBe(EXIT.OK);
    expect(h.out()).toBe(HELP);
    const v = io();
    expect(await main(["--version"], v.io)).toBe(EXIT.OK);
    expect(v.out().trim()).toBe(VERSION);
  });

  it("exits 1 when the gate fails and 0 when it passes", async () => {
    const a = io();
    expect(await main([AWS], a.io)).toBe(EXIT.GATE_FAILED);
    expect(a.out()).toContain("Gate failed");
    expect(await main([NOOP], io().io)).toBe(EXIT.OK);
    expect(await main([AWS, "--fail-on", "none"], io().io)).toBe(EXIT.OK);
  });

  it("emits every format", async () => {
    for (const [fmt, check] of [
      ["markdown", (s: string) => s.includes("## 🔴 planlens")],
      ["json", (s: string) => JSON.parse(s).schemaVersion === 1],
      ["sarif", (s: string) => JSON.parse(s).version === "2.1.0"],
      ["text", (s: string) => s.includes("Risk 100/100")],
    ] as const) {
      const r = io();
      await main([AWS, "-f", fmt], r.io);
      expect(check(r.out()), fmt).toBe(true);
    }
  });

  it("writes --output and repeated --out files; summary goes to stderr", async () => {
    const d = mkdtempSync(join(tmpdir(), "planlens-cli-"));
    const r = io();
    const code = await main(
      [AWS, "-f", "json", "-o", join(d, "r.json"), "--out", `sarif=${join(d, "s", "r.sarif")}`, "--out", `markdown=${join(d, "c.md")}`],
      r.io,
    );
    expect(code).toBe(EXIT.GATE_FAILED);
    expect(JSON.parse(readFileSync(join(d, "r.json"), "utf8")).reports).toHaveLength(1);
    expect(existsSync(join(d, "s", "r.sarif"))).toBe(true);
    expect(readFileSync(join(d, "c.md"), "utf8")).toContain("planlens");
    expect(r.out()).toBe("");
    expect(r.err()).toContain("Gate failed");
  });

  it("supports --quiet, --verbose, colors, NO_COLOR and --name", async () => {
    const q = io();
    await main([AWS, "-q"], q.io);
    expect(q.out()).toBe("");
    const c = io({ isTTY: true });
    await main([NOOP], c.io);
    expect(c.out()).toContain("\u001b[");
    const nc = io({ isTTY: true, env: { NO_COLOR: "1" } });
    await main([NOOP, "--name", "prod"], nc.io);
    expect(nc.out()).not.toContain("\u001b[");
    expect(nc.out()).toContain("prod");
    const v = io();
    await main(["real/lifecycle.json", "-v"], v.io);
    expect(v.out()).toContain("Changes:");
  });

  it("analyzes multiple plans with a combined gate", async () => {
    const r = io();
    expect(await main([NOOP, AWS, "-f", "json"], r.io)).toBe(EXIT.GATE_FAILED);
    expect(JSON.parse(r.out()).reports.map((x: { name: string }) => x.name)).toEqual(["real/noop.json", "real/aws-create.json"]);
  });

  it("lists rules in text, json and markdown", async () => {
    const t = io();
    await main(["--list-rules"], t.io);
    expect(t.out()).toMatch(/^PL001 {2}critical/);
    const j = io();
    await main(["--list-rules", "-f", "json"], j.io);
    expect(JSON.parse(j.out()).length).toBeGreaterThan(35);
    const m = io();
    await main(["--list-rules", "-f", "markdown"], m.io);
    expect(m.out()).toContain("| PL306 | critical | iam |");
  });

  it("applies a config file", async () => {
    const d = mkdtempSync(join(tmpdir(), "planlens-cfg-"));
    writeFileSync(join(d, "cfg.yml"), "fail_on: none\n");
    expect(await main([AWS, "-c", join(d, "cfg.yml")], io().io)).toBe(EXIT.OK);
  });

  it.each([
    [["--bogus"], /Unknown option/],
    [[], /no plan given/],
    [[AWS, "-f", "xml"], /--format must be/],
    [[AWS, "--fail-on", "severe"], /--fail-on must be/],
    [[AWS, "--ai", "skynet"], /--ai must be/],
    [[AWS, "--out", "pdf=x"], /--out expects/],
    [["missing.json"], /not found/],
    [[AWS, "-c", "missing.yml"], /Config file not found/],
  ])("exits 2 on usage/input errors: %j", async (args, re) => {
    const r = io();
    expect(await main(args as string[], r.io)).toBe(EXIT.ERROR);
    expect(r.err()).toMatch(re);
  });

  it("reports invalid configs with every problem", async () => {
    const d = mkdtempSync(join(tmpdir(), "planlens-cfg-"));
    writeFileSync(join(d, "cfg.yml"), "fail_on: x\ntypo: 1\n");
    const r = io();
    expect(await main([AWS, "-c", join(d, "cfg.yml")], r.io)).toBe(EXIT.ERROR);
    expect(r.err()).toContain("fail_on must be");
    expect(r.err()).toContain("unknown key `typo`");
  });
});

describe("cli --infracost", () => {
  const plan = "../../docs/samples/prod-change.json";
  it("adds the cost delta and gates on cost thresholds", async () => {
    const d = mkdtempSync(join(tmpdir(), "planlens-cost-"));
    writeFileSync(join(d, "cfg.yml"), "fail_on: high\ndisable: [PL001, PL002, PL003, PL006, PL101, PL110, PL201, PL306]\ncost:\n  max_monthly_increase: 100\n");
    const r = io();
    const code = await main([plan, "--infracost", "infracost/prod-change.json", "-c", join(d, "cfg.yml"), "-f", "markdown"], r.io);
    expect(r.out()).toContain("+$412.30/mo");
    expect(r.out()).toContain("`PL501`");
    expect(code).toBe(EXIT.GATE_FAILED);
  });
  it.each([
    [[plan, "--infracost", "missing.json"], /Infracost file not found/],
    [[plan, "--infracost", "real/noop.json"], /does not look like Infracost/],
    [[plan, AWS, "--infracost", "infracost/prod-change.json"], /single plan/],
  ])("rejects bad input: %j", async (args, re) => {
    const r = io();
    expect(await main(args as string[], r.io)).toBe(EXIT.ERROR);
    expect(r.err()).toMatch(re);
  });
});

describe("cli — user sample (single EC2)", () => {
  it("passes without cost, shows cost with a matching estimate, explains a swapped file", async () => {
    const a = io();
    expect(await main(["user/single-ec2.json"], a.io)).toBe(EXIT.OK);
    expect(a.out()).not.toContain("Cost");
    const b = io();
    expect(await main(["user/single-ec2.json", "--infracost", "infracost/single-ec2.json"], b.io)).toBe(EXIT.OK);
    expect(b.out()).toContain("Cost $31.17/mo +$31.17/mo (Infracost)");
    const c = io();
    expect(await main(["infracost/single-ec2.json"], c.io)).toBe(EXIT.ERROR);
    expect(c.err()).toMatch(/This is Infracost output, not a Terraform plan/);
    const d = io();
    await main(["user/single-ec2.json", "--infracost", "infracost/prod-change.json"], d.io);
    expect(d.out()).toMatch(/does not mention any resource in this plan/);
  });
});
