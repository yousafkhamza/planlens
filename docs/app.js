// planlens web UI. All analysis happens locally via window.PlanLens.
// Security: plan content is untrusted — it is only ever inserted with
// textContent / createTextNode, never innerHTML.
(() => {
  "use strict";
  const PL = window.PlanLens;
  const $ = (sel) => document.querySelector(sel);
  const SEV = ["critical", "high", "medium", "low", "info"];
  const MAX_BYTES = 200 * 1024 * 1024;

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return node;
  }

  /** Render `code` and **bold** spans from finding text safely. */
  function rich(text) {
    const frag = document.createDocumentFragment();
    const parts = String(text).split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
    for (const p of parts) {
      if (!p) continue;
      if (p.startsWith("`") && p.endsWith("`") && p.length > 1) frag.append(el("code", { text: p.slice(1, -1) }));
      else if (p.startsWith("**") && p.endsWith("**")) frag.append(el("strong", { text: p.slice(2, -2) }));
      else frag.append(document.createTextNode(p));
    }
    return frag;
  }

  /** Detail lines may contain a fenced code block (e.g. a suggested `moved` block). */
  function detail(text) {
    const m = /^([\s\S]*?)```\w*\n([\s\S]*?)\n```\s*$/.exec(text);
    if (!m) return el("li", {}, rich(text));
    return el("li", {}, rich(m[1].trim()), el("pre", {}, el("code", { text: m[2] })));
  }

  function download(name, content, type) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const a = el("a", { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function copy(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
      const old = btn.textContent;
      btn.textContent = "Copied ✓";
      setTimeout(() => (btn.textContent = old), 1400);
    } catch {
      btn.textContent = "Copy failed";
    }
  }

  // ---------------------------------------------------------------- theme
  const root = document.documentElement;
  try {
    const saved = localStorage.getItem("planlens-theme");
    if (saved === "dark" || saved === "light") root.dataset.theme = saved;
  } catch {}
  $("#theme").addEventListener("click", () => {
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try {
      localStorage.setItem("planlens-theme", root.dataset.theme);
    } catch {}
  });

  $("#ver").textContent = `v${PL.VERSION}`;

  // ---------------------------------------------------------------- analyzer
  const paste = $("#paste");
  const errorBox = $("#error");
  const result = $("#result");
  let currentName = "plan.json";

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = false;
  }

  function ring(score, level) {
    const r = 42;
    const c = 2 * Math.PI * r;
    const color = getComputedStyle(root).getPropertyValue(level === "none" ? "--ok" : `--${level}`).trim() || "#888";
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("viewBox", "0 0 96 96");
    svg.setAttribute("width", "96");
    svg.setAttribute("height", "96");
    const track = document.createElementNS(svgNS, "circle");
    for (const [k, v] of Object.entries({ cx: 48, cy: 48, r, fill: "none", "stroke-width": 9, class: "track" })) track.setAttribute(k, String(v));
    const bar = document.createElementNS(svgNS, "circle");
    for (const [k, v] of Object.entries({ cx: 48, cy: 48, r, fill: "none", "stroke-width": 9, stroke: color, "stroke-linecap": "round", "stroke-dasharray": `${(score / 100) * c} ${c}` }))
      bar.setAttribute(k, String(v));
    svg.append(track, bar);
    return el("div", { class: "ring", role: "img", "aria-label": `Risk score ${score} out of 100` }, svg, el("div", { class: "ring-label" }, el("div", {}, el("b", { text: String(score) }), el("span", { text: "/ 100" }))));
  }

  function renderReport(report) {
    result.replaceChildren();
    const s = report.summary;
    const levelLabel = report.level === "none" ? "NO RISK FOUND" : report.level.toUpperCase();

    result.append(
      el(
        "div",
        { class: "r-head" },
        ring(report.score, report.level),
        el(
          "div",
          { class: "r-title" },
          el("h3", {}, el("span", { class: `sev sev-${report.level}`, text: levelLabel }), report.name),
          el("div", { class: `gate ${report.passed ? "pass" : "fail"}`, text: report.passed ? `✓ Gate passed (fail-on: ${report.failOn})` : `✗ Gate failed (fail-on: ${report.failOn})` }),
          el("div", { class: "muted small", text: `Terraform ${report.terraformVersion} · ${report.findings.length} finding(s)${report.suppressed.length ? ` · ${report.suppressed.length} accepted` : ""}` }),
        ),
      ),
    );

    const counts = [
      ["Create", s.create],
      ["Update", s.update],
      ["Replace", s.replace, true],
      ["Destroy", s.delete, true],
      ["Import", s.imported],
      ["Move", s.moved],
      ["Drift", s.drifted],
    ];
    result.append(el("div", { class: "counts" }, counts.map(([label, n, hot]) => el("div", { class: `count${hot && n > 0 ? " hot" : ""}` }, el("b", { text: String(n) }), el("span", { text: label })))));

    const actions = el("div", { class: "r-actions" });
    const mdBtn = el("button", { class: "btn btn-ghost", type: "button", text: "Copy PR comment (Markdown)" });
    mdBtn.addEventListener("click", () => copy(PL.renderMarkdown([report]), mdBtn));
    actions.append(
      mdBtn,
      el("button", { class: "btn btn-ghost", type: "button", text: "Download SARIF", onclick: () => download("planlens.sarif", PL.renderSarif([report]), "application/sarif+json") }),
      el("button", { class: "btn btn-ghost", type: "button", text: "Download JSON", onclick: () => download("planlens.json", JSON.stringify(report, null, 2), "application/json") }),
    );
    result.append(actions);

    for (const w of report.warnings) result.append(el("div", { class: "warn" }, "⚠️ ", rich(w)));

    if (report.findings.length === 0) {
      result.append(el("div", { class: "clean", text: s.total === 0 ? "✓ No changes — infrastructure matches the configuration." : "✓ No risky changes found." }));
    }

    for (const sev of SEV) {
      const group = report.findings.filter((f) => f.severity === sev);
      if (!group.length) continue;
      result.append(el("p", { class: "group-title", text: `${sev} (${group.length})` }));
      const list = el("div", { class: "findings" });
      for (const f of group) {
        const body = el("div", { class: "body" });
        if (f.details.length) body.append(el("ul", {}, f.details.map(detail)));
        if (f.remediation) body.append(el("p", { class: "fix" }, el("strong", { text: "Fix: " }), rich(f.remediation)));
        list.append(
          el(
            "details",
            { class: `finding ${f.severity}`, open: sev === "critical" ? true : undefined },
            el("summary", {}, el("span", { class: `sev sev-${f.severity}`, text: f.severity.toUpperCase() }), el("span", { class: "rid", text: `${f.ruleId} · ${f.title}` }), el("span", { class: "msg" }, rich(f.message))),
            body,
          ),
        );
      }
      result.append(list);
    }

    if (report.suppressed.length) {
      result.append(el("p", { class: "group-title", text: `accepted risks (${report.suppressed.length})` }));
      result.append(
        el(
          "div",
          { class: "findings" },
          report.suppressed.map((f) =>
            el(
              "details",
              { class: "finding info" },
              el("summary", {}, el("span", { class: "sev sev-info", text: "ACCEPTED" }), el("span", { class: "rid", text: f.ruleId }), el("span", { class: "msg" }, rich(f.message))),
              el("div", { class: "body", text: `Reason: ${f.suppressed.reason}${f.suppressed.expires ? ` (until ${f.suppressed.expires})` : ""}` }),
            ),
          ),
        ),
      );
    }

    if (report.changes.length) {
      const rows = report.changes.map((c) => {
        const extra = c.kind === "replace" && c.replacePaths.length ? ` — forced by ${c.replacePaths.slice(0, 3).join(", ")}` : c.kind === "update" && c.changedPaths.length ? ` — ${c.changedPaths.slice(0, 4).join(", ")}` : "";
        return el("tr", {}, el("td", { class: `kind-${c.kind}`, text: c.kind }), el("td", {}, el("code", { text: c.address }), extra));
      });
      result.append(el("details", { class: "changes" }, el("summary", { text: `All changes (${report.changes.length})` }), el("table", {}, el("tbody", {}, rows))));
    }
  }

  function run() {
    errorBox.hidden = true;
    const text = paste.value.trim();
    if (!text) return showError("Paste a plan, drop a file, or pick a sample first.");
    let config = {};
    try {
      config = PL.parseConfigText($("#config").value);
    } catch (e) {
      return showError(e.message);
    }
    try {
      const plan = PL.parsePlanText(text);
      const report = PL.analyzePlan(plan, { config, failOn: $("#failon").value, name: currentName });
      renderReport(report);
      if (window.matchMedia("(max-width: 960px)").matches) result.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      showError(e.message || String(e));
    }
  }

  function loadText(text, name) {
    paste.value = text;
    currentName = name;
    run();
  }

  async function loadSample(name, btn) {
    document.querySelectorAll("[data-sample]").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
    try {
      const res = await fetch(`samples/${name}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      loadText(await res.text(), name);
    } catch (e) {
      showError(`Could not load sample: ${e.message}`);
    }
  }

  function readFile(file) {
    if (!file) return;
    if (file.size > MAX_BYTES) return showError("That file is larger than 200 MB — use the CLI for very large plans.");
    const reader = new FileReader();
    reader.onload = () => loadText(String(reader.result), file.name);
    reader.onerror = () => showError("Could not read the file.");
    reader.readAsText(file);
  }

  document.querySelectorAll("[data-sample]").forEach((b) => b.addEventListener("click", () => loadSample(b.dataset.sample, b)));
  $("#run").addEventListener("click", () => {
    currentName = currentName || "plan.json";
    run();
  });
  $("#clear").addEventListener("click", () => {
    paste.value = "";
    errorBox.hidden = true;
    currentName = "plan.json";
    document.querySelectorAll("[data-sample]").forEach((b) => b.setAttribute("aria-pressed", "false"));
    result.replaceChildren(el("div", { class: "empty" }, el("p", { text: "Load a sample or drop your own plan to see the review." })));
  });
  paste.addEventListener("input", () => (currentName = "pasted plan"));
  $("#failon").addEventListener("change", () => paste.value.trim() && run());
  $("#file").addEventListener("change", (e) => readFile(e.target.files[0]));

  const drop = $("#drop");
  ["dragenter", "dragover"].forEach((t) =>
    drop.addEventListener(t, (e) => {
      e.preventDefault();
      drop.classList.add("over");
    }),
  );
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, () => drop.classList.remove("over")));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    readFile(e.dataTransfer.files[0]);
  });
  // Allow dropping anywhere on the analyzer without the browser opening the file.
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());

  // ---------------------------------------------------------------- rules
  const grid = $("#rule-grid");
  const search = $("#rule-search");
  const cat = $("#rule-cat");
  [...new Set(PL.RULES.map((r) => r.category))].sort().forEach((c) => cat.append(el("option", { value: c, text: c })));
  function renderRules() {
    const q = search.value.trim().toLowerCase();
    const c = cat.value;
    const list = PL.RULES.filter((r) => (!c || r.category === c) && (!q || `${r.id} ${r.title} ${r.description} ${r.category}`.toLowerCase().includes(q)));
    grid.replaceChildren(
      ...list.map((r) =>
        el(
          "article",
          { class: "rule" },
          el("header", {}, el("span", { class: `sev sev-${r.severity}`, text: r.severity.toUpperCase() }), el("span", { class: "cat", text: r.category }), el("span", { class: "rid", text: r.id })),
          el("h3", { text: r.title }),
          el("p", {}, rich(r.description)),
        ),
      ),
    );
    if (!list.length) grid.append(el("p", { class: "muted", text: "No rules match." }));
  }
  search.addEventListener("input", renderRules);
  cat.addEventListener("change", renderRules);
  renderRules();

  // ---------------------------------------------------------------- tabs + copy
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  function select(tab) {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    }
  }
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => select(t));
    t.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
      select(next);
      next.focus();
    });
  });
  document.querySelectorAll(".code .copy").forEach((b) => b.addEventListener("click", () => copy(b.parentElement.querySelector("code").textContent, b)));
})();
