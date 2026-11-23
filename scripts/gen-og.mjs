// Renders the social share images (Open Graph / LinkedIn / X and the GitHub
// social preview) from an SVG template, using the same fonts as the site.
//   docs/assets/og.png             1200×630  (og:image, twitter:image, LinkedIn)
//   docs/assets/github-social.png  1280×640  (repo Settings → Social preview)
// Run: node scripts/gen-og.mjs   (downloads Inter / JetBrains Mono once into a temp cache)
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Resvg } from "@resvg/resvg-js";

const root = fileURLToPath(new URL("..", import.meta.url));
const cache = join(tmpdir(), "planlens-og-fonts");
mkdirSync(cache, { recursive: true });

const FONTS = {
  "inter-400.ttf": "https://cdn.jsdelivr.net/fontsource/fonts/inter@latest/latin-400-normal.ttf",
  "inter-600.ttf": "https://cdn.jsdelivr.net/fontsource/fonts/inter@latest/latin-600-normal.ttf",
  "inter-800.ttf": "https://cdn.jsdelivr.net/fontsource/fonts/inter@latest/latin-800-normal.ttf",
  "jbmono-500.ttf": "https://cdn.jsdelivr.net/fontsource/fonts/jetbrains-mono@latest/latin-500-normal.ttf",
};
const fontFiles = [];
for (const [name, url] of Object.entries(FONTS)) {
  const path = join(cache, name);
  if (!existsSync(path)) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`font download failed: ${url} → ${res.status}`);
    writeFileSync(path, Buffer.from(await res.arrayBuffer()));
  }
  fontFiles.push(path);
}

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const ruleCount = (await import(new URL("../dist/index.mjs", import.meta.url).href)).RULES.length;

const SEV = { CRITICAL: "#f87171", HIGH: "#fb923c", MEDIUM: "#facc15" };
function row(y, sev, code, text) {
  const color = SEV[sev];
  const w = sev.length * 9.2 + 18;
  return `
    <rect x="688" y="${y - 18}" width="${w}" height="26" rx="6" fill="${color}"/>
    <text x="${688 + w / 2}" y="${y}" font-family="Inter" font-weight="800" font-size="13" fill="#0b0f17" text-anchor="middle" letter-spacing="0.6">${sev}</text>
    <text x="${688 + w + 12}" y="${y}" font-family="JetBrains Mono" font-weight="500" font-size="15" fill="#e6ebf5">${esc(code)}</text>
    <text x="688" y="${y + 26}" font-family="Inter" font-weight="400" font-size="15" fill="#93a0b8">${esc(text)}</text>`;
}

/** Pills laid out left→right using an approximate Inter 600/16px advance width. */
function pills(labels, x0, y) {
  let x = x0;
  return labels
    .map((t) => {
      const w = Math.round(t.length * 8.7 + 30);
      const out = `<rect x="${x}" y="${y}" width="${w}" height="36" rx="18" fill="#121a28" stroke="#243049"/><text x="${x + w / 2}" y="${y + 24}" font-family="Inter" font-weight="600" font-size="16" fill="#cbd5e1" text-anchor="middle">${esc(t)}</text>`;
      x += w + 10;
      return out;
    })
    .join("\n    ");
}

/** 1200×630 design; `w`/`h` > design size centers it on an extended background. */
function svg(w = 1200, h = 630) {
  const dx = (w - 1200) / 2;
  const dy = (h - 630) / 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
  <defs>
    <radialGradient id="g1" cx="0.88" cy="0" r="0.75"><stop offset="0" stop-color="#a78bfa" stop-opacity="0.35"/><stop offset="1" stop-color="#a78bfa" stop-opacity="0"/></radialGradient>
    <radialGradient id="g2" cx="0" cy="0.15" r="0.7"><stop offset="0" stop-color="#38bdf8" stop-opacity="0.28"/><stop offset="1" stop-color="#38bdf8" stop-opacity="0"/></radialGradient>
    <linearGradient id="hl" x1="0" x2="1"><stop offset="0" stop-color="#38bdf8"/><stop offset="1" stop-color="#a78bfa"/></linearGradient>
    <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M40 0H0V40" fill="none" stroke="#ffffff" stroke-opacity="0.035"/></pattern>
  </defs>
  <rect width="${w}" height="${h}" fill="#0b0f17"/>
  <rect width="${w}" height="${h}" fill="url(#grid)"/>
  <rect width="${w}" height="${h}" fill="url(#g1)"/>
  <rect width="${w}" height="${h}" fill="url(#g2)"/>
  <g transform="translate(${dx} ${dy})">
    <!-- brand -->
    <rect x="64" y="56" width="52" height="52" rx="13" fill="#172133" stroke="#243049"/>
    <circle cx="87" cy="79" r="12" fill="none" stroke="#38bdf8" stroke-width="5"/>
    <path d="M96 88l11 11" stroke="#38bdf8" stroke-width="5" stroke-linecap="round"/>
    <text x="132" y="93" font-family="Inter" font-weight="800" font-size="34" fill="#e6ebf5">planlens</text>
    <rect x="292" y="68" width="${String(version).length * 9 + 26}" height="28" rx="14" fill="#172133" stroke="#243049"/>
    <text x="305" y="88" font-family="JetBrains Mono" font-weight="500" font-size="15" fill="#93a0b8">v${esc(version)}</text>

    <!-- headline -->
    <text font-family="Inter" font-weight="800" font-size="56" fill="#e6ebf5" letter-spacing="-1.5">
      <tspan x="64" y="206">Know what</tspan>
      <tspan x="64" y="272" font-family="JetBrains Mono" font-weight="500" font-size="48" fill="#38bdf8" letter-spacing="-1">terraform apply</tspan>
      <tspan x="64" y="338">will <tspan fill="url(#hl)">really</tspan> do.</tspan>
    </text>
    <text font-family="Inter" font-weight="400" font-size="21" fill="#93a0b8">
      <tspan x="64" y="392">Reviews the plan, not the code:</tspan>
      <tspan x="64" y="422">destroyed databases, forced replacements,</tspan>
      <tspan x="64" y="452">open ports, IAM widening &amp; cost.</tspan>
    </text>

    <!-- pills -->
    ${pills([`${ruleCount} rules`, "PR comment + SARIF", "Open source"], 64, 482)}

    <!-- PR card -->
    <rect x="664" y="140" width="472" height="372" rx="18" fill="#121a28" stroke="#243049"/>
    <rect x="664" y="140" width="472" height="44" rx="18" fill="#172133"/>
    <rect x="664" y="166" width="472" height="18" fill="#172133"/>
    <circle cx="690" cy="162" r="6" fill="#ef4444"/><circle cx="710" cy="162" r="6" fill="#eab308"/><circle cx="730" cy="162" r="6" fill="#22c55e"/>
    <text x="750" y="167" font-family="Inter" font-weight="400" font-size="14" fill="#93a0b8">github-actions commented · infra#482</text>
    <text x="688" y="224" font-family="Inter" font-weight="800" font-size="21" fill="#e6ebf5">Risk 99/100 · CRITICAL</text>
    <rect x="1010" y="204" width="104" height="28" rx="14" fill="#3b1218" stroke="#f87171" stroke-opacity="0.6"/>
    <text x="1062" y="223" font-family="Inter" font-weight="700" font-size="13" fill="#f87171" text-anchor="middle">Gate failed</text>
    <text x="688" y="250" font-family="Inter" font-weight="400" font-size="14" fill="#93a0b8">+$412.30/mo cost · 4 critical · 6 high</text>
    <line x1="688" y1="268" x2="1112" y2="268" stroke="#243049"/>
    ${row(300, "CRITICAL", "aws_db_instance.payments", "will be REPLACED, forced by storage_encrypted")}
    ${row(366, "CRITICAL", "aws_security_group.api", "0.0.0.0/0 on 5432 (PostgreSQL)")}
    ${row(432, "HIGH", "aws_s3_bucket.reports", "rename recreates it, add a moved block")}

    <!-- footer -->
    <line x1="64" y1="556" x2="1136" y2="556" stroke="#243049"/>
    <text x="64" y="590" font-family="JetBrains Mono" font-weight="500" font-size="18" fill="#38bdf8">yousafkhamza.github.io/planlens</text>
    <text x="1136" y="590" font-family="Inter" font-weight="600" font-size="17" fill="#93a0b8" text-anchor="end">GitHub Action · CLI · Docker · Web</text>
  </g>
</svg>`;
}

function render(w, h, out) {
  const png = new Resvg(svg(w, h), {
    fitTo: { mode: "width", value: w },
    font: { fontFiles, loadSystemFonts: false, defaultFontFamily: "Inter" },
    background: "#0b0f17",
  })
    .render()
    .asPng();
  writeFileSync(join(root, out), png);
  console.log(`✓ ${out} (${w}×${h}, ${Math.round(png.length / 1024)} KB)`);
}

render(1200, 630, "docs/assets/og.png");
render(1280, 640, "docs/assets/github-social.png");

// App icons (favicon SVG + PNGs for Apple touch / PWA / search result favicons)
const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#0b0f17"/><circle cx="28" cy="28" r="13" fill="none" stroke="#38bdf8" stroke-width="6"/><path d="M38 38l13 13" stroke="#38bdf8" stroke-width="6" stroke-linecap="round"/></svg>`;
writeFileSync(join(root, "docs/assets/icon.svg"), `${ICON_SVG}\n`);
for (const [size, out] of [
  [180, "docs/assets/apple-touch-icon.png"],
  [192, "docs/assets/icon-192.png"],
  [512, "docs/assets/icon-512.png"],
]) {
  writeFileSync(join(root, out), new Resvg(ICON_SVG, { fitTo: { mode: "width", value: size } }).render().asPng());
  console.log(`✓ ${out}`);
}
