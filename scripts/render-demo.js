// Renders blastmap's real output against the fake demo home (scripts/demo-home.js)
// as a terminal-styled HTML page, used to make assets/demo.png with headless Chrome.
// Usage: node scripts/render-demo.js <out.html> [--markdown <out.md>]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { makeContext, collectAll } from "../src/collect.js";
import { renderText, renderMarkdown } from "../src/report.js";
import { buildDemoHome, DEMO_GH_STATUS, DEMO_MOUNT } from "./demo-home.js";

const out = process.argv[2];
if (!out) { console.error("usage: node scripts/render-demo.js <out.html>"); process.exit(2); }
const home = fs.mkdtempSync(path.join(os.tmpdir(), "blastmap-demo-"));
buildDemoHome(home);
const ctx = makeContext({
  home,
  cwd: path.join(home, "project"),
  env: { HOME: home, AWS_PROFILE: "acme-prod", OPENAI_API_KEY: "demo", PATH: "/bin" },
  platform: "darwin",
  exec: (cmd) => {
    if (cmd === "gh") return { code: 0, stdout: "", stderr: DEMO_GH_STATUS };
    if (cmd === "mount") return { code: 0, stdout: DEMO_MOUNT, stderr: "" };
    if (cmd === "sudo") return { code: 1, stdout: "", stderr: "" };
    return null;
  },
  writable: (p) => p.startsWith("/Volumes/"),
});
const findings = collectAll(ctx);
const version = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const text = renderText(findings, { color: true, version });

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const styles = { "1": "font-weight:700", "2": "opacity:.6", "4": "text-decoration:underline", "31": "color:#ff6b6b", "32": "color:#7ee787", "33": "color:#f2cc60", "36": "color:#79c0ff" };
let html = "";
let open = 0;
for (const part of text.split(/(\x1b\[[0-9;]*m)/)) {
  const m = /^\x1b\[([0-9;]*)m$/.exec(part);
  if (!m) { html += esc(part); continue; }
  if (m[1] === "0") { html += "</span>".repeat(open); open = 0; continue; }
  html += `<span style="${m[1].split(";").map((c) => styles[c] || "").join(";")}">`;
  open++;
}
html += "</span>".repeat(open);
const page = `<!doctype html><html><head><meta charset="utf-8"><style>
body{margin:0;background:#0d1117;font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;color:#e6edf3}
.win{margin:18px;border-radius:10px;background:#161b22;box-shadow:0 8px 30px #0008;overflow:hidden}
.bar{height:30px;background:#21262d;display:flex;align-items:center;padding:0 12px;gap:7px}
.bar i{width:12px;height:12px;border-radius:50%;display:inline-block}
.bar b{margin-left:10px;font-weight:400;color:#8b949e;font-size:12px}
pre{margin:0;padding:14px 18px 18px;white-space:pre-wrap}
</style></head><body><div class="win"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i><b>~/project — npx github:thinx-pro/blastmap   (demo home, fake credentials)</b></div><pre><span style="color:#7ee787">$</span> npx github:thinx-pro/blastmap\n${html}</pre></div></body></html>`;
fs.writeFileSync(out, page);
const mdi = process.argv.indexOf("--markdown");
if (mdi > 0) fs.writeFileSync(process.argv[mdi + 1], renderMarkdown(findings, { version }) + "\n");
console.log(`${out} (${findings.length} findings)`);
