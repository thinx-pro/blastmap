import { summarize } from "./rules.js";

const AREA_LABEL = {
  agent: "Agent permissions",
  cloud: "Cloud & clusters",
  publish: "Publish & code hosting",
  host: "This machine",
  files: "Files that deletes reach",
  data: "Secrets & databases",
};

export function renderText(findings, { color = true, version = "" } = {}) {
  const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const sev = {
    high: (s) => c("1;31", s),
    medium: (s) => c("33", s),
    info: (s) => c("2", s),
  };
  const tag = { high: "HIGH", medium: "MED ", info: "info" };
  const { counts, could } = summarize(findings);
  const lines = [];
  lines.push(c("1", `blastmap${version ? " " + version : ""}`) + c("2", " — what an agent started from this shell could reach"));
  lines.push("");
  lines.push(`  ${sev.high(counts.high + " high")}   ${sev.medium(counts.medium + " medium")}   ${sev.info(counts.info + " info")}`);
  lines.push("");
  if (could.length) {
    lines.push(c("1", "An agent running here could:"));
    for (const x of could) lines.push(`  ${x.severity === "high" ? sev.high("●") : sev.medium("●")} ${x.text}`);
    lines.push("");
  } else {
    lines.push(c("32", "Nothing high or medium found. Nice and small."));
    lines.push("");
  }
  const byArea = new Map();
  for (const f of findings) {
    if (!byArea.has(f.area)) byArea.set(f.area, []);
    byArea.get(f.area).push(f);
  }
  for (const area of Object.keys(AREA_LABEL)) {
    const list = byArea.get(area);
    if (!list || !list.length) continue;
    lines.push(c("1;4", AREA_LABEL[area]));
    for (const f of list) {
      lines.push(`  ${sev[f.severity](tag[f.severity])}  ${f.title}`);
      if (f.detail) lines.push(c("2", `        ${f.detail}`));
      if (f.fix && f.severity !== "info") lines.push(`        ${c("36", "fix:")} ${f.fix}`);
    }
    lines.push("");
  }
  lines.push(c("2", "Read-only scan. Secret values are never read out; paths under your home show as ~, emails as <email>."));
  return lines.join("\n");
}

export function renderMarkdown(findings, { version = "" } = {}) {
  const { counts, could } = summarize(findings);
  const md = [];
  md.push(`### blastmap${version ? " " + version : ""}: ${counts.high} high · ${counts.medium} medium · ${counts.info} info`);
  md.push("");
  if (could.length) {
    md.push("**An agent running here could:**");
    md.push("");
    for (const x of could) md.push(`- ${x.severity === "high" ? "🔴" : "🟠"} ${x.text}`);
    md.push("");
  }
  md.push("| Severity | Area | Finding | Fix |");
  md.push("|---|---|---|---|");
  const esc = (s) => String(s || "").replace(/\|/g, "\\|").replace(/\n/g, " ");
  for (const f of findings) {
    md.push(`| ${f.severity} | ${AREA_LABEL[f.area] || f.area} | ${esc(f.title)}${f.detail ? `<br><sub>${esc(f.detail)}</sub>` : ""} | ${f.severity === "info" ? "" : esc(f.fix)} |`);
  }
  return md.join("\n");
}

export function renderJson(findings, { version = "" } = {}) {
  const { counts, could } = summarize(findings);
  return JSON.stringify({ tool: "blastmap", version, counts, could: could.map((x) => x.text), findings }, null, 2);
}
