#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { makeContext, collectAll, AREAS } from "../src/collect.js";
import { renderText, renderMarkdown, renderJson } from "../src/report.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const VERSION = JSON.parse(readFileSync(path.join(here, "..", "package.json"), "utf8")).version;

const HELP = `blastmap ${VERSION}
What could a coding agent started from this shell delete, publish or change?
Read-only: checks agent permission settings, logged-in cloud/cluster CLIs,
publish tokens, SSH keys, Docker socket, sudo, mounted shares, cloud-synced
folders and secret-looking env vars. Values are never printed.

Usage: blastmap [options]

Options:
  --json            Machine-readable output (for agents and scripts)
  --markdown        Markdown table (paste into an issue or a PR)
  --only AREAS      Comma-separated: ${Object.keys(AREAS).join(",")}
  --cwd DIR         Project directory to check (default: current directory)
  --no-exec         Skip checks that run commands (gh, ssh-add, sudo -n, mount, tmutil)
  --strict          Exit 1 if any high finding (use in a pre-flight hook)
  --no-color        Plain text
  -v, --version     Print version
  -h, --help        Show this help
`;

function parseArgs(argv) {
  const o = { format: "text", only: null, cwd: null, noExec: false, strict: false, color: process.stdout.isTTY && !process.env.NO_COLOR };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") o.help = true;
    else if (a === "-v" || a === "--version") o.version = true;
    else if (a === "--json") o.format = "json";
    else if (a === "--markdown" || a === "--md") o.format = "markdown";
    else if (a === "--only") o.only = String(argv[++i] || "").split(",").map((s) => s.trim()).filter(Boolean);
    else if (a.startsWith("--only=")) o.only = a.slice(7).split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--cwd") o.cwd = argv[++i];
    else if (a === "--no-exec") o.noExec = true;
    else if (a === "--strict") o.strict = true;
    else if (a === "--no-color") o.color = false;
    else { o.error = `unknown option: ${a}`; }
  }
  if (o.only) {
    const bad = o.only.filter((x) => !AREAS[x]);
    if (bad.length) o.error = `unknown area(s): ${bad.join(", ")}`;
  }
  return o;
}

const o = parseArgs(process.argv.slice(2));
if (o.help) { process.stdout.write(HELP); process.exit(0); }
if (o.version) { console.log(VERSION); process.exit(0); }
if (o.error) { console.error(`blastmap: ${o.error}\n`); process.stderr.write(HELP); process.exit(2); }

const ctx = makeContext({ cwd: o.cwd ? path.resolve(o.cwd) : undefined, noExec: o.noExec });
const findings = collectAll(ctx, o.only);
if (o.format === "json") console.log(renderJson(findings, { version: VERSION }));
else if (o.format === "markdown") console.log(renderMarkdown(findings, { version: VERSION }));
else console.log(renderText(findings, { color: o.color, version: VERSION }));
if (o.strict && findings.some((f) => f.severity === "high")) process.exit(1);
