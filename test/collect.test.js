import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { makeContext, collectAll } from "../src/collect.js";
import { renderText, renderMarkdown, renderJson } from "../src/report.js";
import { buildDemoHome, DEMO_GH_STATUS, DEMO_MOUNT } from "../scripts/demo-home.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function demo() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "blastmap-test-"));
  buildDemoHome(home);
  const calls = [];
  const exec = (cmd, args) => {
    calls.push([cmd, ...args].join(" "));
    if (cmd === "gh") return { code: 0, stdout: "", stderr: DEMO_GH_STATUS };
    if (cmd === "mount") return { code: 0, stdout: DEMO_MOUNT, stderr: "" };
    if (cmd === "sudo") return { code: 1, stdout: "", stderr: "a password is required" };
    return null;
  };
  const ctx = makeContext({
    home,
    cwd: path.join(home, "project"),
    env: { HOME: home, AWS_PROFILE: "acme-prod", OPENAI_API_KEY: "sk-demo", PATH: "/bin" },
    platform: "darwin",
    exec,
    writable: (p) => p.startsWith("/Volumes/"),
  });
  return { home, ctx, calls };
}

test("demo home: expected findings across all areas", () => {
  const { home, ctx, calls } = demo();
  const f = collectAll(ctx);
  const got = new Set(f.map((x) => x.id));
  for (const id of [
    "claude.bypass", "claude.allowRisky", "mcp.servers", "codex.yolo", "shell.yoloAlias",
    "aws.staticKeys", "aws.env", "kube.prod", "kube.currentProd",
    "gh.deleteRepo", "gh.repo", "npm.token",
    "ssh.unencrypted", "ssh.hosts",
    "mount.network", "mount.external", "sync.folders", "rclone.remotes",
    "env.secrets", "db.pgpass", "env.files",
  ]) assert.ok(got.has(id), `missing ${id}`);
  // gh pr view and npm run test are read-only/narrow: only git and rm -rf flagged
  assert.equal(f.filter((x) => x.id === "claude.allowRisky").length, 2);
  // exactly one of the two keys is unencrypted
  assert.match(f.find((x) => x.id === "ssh.unencrypted").title, /^1 SSH .*id_ed25519$/);
  // high severities
  assert.equal(f.find((x) => x.id === "aws.staticKeys").severity, "high"); // acme-prod
  assert.equal(f.find((x) => x.id === "db.pgpass").severity, "high");
  // findings are sorted high first
  const order = f.map((x) => x.severity);
  assert.deepEqual(order, [...order].sort((a, b) => ({ high: 0, medium: 1, info: 2 })[a] - ({ high: 0, medium: 1, info: 2 })[b]));
  // no absolute home path or demo secret values leak into any output
  for (const out of [renderText(f, { color: false }), renderMarkdown(f), renderJson(f)]) {
    assert.ok(!out.includes(home), "home path leaked");
    assert.ok(!out.includes("DEMO_NOT_A"), "credential value leaked");
    assert.ok(!out.includes("sk-demo"), "env value leaked");
    assert.ok(!out.includes("db.example.internal/app"), "db url leaked");
  }
  assert.ok(calls.includes("gh auth status"));
});

test("--no-exec runs no commands", () => {
  const { home } = demo();
  const calls = [];
  const ctx = makeContext({ home, cwd: home, env: {}, platform: "linux", noExec: true, exec: (c) => { calls.push(c); return null; } });
  collectAll(ctx);
  assert.deepEqual(calls, []);
});

test("--only limits areas", () => {
  const { ctx } = demo();
  const f = collectAll(ctx, ["agent"]);
  assert.ok(f.length > 0);
  assert.ok(f.every((x) => x.area === "agent"));
});

test("empty home produces no high findings", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "blastmap-empty-"));
  const ctx = makeContext({ home, cwd: home, env: {}, platform: "linux", noExec: true });
  assert.deepEqual(collectAll(ctx).filter((x) => x.severity !== "info"), []);
});

test("CLI: --help, --version, bad flag, --json against a demo HOME", () => {
  const bin = path.join(root, "bin", "blastmap.js");
  const help = spawnSync(process.execPath, [bin, "--help"], { encoding: "utf8" });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /Usage: blastmap/);
  const ver = spawnSync(process.execPath, [bin, "--version"], { encoding: "utf8" });
  assert.equal(ver.stdout.trim(), JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")).version);
  const bad = spawnSync(process.execPath, [bin, "--nope"], { encoding: "utf8" });
  assert.equal(bad.status, 2);
  const badArea = spawnSync(process.execPath, [bin, "--only", "agent,nope"], { encoding: "utf8" });
  assert.equal(badArea.status, 2);

  const { home } = demo();
  const r = spawnSync(process.execPath, [bin, "--json", "--no-exec", "--cwd", path.join(home, "project"), "--strict"], {
    encoding: "utf8",
    env: { HOME: home, PATH: process.env.PATH },
  });
  assert.equal(r.status, 1, r.stderr); // --strict with high findings
  const j = JSON.parse(r.stdout);
  assert.equal(j.tool, "blastmap");
  assert.ok(j.counts.high >= 3);
  assert.ok(j.could.length > 0);
  assert.ok(!r.stdout.includes(home));
});

test("docs/rules.js is identical to src/rules.js (web checker uses the same rules)", () => {
  const a = fs.readFileSync(path.join(root, "src", "rules.js"), "utf8");
  const b = fs.readFileSync(path.join(root, "docs", "rules.js"), "utf8");
  assert.equal(a, b, "run: npm run sync-docs");
});
