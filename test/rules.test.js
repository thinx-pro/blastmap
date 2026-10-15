import { test } from "node:test";
import assert from "node:assert/strict";
import * as R from "../src/rules.js";

const ids = (list) => list.map((f) => f.id);

test("bash rules: blanket, risky, read-only narrowing, exact", () => {
  assert.equal(R.bashRuleRisk(null).any, true);
  assert.equal(R.bashRuleRisk("*").any, true);
  assert.equal(R.bashRuleRisk(":*").any, true);
  const git = R.bashRuleRisk("git:*");
  assert.ok(git.hits.some((h) => h[0] === "git push"));
  assert.ok(git.hits.some((h) => h[0] === "git reset"));
  assert.ok(R.bashRuleRisk("git push origin *").hits.some((h) => h[0] === "git push"));
  assert.deepEqual(R.bashRuleRisk("git status:*").hits, []);
  assert.deepEqual(R.bashRuleRisk("gh search *").hits, []);
  assert.deepEqual(R.bashRuleRisk("gh pr view:*").hits, []);
  assert.ok(R.bashRuleRisk("gh pr merge:*").hits.length > 0);
  assert.deepEqual(R.bashRuleRisk("kubectl get *").hits, []);
  assert.ok(R.bashRuleRisk("kubectl delete *").hits.length > 0);
  assert.deepEqual(R.bashRuleRisk("npm run test:*").hits, []);
  assert.ok(R.bashRuleRisk("npm *").hits.some((h) => h[0] === "npm publish"));
  assert.deepEqual(R.bashRuleRisk("rmdir:*").hits, []);
  assert.ok(R.bashRuleRisk("rm:*").hits.some((h) => h[0] === "rm"));
  assert.equal(R.bashRuleRisk("curl -s https://example.com/x.json").exact, true);
  assert.deepEqual(R.bashRuleRisk("curl -s https://example.com/x.json").hits, []);
});

test("claude settings: bypass, allow-all bash, risky prefix, sandbox", () => {
  const out = R.analyzeClaudeSettings(JSON.stringify({
    permissions: { defaultMode: "bypassPermissions", allow: ["Bash", "Bash(rm -rf:*)", "Read", "Bash(ls:*)"] },
    sandbox: { enabled: true },
  }), "x");
  assert.deepEqual(ids(out).sort(), ["claude.allowAllBash", "claude.allowRisky", "claude.bypass", "claude.sandbox"].sort());
  assert.equal(out.find((f) => f.id === "claude.bypass").severity, "high");
  assert.match(out.find((f) => f.id === "claude.bypass").detail, /No deny rules/);
  assert.deepEqual(ids(R.analyzeClaudeSettings("{not json", "x")), ["claude.parse"]);
  assert.deepEqual(R.analyzeClaudeSettings(JSON.stringify({ permissions: { allow: ["Bash(npm test:*)"] } }), "x"), []);
});

test("codex config: per-profile yolo detection", () => {
  const out = R.analyzeCodexConfig('approval_policy = "on-request"\n[profiles.night]\napproval_policy = "never" # unattended\nsandbox_mode = "danger-full-access"\n[profiles.ro]\nsandbox_mode = "read-only"\n', "x");
  assert.deepEqual(ids(out), ["codex.yolo"]);
  assert.match(out[0].title, /\[profiles\.night\]/);
  assert.deepEqual(ids(R.analyzeCodexConfig('sandbox_mode = "danger-full-access"\n', "x")), ["codex.fullAccess"]);
});

test("shell rc: yolo aliases, ignores comments and plain commands", () => {
  const out = R.analyzeShellRc('# alias x="claude --dangerously-skip-permissions"\nalias yolo="codex --dangerously-bypass-approvals-and-sandbox"\necho --yolo\n', "x");
  assert.equal(out.length, 1);
  assert.match(out[0].title, /yolo/);
});

test("mcp servers merged from top level and projects", () => {
  assert.deepEqual(R.mcpServersFromClaudeJson({ mcpServers: { b: {} }, projects: { p: { mcpServers: { a: {}, b: {} } } } }), ["a", "b"]);
});

test("kubeconfig: contexts, current, prod detection", () => {
  const p = R.parseKubeconfig("contexts:\n- context:\n    cluster: c\n  name: dev\n- name: \"gke_acme_production\"\n  context:\n    cluster: x\ncurrent-context: dev\nusers:\n- name: someuser\n");
  assert.deepEqual(p.contexts, ["dev", "gke_acme_production"]);
  assert.equal(p.current, "dev");
  const out = R.analyzeKube(p, "x");
  assert.deepEqual(ids(out), ["kube.prod", "kube.contexts"]);
  assert.equal(R.PROD_RX.test("reproduce"), false);
  assert.equal(R.PROD_RX.test("eks-prod-1"), true);
});

test("gh auth status parsing (multi-account, scopes)", () => {
  const txt = `github.com
  ✓ Logged in to github.com account octo (keyring)
  - Active account: true
  - Token scopes: 'delete_repo', 'repo', 'workflow'

  ✓ Logged in to github.com account other (keyring)
  - Active account: false
  - Token scopes: 'read:org'
`;
  const acc = R.parseGhStatus(txt);
  assert.equal(acc.length, 2);
  assert.deepEqual(acc[0].scopes, ["delete_repo", "repo", "workflow"]);
  assert.equal(acc[1].active, false);
  assert.deepEqual(ids(R.analyzeGh(acc, "x")), ["gh.deleteRepo", "gh.repo", "gh.workflow"]);
});

function fakeKey(cipher) {
  const magic = Buffer.from("openssh-key-v1\0", "latin1");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(cipher.length);
  const b64 = Buffer.concat([magic, len, Buffer.from(cipher), Buffer.alloc(40, 1)]).toString("base64");
  const w = "PRIVATE" + " KEY";
  return `-----BEGIN OPENSSH ${w}-----\n${b64.slice(0, 70)}\n${b64.slice(70)}\n-----END OPENSSH ${w}-----\n`;
}

test("ssh key encryption detection without reading key material out", () => {
  assert.equal(R.sshKeyInfo(fakeKey("none")).encrypted, false);
  assert.equal(R.sshKeyInfo(fakeKey("aes256-ctr")).encrypted, true);
  const w = "PRIVATE" + " KEY";
  assert.equal(R.sshKeyInfo(`-----BEGIN RSA ${w}-----\nProc-Type: 4,ENCRYPTED\nabc\n`).encrypted, true);
  assert.equal(R.sshKeyInfo(`-----BEGIN RSA ${w}-----\nabc\n`).encrypted, false);
  assert.equal(R.sshKeyInfo(`-----BEGIN ENCRYPTED ${w}-----\nabc\n`).encrypted, true);
  assert.equal(R.sshKeyInfo("ssh-ed25519 AAAA user").isPrivate, false);
});

test("mount parsing and classification", () => {
  const mac = R.parseMount("//u@nas/x on /Volumes/x (smbfs, nodev, nosuid, mounted by u)\n/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n/dev/disk5 on /Volumes/Backup (apfs, local, journaled)\n");
  assert.equal(mac.length, 3);
  assert.equal(R.classifyMount(mac[0], "darwin").kind, "network");
  assert.equal(R.classifyMount(mac[1], "darwin").kind, "system");
  assert.equal(R.classifyMount(mac[1], "darwin").ro, true);
  assert.equal(R.classifyMount(mac[2], "darwin").kind, "external");
  const lin = R.parseMount("srv:/export on /mnt/share type nfs4 (rw,relatime)\n/dev/sdb1 on /media/me/usb type vfat (rw,nosuid)\nproc on /proc type proc (rw)\n");
  assert.equal(R.classifyMount(lin[0], "linux").kind, "network");
  assert.equal(R.classifyMount(lin[1], "linux").kind, "external");
  assert.equal(R.classifyMount(lin[2], "linux").kind, "system");
});

test("env names and db url classification", () => {
  assert.deepEqual(R.secretEnvNames({ OPENAI_API_KEY: "x", SSH_AUTH_SOCK: "/tmp/s", PATH: "/bin", EMPTY_TOKEN: "", STRIPE_SECRET: "y" }), ["OPENAI_API_KEY", "STRIPE_SECRET"]);
  assert.equal(R.dbUrlIsRemote("postgres://u:p@localhost:5432/db"), false);
  assert.equal(R.dbUrlIsRemote("postgres://u:p@db.prod.example.com/db"), true);
  assert.equal(R.dbUrlIsRemote("mysql://127.0.0.1/x"), false);
  assert.equal(R.dbUrlIsRemote("not a url"), null);
});

test("redaction of home and emails", () => {
  assert.equal(R.redact("/home/me/.aws for me@x.io", "/home/me"), "~/.aws for <email>");
});

test("summary lists unique could-phrases, high first", () => {
  const s = R.summarize([
    R.finding("medium", "a", "1", "t", { could: "b" }),
    R.finding("high", "a", "2", "t", { could: "a" }),
    R.finding("medium", "a", "3", "t", { could: "b" }),
    R.finding("info", "a", "4", "t", { could: "c" }),
  ]);
  assert.deepEqual(s.counts, { high: 1, medium: 2, info: 1 });
  assert.deepEqual(s.could.map((x) => x.text), ["a", "b"]);
});
