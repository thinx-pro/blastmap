// Read-only collectors. Every check reads files or runs a harmless status
// command; nothing is written, and secret values are never returned.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import * as R from "./rules.js";

const { finding } = R;

export function makeContext(overrides = {}) {
  const home = overrides.home || os.homedir();
  const ctx = {
    home,
    cwd: overrides.cwd || process.cwd(),
    env: overrides.env || process.env,
    platform: overrides.platform || process.platform,
    exec: overrides.exec || realExec,
    writable: overrides.writable || null,
    noExec: !!overrides.noExec,
  };
  return ctx;
}

function realExec(cmd, args, timeout = 5000) {
  try {
    const r = spawnSync(cmd, args, { encoding: "utf8", timeout, stdio: ["ignore", "pipe", "pipe"] });
    if (r.error) return null;
    return { code: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
  } catch {
    return null;
  }
}

function readText(p, max = 2_000_000) {
  try {
    const st = fs.statSync(p);
    if (!st.isFile() || st.size > max) return null;
    return fs.readFileSync(p, "utf8");
  } catch {
    return null;
  }
}
const exists = (p) => { try { fs.accessSync(p); return true; } catch { return false; } };
const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };
const writable = (p) => { try { fs.accessSync(p, fs.constants.W_OK); return true; } catch { return false; } };
const listDir = (p) => { try { return fs.readdirSync(p); } catch { return []; } };

function run(ctx, cmd, args) {
  if (ctx.noExec) return null;
  return ctx.exec(cmd, args);
}

const tilde = (ctx, p) => R.redact(p, ctx.home);

// ---------------------------------------------------------------- agent

export function checkAgent(ctx) {
  const out = [];
  const files = [
    path.join(ctx.home, ".claude", "settings.json"),
    path.join(ctx.home, ".claude", "settings.local.json"),
    path.join(ctx.cwd, ".claude", "settings.json"),
    path.join(ctx.cwd, ".claude", "settings.local.json"),
    ctx.platform === "darwin"
      ? "/Library/Application Support/ClaudeCode/managed-settings.json"
      : "/etc/claude-code/managed-settings.json",
  ];
  const seen = new Set();
  for (const f of files) {
    const real = path.resolve(f);
    if (seen.has(real)) continue;
    seen.add(real);
    const t = readText(real);
    if (t !== null) out.push(...R.analyzeClaudeSettings(t, tilde(ctx, real)));
  }
  const codexHome = ctx.env.CODEX_HOME || path.join(ctx.home, ".codex");
  const codexCfg = path.join(codexHome, "config.toml");
  const ct = readText(codexCfg);
  if (ct !== null) out.push(...R.analyzeCodexConfig(ct, tilde(ctx, codexCfg)));

  for (const rc of [".zshrc", ".bashrc", ".bash_profile", ".zprofile", ".profile", ".config/fish/config.fish", ".aliases"]) {
    const p = path.join(ctx.home, rc);
    const t = readText(p);
    if (t !== null) out.push(...R.analyzeShellRc(t, tilde(ctx, p)));
  }

  // MCP servers extend what the agent can touch.
  const mcp = new Set();
  const cj = readText(path.join(ctx.home, ".claude.json"), 50_000_000);
  if (cj) {
    try { for (const n of R.mcpServersFromClaudeJson(JSON.parse(cj))) mcp.add(n); } catch { /* ignore */ }
  }
  const pj = readText(path.join(ctx.cwd, ".mcp.json"));
  if (pj) {
    try { for (const n of R.mcpServersFromClaudeJson(JSON.parse(pj))) mcp.add(n); } catch { /* ignore */ }
  }
  if (mcp.size) {
    out.push(finding("info", "agent", "mcp.servers", `${mcp.size} MCP server(s) configured for Claude Code`, {
      detail: [...mcp].join(", "),
      fix: "Each server adds tools the agent can call; remove ones you no longer use (claude mcp remove <name>).",
      source: "~/.claude.json, .mcp.json",
    }));
  }
  return out;
}

// ---------------------------------------------------------------- cloud

function iniSections(text) {
  const secs = [];
  let cur = null;
  for (const line of String(text).split(/\r?\n/)) {
    const m = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (m) { cur = { name: m[1].trim(), keys: new Set() }; secs.push(cur); continue; }
    const kv = /^\s*([A-Za-z0-9_.-]+)\s*[=:]/.exec(line);
    if (kv && cur) cur.keys.add(kv[1].toLowerCase());
  }
  return secs;
}

export function checkCloud(ctx) {
  const out = [];
  const H = ctx.home;
  // AWS
  const awsCredPath = ctx.env.AWS_SHARED_CREDENTIALS_FILE || path.join(H, ".aws", "credentials");
  const awsCred = readText(awsCredPath);
  if (awsCred) {
    const keyed = iniSections(awsCred).filter((s) => s.keys.has("aws_access_key_id"));
    if (keyed.length) {
      const names = keyed.map((s) => s.name);
      const prod = names.filter((n) => R.PROD_RX.test(n));
      out.push(finding(prod.length ? "high" : "medium", "cloud", "aws.staticKeys", `${keyed.length} AWS profile(s) with long-lived access keys: ${names.join(", ")}`, {
        could: prod.length ? `use AWS production profile(s) ${prod.join(", ")}` : "act on AWS with your long-lived keys",
        fix: "Prefer SSO / short-lived credentials (aws configure sso); give agent shells a read-only profile.",
        source: tilde(ctx, awsCredPath),
      }));
    }
  }
  const awsConf = readText(ctx.env.AWS_CONFIG_FILE || path.join(H, ".aws", "config"));
  if (awsConf) {
    const sso = iniSections(awsConf).filter((s) => [...s.keys].some((k) => k.startsWith("sso_")) && s.name.startsWith("profile "));
    if (sso.length) {
      const cache = listDir(path.join(H, ".aws", "sso", "cache")).filter((f) => f.endsWith(".json"));
      out.push(finding("info", "cloud", "aws.sso", `${sso.length} AWS SSO profile(s)${cache.length ? " (cached SSO session present)" : ""}`, {
        detail: sso.map((s) => s.name.replace(/^profile /, "")).join(", "),
        source: "~/.aws/config",
      }));
    }
  }
  const awsEnv = ["AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN", "AWS_PROFILE"].filter((k) => ctx.env[k]);
  if (awsEnv.length) {
    const prof = ctx.env.AWS_PROFILE || "";
    out.push(finding(R.PROD_RX.test(prof) ? "high" : "medium", "cloud", "aws.env", `AWS credentials in this shell's environment (${awsEnv.join(", ")})`, {
      could: "act on AWS from any command the agent runs here",
      detail: prof ? `AWS_PROFILE=${prof}` : "",
      fix: "Unset them before starting the agent, or start the agent from a clean shell.",
      source: "environment",
    }));
  }
  // Google Cloud
  const gdir = ctx.env.CLOUDSDK_CONFIG || path.join(H, ".config", "gcloud");
  if (exists(path.join(gdir, "application_default_credentials.json"))) {
    out.push(finding("medium", "cloud", "gcloud.adc", "Google Cloud application-default credentials present", {
      could: "call Google Cloud APIs as you (any SDK picks these up)",
      fix: "gcloud auth application-default revoke   # when you don't need them",
      source: tilde(ctx, path.join(gdir, "application_default_credentials.json")),
    }));
  }
  const gconfigs = listDir(path.join(gdir, "configurations")).filter((f) => f.startsWith("config_"));
  const projects = [];
  for (const c of gconfigs) {
    const t = readText(path.join(gdir, "configurations", c)) || "";
    const m = /^\s*project\s*=\s*(\S+)/m.exec(t);
    if (m) projects.push(m[1]);
  }
  if (exists(path.join(gdir, "credentials.db")) || exists(path.join(gdir, "access_tokens.db"))) {
    const prod = projects.filter((p) => R.PROD_RX.test(p));
    out.push(finding(prod.length ? "high" : "medium", "cloud", "gcloud.login", `gcloud is logged in${projects.length ? ` (projects: ${projects.join(", ")})` : ""}`, {
      could: prod.length ? `change Google Cloud production project(s) ${prod.join(", ")}` : "act on Google Cloud as you",
      fix: "gcloud auth revoke   # or use a separate CLOUDSDK_CONFIG for agent shells",
      source: tilde(ctx, gdir),
    }));
  }
  // Azure
  const az = path.join(H, ".azure");
  const azProfile = readText(path.join(az, "azureProfile.json"));
  const azTokens = listDir(az).some((f) => f.startsWith("msal_token_cache"));
  if (azTokens) {
    let subs = 0;
    if (azProfile) { try { subs = (JSON.parse(azProfile.replace(/^﻿/, "")).subscriptions || []).length; } catch { /* ignore */ } }
    out.push(finding("medium", "cloud", "azure.login", `Azure CLI is logged in${subs ? ` (${subs} subscription(s))` : ""}`, {
      could: "act on Azure as you",
      fix: "az logout   # when you don't need it",
      source: "~/.azure",
    }));
  }
  // Other platform CLIs: presence of their auth files only.
  const others = [
    ["vercel", "Vercel", ctx.platform === "darwin" ? path.join(H, "Library", "Application Support", "com.vercel.cli", "auth.json") : path.join(H, ".local", "share", "com.vercel.cli", "auth.json"), "deploy, change env vars and delete Vercel projects"],
    ["fly", "Fly.io", path.join(H, ".fly", "config.yml"), "deploy and destroy Fly apps"],
    ["doctl", "DigitalOcean", ctx.platform === "darwin" ? path.join(H, "Library", "Application Support", "doctl", "config.yaml") : path.join(H, ".config", "doctl", "config.yaml"), "create and destroy droplets and databases"],
    ["wrangler", "Cloudflare (wrangler)", ctx.platform === "darwin" ? path.join(H, "Library", "Preferences", ".wrangler", "config", "default.toml") : path.join(H, ".config", ".wrangler", "config", "default.toml"), "deploy Workers and change Cloudflare resources"],
    ["wrangler-legacy", "Cloudflare (wrangler)", path.join(H, ".wrangler", "config", "default.toml"), "deploy Workers and change Cloudflare resources"],
    ["supabase", "Supabase", path.join(H, ".supabase", "access-token"), "change and delete Supabase projects"],
    ["firebase", "Firebase", path.join(H, ".config", "configstore", "firebase-tools.json"), "deploy and delete Firebase resources"],
    ["terraform", "Terraform Cloud", path.join(H, ".terraform.d", "credentials.tfrc.json"), "run plans and applies in Terraform Cloud"],
  ];
  const seenNames = new Set();
  for (const [id, name, p, could] of others) {
    if (seenNames.has(name) || !exists(p)) continue;
    if (id === "fly") { const t = readText(p) || ""; if (!/access_token/.test(t)) continue; }
    if (id === "firebase") { const t = readText(p) || ""; if (!/refresh_token|"tokens"/.test(t)) continue; }
    seenNames.add(name);
    out.push(finding("medium", "cloud", `cli.${id}`, `${name} CLI is logged in`, { could, source: tilde(ctx, p) }));
  }
  const netrc = readText(path.join(H, ".netrc"));
  if (netrc) {
    const machines = [...netrc.matchAll(/machine\s+(\S+)/g)].map((m) => m[1]);
    if (machines.length) {
      out.push(finding("medium", "cloud", "netrc", `~/.netrc holds credentials for ${machines.length} host(s): ${machines.join(", ")}`, {
        could: "authenticate to those hosts with curl/git/heroku",
        source: "~/.netrc",
      }));
    }
  }
  // Kubernetes
  const kubePaths = (ctx.env.KUBECONFIG ? ctx.env.KUBECONFIG.split(path.delimiter) : [path.join(H, ".kube", "config")]).filter(Boolean);
  const merged = { contexts: [], current: null };
  for (const kp of kubePaths) {
    const t = readText(kp);
    if (!t) continue;
    const p = R.parseKubeconfig(t);
    merged.contexts.push(...p.contexts);
    merged.current = merged.current || p.current;
  }
  merged.contexts = [...new Set(merged.contexts)];
  out.push(...R.analyzeKube(merged, kubePaths.map((p) => tilde(ctx, p)).join(", ")));
  return out;
}

// ---------------------------------------------------------------- publish

export function checkPublish(ctx) {
  const out = [];
  const H = ctx.home;
  const gh = run(ctx, "gh", ["auth", "status"]);
  if (gh) {
    const accounts = R.parseGhStatus(gh.stdout + "\n" + gh.stderr);
    out.push(...R.analyzeGh(accounts, "gh auth status"));
  }
  const ghEnv = ["GH_TOKEN", "GITHUB_TOKEN"].filter((k) => ctx.env[k]);
  if (ghEnv.length) {
    out.push(finding("medium", "publish", "gh.env", `GitHub token in this shell's environment (${ghEnv.join(", ")})`, {
      could: "use that GitHub token from any command the agent runs here",
      source: "environment",
    }));
  }
  const npmrc = readText(path.join(H, ".npmrc"));
  if (npmrc && /_authToken\s*=/.test(npmrc)) {
    const regs = [...npmrc.matchAll(/^\s*(\/\/[^:]+):_authToken/gm)].map((m) => m[1]);
    out.push(finding("medium", "publish", "npm.token", `npm auth token in ~/.npmrc${regs.length ? ` (${regs.join(", ")})` : ""}`, {
      could: "publish packages under your npm account",
      fix: "Use a granular, publish-scoped token only where you publish; npm logout elsewhere.",
      source: "~/.npmrc",
    }));
  }
  if (ctx.env.NPM_TOKEN || ctx.env.NODE_AUTH_TOKEN) {
    out.push(finding("medium", "publish", "npm.env", "npm token in this shell's environment", { could: "publish packages under your npm account", source: "environment" }));
  }
  const pypirc = readText(path.join(H, ".pypirc"));
  if (pypirc && /password\s*[=:]/i.test(pypirc)) {
    out.push(finding("medium", "publish", "pypi.token", "PyPI credentials in ~/.pypirc", { could: "upload Python packages under your account", source: "~/.pypirc" }));
  }
  for (const p of [path.join(H, ".cargo", "credentials.toml"), path.join(H, ".cargo", "credentials")]) {
    if (exists(p)) { out.push(finding("medium", "publish", "cargo.token", "crates.io token present", { could: "publish and yank crates", source: tilde(ctx, p) })); break; }
  }
  if (exists(path.join(H, ".gem", "credentials"))) {
    out.push(finding("medium", "publish", "gem.token", "RubyGems credentials present", { could: "push and yank gems", source: "~/.gem/credentials" }));
  }
  const dcfg = readText(path.join(H, ".docker", "config.json"));
  if (dcfg) {
    try {
      const j = JSON.parse(dcfg);
      const inline = Object.entries(j.auths || {}).filter(([, v]) => v && v.auth).map(([k]) => k);
      if (inline.length) {
        out.push(finding("medium", "publish", "docker.inlineAuth", `Docker registry credentials stored inline for: ${inline.join(", ")}`, {
          could: "push images to those registries",
          fix: "Use a credential helper (credsStore) instead of inline auth.",
          source: "~/.docker/config.json",
        }));
      }
    } catch { /* ignore */ }
  }
  return out;
}

// ---------------------------------------------------------------- host

export function checkHost(ctx) {
  const out = [];
  const H = ctx.home;
  const socks = [
    "/var/run/docker.sock",
    path.join(H, ".docker", "run", "docker.sock"),
    path.join(H, ".orbstack", "run", "docker.sock"),
    path.join(H, ".colima", "default", "docker.sock"),
    path.join(H, ".rd", "docker.sock"),
  ];
  if (ctx.env.DOCKER_HOST && ctx.env.DOCKER_HOST.startsWith("unix://")) socks.unshift(ctx.env.DOCKER_HOST.slice(7));
  const live = [...new Set(socks)].filter((s) => exists(s) && writable(s));
  if (live.length) {
    const linux = ctx.platform === "linux";
    out.push(finding(linux ? "high" : "medium", "host", "docker.socket", `Docker socket is writable: ${live.map((s) => tilde(ctx, s)).join(", ")}`, {
      could: linux ? "get root on this machine via docker run -v /:/host" : "mount any folder shared with the Docker VM into a root container",
      fix: "Don't run agents as a user in the docker group; or give them a rootless/remote Docker context.",
      source: "filesystem",
    }));
  }
  const sudo = run(ctx, "sudo", ["-n", "true"]);
  if (sudo && sudo.code === 0) {
    out.push(finding("high", "host", "sudo.nopasswd", "sudo works without a password right now", {
      could: "run anything as root",
      fix: "Remove NOPASSWD rules or lower timestamp_timeout; start agents after `sudo -k`.",
      source: "sudo -n true",
    }));
  }
  // SSH
  const sshDir = path.join(H, ".ssh");
  const unenc = [];
  for (const f of listDir(sshDir)) {
    if (f.endsWith(".pub") || f === "known_hosts" || f === "config" || f === "authorized_keys") continue;
    const t = readText(path.join(sshDir, f), 64_000);
    if (!t) continue;
    const info = R.sshKeyInfo(t);
    if (info.isPrivate && info.encrypted === false) unenc.push(f);
  }
  if (unenc.length) {
    out.push(finding("medium", "host", "ssh.unencrypted", `${unenc.length} SSH private key(s) without a passphrase: ${unenc.join(", ")}`, {
      could: "ssh/scp/git-push to every host that trusts those keys",
      fix: "ssh-keygen -p -f ~/.ssh/<key>   # add a passphrase; use ssh-agent with confirmation (ssh-add -c)",
      source: "~/.ssh",
    }));
  }
  if (ctx.env.SSH_AUTH_SOCK) {
    const r = run(ctx, "ssh-add", ["-l"]);
    if (r && r.code === 0) {
      const n = r.stdout.split(/\r?\n/).filter((l) => /\S/.test(l)).length;
      if (n) {
        out.push(finding("medium", "host", "ssh.agent", `${n} key(s) loaded in ssh-agent`, {
          could: "use your loaded SSH keys without any passphrase",
          fix: "ssh-add -c <key>   # require confirmation per use; or ssh-add -D before long unattended runs",
          source: "ssh-add -l",
        }));
      }
    }
  }
  const sshCfg = readText(path.join(sshDir, "config"));
  if (sshCfg) {
    const hosts = [...sshCfg.matchAll(/^\s*Host\s+(.+)$/gim)].flatMap((m) => m[1].split(/\s+/)).filter((h) => h && !h.includes("*"));
    if (hosts.length) {
      const prod = hosts.filter((h) => R.PROD_RX.test(h));
      out.push(finding(prod.length ? "high" : "info", "host", "ssh.hosts", `${hosts.length} named SSH host(s) in ~/.ssh/config${prod.length ? `, production-looking: ${prod.join(", ")}` : ""}`, {
        could: prod.length ? `ssh into production host(s) ${prod.join(", ")}` : "",
        fix: prod.length ? "Use a passphrase-protected key (or a hardware key) for production hosts, not the agent's default key." : "",
        source: "~/.ssh/config",
      }));
    }
  }
  return out;
}

// ---------------------------------------------------------------- files

export function checkFiles(ctx) {
  const out = [];
  const H = ctx.home;
  const m = run(ctx, "mount", []);
  if (m && m.code === 0) {
    const net = [];
    const ext = [];
    for (const mt of R.parseMount(m.stdout)) {
      const c = R.classifyMount(mt, ctx.platform);
      if (c.ro || c.kind === "system") continue;
      if (!(ctx.writable || writable)(mt.point)) continue;
      if (c.kind === "network") net.push(`${tilde(ctx, mt.point)} (${mt.fstype})`);
      else ext.push(tilde(ctx, mt.point));
    }
    if (net.length) {
      out.push(finding("high", "files", "mount.network", `Writable network share(s) mounted: ${net.join(", ")}`, {
        could: "delete files on a file server (rm -rf follows you there)",
        fix: "Unmount shares you aren't using, or mount them read-only for agent sessions.",
        source: "mount",
      }));
    }
    if (ext.length) {
      out.push(finding("medium", "files", "mount.external", `Writable external volume(s) mounted: ${ext.join(", ")}`, {
        could: "delete files on external or backup drives",
        fix: "Eject drives (especially backup drives) before long agent runs.",
        source: "mount",
      }));
    }
  }
  // Cloud-synced folders: local deletes are synced up.
  const synced = [];
  const cs = path.join(H, "Library", "CloudStorage");
  for (const d of listDir(cs)) if (isDir(path.join(cs, d))) synced.push(R.redact(`~/Library/CloudStorage/${d}`));
  const icloud = path.join(H, "Library", "Mobile Documents", "com~apple~CloudDocs");
  if (isDir(icloud)) {
    synced.push("iCloud Drive");
    if (isDir(path.join(icloud, "Desktop")) || isDir(path.join(icloud, "Documents"))) synced.push("iCloud Desktop & Documents (your ~/Desktop and ~/Documents)");
  }
  for (const d of ["Dropbox", "OneDrive", "Google Drive", "Nextcloud", "pCloud Drive", "Box", "Sync"]) {
    const p = path.join(H, d);
    if (isDir(p)) {
      let real = p;
      try { real = fs.realpathSync(p); } catch { /* ignore */ }
      if (!real.includes(path.join("Library", "CloudStorage"))) synced.push(`~/${d}`);
    }
  }
  if (synced.length) {
    out.push(finding("medium", "files", "sync.folders", `${synced.length} cloud-synced folder(s): local deletes propagate`, {
      could: "delete files that sync deletes from the cloud copy too",
      detail: synced.join(", "),
      fix: "Know your provider's restore window (trash / version history); keep agents' working dirs outside synced folders.",
      source: "filesystem",
    }));
  }
  const rcl = readText(path.join(H, ".config", "rclone", "rclone.conf"));
  if (rcl) {
    const remotes = iniSections(rcl).map((s) => s.name);
    if (remotes.length) {
      out.push(finding("medium", "files", "rclone.remotes", `${remotes.length} rclone remote(s) configured: ${remotes.join(", ")}`, {
        could: "rclone delete / sync --delete-after on cloud storage",
        fix: "Use read-only scopes for remotes you only read from (e.g. drive scope drive.readonly).",
        source: "~/.config/rclone/rclone.conf",
      }));
    }
  }
  if (ctx.platform === "darwin") {
    const tm = run(ctx, "tmutil", ["latestbackup"]);
    if (tm && tm.code === 0 && tm.stdout.trim()) {
      const mm = /(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})/.exec(tm.stdout);
      if (mm) {
        const t = Date.UTC(+mm[1], +mm[2] - 1, +mm[3], +mm[4], +mm[5], +mm[6]);
        const days = Math.floor((Date.now() - t) / 86_400_000);
        out.push(finding(days > 7 ? "medium" : "info", "files", "backup.timemachine", `Latest Time Machine backup: ${days} day(s) ago`, {
          could: days > 7 ? "destroy work that has no recent backup" : "",
          source: "tmutil latestbackup",
        }));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------- data

export function checkData(ctx) {
  const out = [];
  const H = ctx.home;
  const names = R.secretEnvNames(ctx.env);
  const already = new Set(["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN"]);
  const rest = names.filter((n) => !already.has(n));
  if (rest.length) {
    out.push(finding("medium", "data", "env.secrets", `${rest.length} secret-looking variable(s) in this shell's environment`, {
      could: "use (or leak) the credentials this shell holds",
      detail: rest.join(", ") + "  (names only; values are never printed)",
      fix: "Start agents from a shell without them, or use a per-project .envrc that loads only what the task needs.",
      source: "environment",
    }));
  }
  for (const k of ["DATABASE_URL", "POSTGRES_URL", "MONGODB_URI", "REDIS_URL", "MYSQL_URL"]) {
    if (!ctx.env[k]) continue;
    const remote = R.dbUrlIsRemote(ctx.env[k]);
    if (remote) {
      out.push(finding("high", "data", "db.remoteUrl", `${k} points to a non-local host`, {
        could: "run destructive SQL against a remote database",
        fix: "Point agents at a local or disposable database; use a read-only role for anything shared.",
        source: "environment (host classified, value not printed)",
      }));
    }
  }
  const pg = readText(path.join(H, ".pgpass"));
  if (pg) {
    const lines = pg.split(/\r?\n/).filter((l) => l.trim() && !l.startsWith("#"));
    if (lines.length) {
      const remote = lines.filter((l) => !/^(localhost|127\.0\.0\.1|::1|\*):/.test(l)).length;
      out.push(finding(remote ? "high" : "medium", "data", "db.pgpass", `~/.pgpass has ${lines.length} saved Postgres login(s)${remote ? `, ${remote} non-local` : ""}`, {
        could: remote ? "connect to remote Postgres databases without a password prompt" : "connect to local Postgres without a password prompt",
        fix: "Keep only local/dev entries in ~/.pgpass; use a read-only role for shared databases.",
        source: "~/.pgpass",
      }));
    }
  }
  const my = readText(path.join(H, ".my.cnf"));
  if (my && /password\s*=/i.test(my)) {
    out.push(finding("medium", "data", "db.mycnf", "~/.my.cnf stores a MySQL password", { could: "connect to MySQL without a password prompt", source: "~/.my.cnf" }));
  }
  const envFiles = listDir(ctx.cwd).filter((f) => /^\.env(\..+)?$/.test(f) && !/\.(example|sample|template)$/.test(f));
  if (envFiles.length) {
    let keys = 0;
    for (const f of envFiles) {
      const t = readText(path.join(ctx.cwd, f)) || "";
      keys += t.split(/\r?\n/).filter((l) => /^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/.test(l) && R.secretEnvNames({ [l.replace(/^\s*export\s+/, "").split("=")[0].trim()]: "x" }).length).length;
    }
    out.push(finding("medium", "data", "env.files", `${envFiles.length} .env file(s) in this project (${envFiles.join(", ")}), ${keys} secret-looking key(s)`, {
      could: "read the secrets in this project's .env files",
      fix: "Add a deny rule such as Read(./.env*) to .claude/settings.json.",
      source: tilde(ctx, ctx.cwd),
    }));
  }
  return out;
}

export const AREAS = {
  agent: checkAgent,
  cloud: checkCloud,
  publish: checkPublish,
  host: checkHost,
  files: checkFiles,
  data: checkData,
};

export function collectAll(ctx, only) {
  const list = [];
  for (const [area, fn] of Object.entries(AREAS)) {
    if (only && only.length && !only.includes(area)) continue;
    try {
      list.push(...fn(ctx));
    } catch (e) {
      list.push(finding("info", area, `${area}.error`, `Check "${area}" failed: ${e.message}`));
    }
  }
  // Final redaction pass over every string.
  return R.sortFindings(list.map((f) => Object.fromEntries(Object.entries(f).map(([k, v]) => [k, typeof v === "string" ? R.redact(v, ctx.home) : v]))));
}
