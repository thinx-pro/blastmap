// Pure analysis rules. No Node or browser APIs here: the same file runs in the
// CLI and in the web checker (docs/rules.js is a copy, kept identical by a test).

export const SEVERITY_ORDER = { high: 0, medium: 1, info: 2 };

export function finding(severity, area, id, title, opts = {}) {
  return {
    severity,
    area,
    id,
    title,
    could: opts.could || "",
    detail: opts.detail || "",
    fix: opts.fix || "",
    source: opts.source || "",
  };
}

const EMAIL_RX = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

export function redact(text, home) {
  let s = String(text);
  if (home) s = s.split(home).join("~");
  return s.replace(EMAIL_RX, "<email>");
}

export const PROD_RX = /(^|[^a-z])(prod|production|prd|live)([^a-z]|$)/i;

// ---------------------------------------------------------------- Claude Code

// Commands that can delete, rewrite history, publish, or reach production.
export const RISKY_PREFIXES = [
  ["rm", "delete files"],
  ["sudo", "run anything as root"],
  ["git push", "push (and force-push) to remotes"],
  ["git reset", "discard commits and working-tree changes"],
  ["git clean", "delete untracked files"],
  ["git checkout", "overwrite uncommitted changes"],
  ["git branch -D", "delete branches"],
  ["gh", "act on GitHub as you (repos, releases, PRs)"],
  ["aws", "act on AWS as you"],
  ["gcloud", "act on Google Cloud as you"],
  ["az", "act on Azure as you"],
  ["kubectl", "change Kubernetes clusters"],
  ["helm", "change Kubernetes releases"],
  ["terraform", "apply or destroy infrastructure"],
  ["docker", "control Docker (root in the Docker host)"],
  ["npm publish", "publish npm packages"],
  ["curl", "send data anywhere"],
  ["wget", "download and send data"],
  ["ssh", "log in to remote machines"],
  ["scp", "copy files to and from remote machines"],
  ["rsync", "sync (and --delete) files"],
  ["find", "run -delete / -exec on any path"],
  ["chmod", "change permissions"],
  ["mv", "move files over other files"],
  ["dd", "overwrite disks"],
  ["psql", "run SQL against databases"],
  ["mysql", "run SQL against databases"],
  ["supabase", "act on Supabase projects"],
  ["vercel", "deploy and change Vercel projects"],
  ["fly", "deploy and destroy Fly apps"],
  ["wrangler", "deploy and change Cloudflare"],
  ["rclone", "delete files on cloud remotes"],
];

// "Bash(npm run test:*)" / "Bash(git push *)" / "Bash" -> { tool, command|null }
export function parseRule(rule) {
  const m = /^\s*([A-Za-z_][\w.-]*)\s*(?:\((.*)\))?\s*$/s.exec(String(rule));
  if (!m) return { tool: String(rule), command: null };
  return { tool: m[1], command: m[2] === undefined ? null : m[2] };
}

function commandPrefix(cmd) {
  // Strip trailing wildcards: ":*", " *", "*"
  return cmd.replace(/:\*\s*$/, "").replace(/\s*\*\s*$/, "").trim();
}

// Subcommands that only read. A rule narrowed to one of these is not risky.
export const READ_ONLY = {
  git: ["status", "log", "diff", "show", "fetch", "blame", "rev-parse", "ls-files", "grep", "describe", "shortlog", "branch --show-current", "remote -v", "config --get"],
  gh: ["search", "status", "browse", "repo view", "repo list", "pr view", "pr list", "pr diff", "pr checks", "pr status", "issue view", "issue list", "issue status", "run view", "run list", "release view", "release list", "auth status"],
  kubectl: ["get", "describe", "logs", "top", "explain", "version", "config get-contexts", "config current-context", "api-resources"],
  docker: ["ps", "images", "logs", "inspect", "version", "info", "stats"],
  aws: ["sts get-caller-identity", "s3 ls", "configure list"],
  gcloud: ["config list", "auth list", "projects list", "info"],
  helm: ["list", "status", "get", "history", "template", "lint"],
  terraform: ["plan", "validate", "fmt", "show", "output", "version"],
  find: [],
};

function isReadOnlyNarrowing(prefix, p) {
  const base = p.split(" ")[0];
  const ro = READ_ONLY[base];
  if (!ro || !prefix.startsWith(base + " ")) return false;
  const rest = prefix.slice(base.length + 1).trim();
  return ro.some((r) => rest === r || rest.startsWith(r + " "));
}

export function bashRuleRisk(command) {
  if (command === null) return { any: true };
  const raw = command.trim();
  const prefix = commandPrefix(raw);
  if (prefix === "" || prefix === "*") return { any: true };
  // An exact command (no wildcard) was approved as written: not a blanket grant.
  if (!/\*/.test(raw)) return { any: false, hits: [], prefix, exact: true };
  const hits = [];
  for (const [p, what] of RISKY_PREFIXES) {
    // The rule grants p if its prefix is p, a shorter prefix of p ("git" grants
    // "git push"), or p followed by more words ("git push origin *").
    const broader = prefix === p || p.startsWith(prefix + " ");
    const narrower = prefix.startsWith(p + " ") || prefix.startsWith(p + ":");
    if ((broader || narrower) && !isReadOnlyNarrowing(prefix, p)) hits.push([p, what]);
  }
  return { any: false, hits, prefix };
}

function joinWhats(whats) {
  if (whats.length <= 3) return whats.join("; ");
  return `${whats.slice(0, 3).join("; ")} (+${whats.length - 3} more)`;
}

export function analyzeClaudeSettings(text, source) {
  const out = [];
  let obj;
  try {
    obj = JSON.parse(text);
  } catch (e) {
    out.push(finding("info", "agent", "claude.parse", `Could not parse ${source}`, { detail: String(e.message), source }));
    return out;
  }
  const perms = (obj && obj.permissions) || {};
  const mode = perms.defaultMode;
  const allow = Array.isArray(perms.allow) ? perms.allow : [];
  const deny = Array.isArray(perms.deny) ? perms.deny : [];
  if (mode === "bypassPermissions") {
    out.push(finding("high", "agent", "claude.bypass", "Claude Code runs with permission prompts off (defaultMode: bypassPermissions)", {
      could: "run any tool call without asking you",
      detail: deny.length ? `${deny.length} deny rule(s) still apply.` : "No deny rules: nothing is blocked.",
      fix: "Use \"acceptEdits\" or \"default\" and allow specific commands; if you need bypass for unattended runs, put it in a project-local settings file for that project only, with deny rules.",
      source,
    }));
  } else if (mode === "acceptEdits") {
    out.push(finding("info", "agent", "claude.acceptEdits", "Claude Code auto-accepts file edits (defaultMode: acceptEdits)", { source }));
  }
  for (const rule of allow) {
    const { tool, command } = parseRule(rule);
    if (tool !== "Bash") continue;
    const r = bashRuleRisk(command);
    if (r.any) {
      out.push(finding("high", "agent", "claude.allowAllBash", `Every shell command is pre-approved: "${rule}"`, {
        could: "run any shell command without asking you",
        fix: "Replace it with specific prefixes such as Bash(npm test:*).",
        source,
      }));
    } else if (r.hits.length) {
      const whats = r.hits.map((h) => h[1]);
      out.push(finding("medium", "agent", "claude.allowRisky", `Pre-approved risky command: "${rule}"`, {
        could: joinWhats(whats),
        detail: `grants: ${r.hits.map((h) => h[0]).join(", ")}`,
        fix: "Narrow it to the read-only or exact commands you need (e.g. Bash(git status:*)), or move it to \"ask\".",
        source,
      }));
    }
  }
  if (obj && obj.skipDangerousModePermissionPrompt === true) {
    out.push(finding("info", "agent", "claude.skipDangerPrompt", "The warning before entering bypass mode is turned off (skipDangerousModePermissionPrompt)", { source }));
  }
  if (obj && obj.sandbox && obj.sandbox.enabled === true) {
    out.push(finding("info", "agent", "claude.sandbox", "Claude Code sandbox is enabled (good: Bash runs with filesystem/network limits)", { source }));
  }
  return out;
}

// ---------------------------------------------------------------- Codex

// Minimal TOML: tracks [section] headers and key = "value" / key = value lines.
export function parseTomlFlat(text) {
  const rows = [];
  let section = "";
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    const sec = /^\[\[?\s*([^\]]+?)\s*\]\]?$/.exec(line);
    if (sec) { section = sec[1]; continue; }
    const kv = /^([A-Za-z0-9_.\-"]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    let v = kv[2].trim();
    if (/^".*"$/.test(v) || /^'.*'$/.test(v)) v = v.slice(1, -1);
    rows.push({ section, key: kv[1].replace(/"/g, ""), value: v });
  }
  return rows;
}

export function analyzeCodexConfig(text, source) {
  const out = [];
  const rows = parseTomlFlat(text);
  const scopes = new Map(); // section -> {approval, sandbox}
  for (const r of rows) {
    const s = r.section || "(top level)";
    if (!scopes.has(s)) scopes.set(s, {});
    if (r.key === "approval_policy") scopes.get(s).approval = r.value;
    if (r.key === "sandbox_mode") scopes.get(s).sandbox = r.value;
  }
  for (const [s, v] of scopes) {
    const where = s === "(top level)" ? "default" : `[${s}]`;
    if (v.sandbox === "danger-full-access" && v.approval === "never") {
      out.push(finding("high", "agent", "codex.yolo", `Codex ${where}: no sandbox and never asks (danger-full-access + approval_policy=never)`, {
        could: "run any command on your machine without asking you",
        fix: "Use sandbox_mode = \"workspace-write\" and approval_policy = \"on-request\" for everyday work.",
        source,
      }));
    } else if (v.sandbox === "danger-full-access") {
      out.push(finding("medium", "agent", "codex.fullAccess", `Codex ${where}: sandbox disabled (danger-full-access)`, {
        could: "read and write anywhere your user can",
        fix: "Use sandbox_mode = \"workspace-write\".",
        source,
      }));
    } else if (v.approval === "never") {
      out.push(finding("info", "agent", "codex.neverAsk", `Codex ${where}: approval_policy = "never" (sandbox: ${v.sandbox || "default"})`, { source }));
    }
  }
  return out;
}

// ---------------------------------------------------------------- shell rc

const YOLO_FLAGS = [
  ["--dangerously-skip-permissions", "Claude Code without permission prompts"],
  ["--dangerously-bypass-approvals-and-sandbox", "Codex without sandbox or approvals"],
  ["--yolo", "an agent in YOLO mode"],
  ["--permission-mode bypassPermissions", "Claude Code without permission prompts"],
];

export function analyzeShellRc(text, source) {
  const out = [];
  const lines = String(text).split(/\r?\n/);
  lines.forEach((line, i) => {
    const t = line.trim();
    if (t.startsWith("#")) return;
    if (!/^(alias|function|export|[A-Za-z_][\w-]*\s*\(\))/.test(t) && !/^\w+=/.test(t)) return;
    for (const [flag, what] of YOLO_FLAGS) {
      if (t.includes(flag)) {
        const name = (/^alias\s+([^=\s]+)/.exec(t) || [])[1];
        out.push(finding("high", "agent", "shell.yoloAlias", `${name ? `Alias "${name}"` : "Shell definition"} launches ${what} (${flag})`, {
          could: "run any tool call without asking you, every time you use the alias",
          detail: `line ${i + 1}`,
          fix: "Keep a separate, explicitly named alias for throwaway sandboxes only.",
          source,
        }));
        break;
      }
    }
  });
  return out;
}

// ---------------------------------------------------------------- MCP

export function mcpServersFromClaudeJson(obj) {
  const names = new Set();
  if (obj && obj.mcpServers && typeof obj.mcpServers === "object") {
    for (const k of Object.keys(obj.mcpServers)) names.add(k);
  }
  if (obj && obj.projects && typeof obj.projects === "object") {
    for (const p of Object.values(obj.projects)) {
      if (p && p.mcpServers && typeof p.mcpServers === "object") {
        for (const k of Object.keys(p.mcpServers)) names.add(k);
      }
    }
  }
  return [...names].sort();
}

// ---------------------------------------------------------------- Kubernetes

export function parseKubeconfig(text) {
  const contexts = [];
  let current = null;
  let top = "";
  for (const raw of String(text).split(/\r?\n/)) {
    if (/^\s*#/.test(raw) || !raw.trim()) continue;
    const topm = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(raw);
    if (topm) {
      top = topm[1];
      if (top === "current-context") current = topm[2].replace(/^["']|["']$/g, "").trim() || null;
      continue;
    }
    if (top === "contexts") {
      const nm = /^\s*-?\s*name:\s*(.+?)\s*$/.exec(raw);
      if (nm) contexts.push(nm[1].replace(/^["']|["']$/g, ""));
    }
  }
  return { contexts, current };
}

export function analyzeKube(parsed, source) {
  const out = [];
  if (!parsed.contexts.length) return out;
  const prod = parsed.contexts.filter((c) => PROD_RX.test(c));
  if (prod.length) {
    out.push(finding("high", "cloud", "kube.prod", `${prod.length} Kubernetes context(s) look like production: ${prod.join(", ")}`, {
      could: `kubectl delete in ${prod.length === 1 ? "a production cluster" : "production clusters"}`,
      detail: `current-context: ${parsed.current || "(none)"}`,
      fix: "Keep production contexts in a separate KUBECONFIG file that agent shells don't load, or use read-only RBAC users for them.",
      source,
    }));
  }
  if (parsed.current && PROD_RX.test(parsed.current)) {
    out.push(finding("high", "cloud", "kube.currentProd", `The current Kubernetes context is production: ${parsed.current}`, {
      could: "change production with a bare kubectl command (no --context needed)",
      fix: "kubectl config use-context <dev-context>",
      source,
    }));
  }
  out.push(finding(prod.length ? "info" : "medium", "cloud", "kube.contexts", `${parsed.contexts.length} Kubernetes context(s) reachable`, {
    could: prod.length ? "" : `change ${parsed.contexts.length} Kubernetes cluster(s)`,
    detail: parsed.contexts.join(", "),
    source,
  }));
  return out;
}

// ---------------------------------------------------------------- GitHub CLI

export function parseGhStatus(text) {
  const accounts = [];
  let cur = null;
  for (const line of String(text).split(/\r?\n/)) {
    const login = /Logged in to (\S+) (?:account|as) (\S+)/.exec(line);
    if (login) {
      cur = { host: login[1], user: login[2].replace(/[()]/g, ""), active: true, scopes: [] };
      accounts.push(cur);
      continue;
    }
    if (cur && /Active account:\s*false/.test(line)) cur.active = false;
    const sc = /Token scopes:\s*(.*)$/.exec(line);
    if (sc && cur) {
      cur.scopes = sc[1].split(",").map((s) => s.trim().replace(/^['"]|['"]$/g, "")).filter((s) => s && s !== "none");
    }
  }
  return accounts;
}

export function analyzeGh(accounts, source) {
  const out = [];
  for (const a of accounts) {
    const who = `${a.user} on ${a.host}${a.active ? "" : " (inactive account)"}`;
    const s = new Set(a.scopes);
    if (s.has("delete_repo")) {
      out.push(finding("high", "publish", "gh.deleteRepo", `GitHub token for ${who} can delete repositories (delete_repo scope)`, {
        could: "delete your GitHub repositories",
        fix: "gh auth refresh -h " + a.host + " -r delete_repo   # removes the scope",
        source,
      }));
    }
    if (s.has("admin:org")) {
      out.push(finding("high", "publish", "gh.adminOrg", `GitHub token for ${who} has admin:org`, {
        could: "change org membership, teams and settings",
        fix: "gh auth refresh -h " + a.host + " -r admin:org",
        source,
      }));
    }
    if (s.has("repo") || s.has("public_repo")) {
      out.push(finding("medium", "publish", "gh.repo", `GitHub token for ${who} can push to every repo you can write to (${s.has("repo") ? "repo" : "public_repo"} scope)`, {
        could: "push, force-push and open PRs as you",
        fix: "For agent work, use a fine-grained token limited to the repos it needs (GH_TOKEN in that shell only).",
        source,
      }));
    }
    if (s.has("workflow")) {
      out.push(finding("medium", "publish", "gh.workflow", `GitHub token for ${who} can edit GitHub Actions workflows (workflow scope)`, {
        could: "change CI workflows (and the secrets they can read)",
        source,
      }));
    }
  }
  return out;
}

// ---------------------------------------------------------------- SSH keys

function b64ToBytes(b64) {
  if (typeof globalThis.atob === "function") {
    const bin = globalThis.atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return null;
}

// Returns {isPrivate, encrypted: true|false|null, format}
export function sshKeyInfo(text) {
  const s = String(text);
  const begin = /-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----/.exec(s);
  if (!begin) return { isPrivate: false, encrypted: null, format: null };
  const kind = begin[1].trim();
  if (kind === "ENCRYPTED") return { isPrivate: true, encrypted: true, format: "pkcs8" };
  if (kind === "OPENSSH") {
    const body = s.split(/\r?\n/).filter((l) => l && !l.startsWith("-----")).join("");
    const bytes = b64ToBytes(body.slice(0, 200).replace(/[^A-Za-z0-9+/=]/g, "").slice(0, 96));
    if (!bytes) return { isPrivate: true, encrypted: null, format: "openssh" };
    const magic = "openssh-key-v1";
    for (let i = 0; i < magic.length; i++) {
      if (bytes[i] !== magic.charCodeAt(i)) return { isPrivate: true, encrypted: null, format: "openssh" };
    }
    let o = magic.length + 1; // NUL
    const len = (bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3];
    o += 4;
    let cipher = "";
    for (let i = 0; i < len && o + i < bytes.length; i++) cipher += String.fromCharCode(bytes[o + i]);
    return { isPrivate: true, encrypted: cipher !== "none", format: "openssh", cipher };
  }
  // Legacy PEM (RSA / EC / DSA)
  return { isPrivate: true, encrypted: /Proc-Type:\s*4,ENCRYPTED/.test(s), format: "pem" };
}

// ---------------------------------------------------------------- mounts

const NETWORK_FS = new Set(["smbfs", "nfs", "nfs4", "afpfs", "cifs", "webdav", "fuse.sshfs", "sshfs", "fuse.rclone", "macfuse", "osxfuse", "fuse.s3fs", "9p", "davfs", "fuse.davfs2"]);

// macOS: "//u@host/share on /Volumes/x (smbfs, nodev, nosuid, mounted by me)"
// Linux: "host:/x on /mnt/x type nfs4 (rw,relatime,...)"
export function parseMount(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    let m = /^(.+?) on (.+?) type (\S+) \(([^)]*)\)/.exec(line);
    if (m) {
      out.push({ device: m[1], point: m[2], fstype: m[3], opts: m[4].split(",").map((x) => x.trim()) });
      continue;
    }
    m = /^(.+?) on (.+?) \(([^)]*)\)/.exec(line);
    if (m) {
      const parts = m[3].split(",").map((x) => x.trim());
      out.push({ device: m[1], point: m[2], fstype: parts[0], opts: parts.slice(1) });
    }
  }
  return out;
}

export function classifyMount(mt, platform) {
  const ro = mt.opts.includes("ro") || mt.opts.includes("read-only");
  if (NETWORK_FS.has(mt.fstype) || mt.fstype.startsWith("fuse.")) return { kind: "network", ro };
  if (platform === "darwin") {
    if (mt.point.startsWith("/Volumes/") && !mt.point.startsWith("/Volumes/Recovery")) return { kind: "external", ro };
    return { kind: "system", ro };
  }
  if (/^\/(mnt|media|run\/media)\//.test(mt.point)) return { kind: "external", ro };
  return { kind: "system", ro };
}

// ---------------------------------------------------------------- env

const SECRET_NAME_RX = /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|_AUTH$|^AUTH_|DATABASE_URL|_DSN$|CONNECTION_STRING|WEBHOOK)/i;
const NOT_SECRET = new Set(["SSH_AUTH_SOCK", "GPG_AGENT_INFO", "KEYTIMEOUT", "TOKENIZERS_PARALLELISM", "GIT_ASKPASS", "SSH_ASKPASS", "SUDO_ASKPASS", "VSCODE_GIT_ASKPASS_MAIN", "VSCODE_GIT_ASKPASS_NODE", "VSCODE_GIT_ASKPASS_EXTRA_ARGS", "VSCODE_GIT_IPC_HANDLE"]);

export function secretEnvNames(env) {
  return Object.keys(env || {}).filter((k) => !NOT_SECRET.has(k) && SECRET_NAME_RX.test(k) && String(env[k] || "").length > 0).sort();
}

export function dbUrlIsRemote(url) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)/i.exec(String(url || ""));
  if (!m) return null;
  const host = m[1].toLowerCase();
  return !(host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host.endsWith(".local") || host === "db" || host === "postgres" || host === "mysql");
}

// ---------------------------------------------------------------- summary

export function sortFindings(list) {
  return [...list].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.area.localeCompare(b.area));
}

export function summarize(list) {
  const counts = { high: 0, medium: 0, info: 0 };
  for (const f of list) counts[f.severity]++;
  const could = [];
  const seen = new Set();
  for (const f of sortFindings(list)) {
    if (f.severity === "info" || !f.could || seen.has(f.could)) continue;
    seen.add(f.could);
    could.push({ severity: f.severity, text: f.could });
  }
  return { counts, could };
}
