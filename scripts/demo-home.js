// Builds a fake home directory with typical agent-reachable credentials, for
// tests and for the README screenshot. Everything in it is made up.
// Usage: node scripts/demo-home.js <dir>
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function sshKey(cipher) {
  const magic = Buffer.from("openssh-key-v1\0", "latin1");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(cipher.length);
  const body = Buffer.concat([magic, len, Buffer.from(cipher, "latin1"), Buffer.alloc(48, 7)]);
  const b64 = body.toString("base64").match(/.{1,70}/g).join("\n");
  const word = "PRIVATE" + " KEY";
  return `-----BEGIN OPENSSH ${word}-----\n${b64}\n-----END OPENSSH ${word}-----\n`;
}

export function buildDemoHome(root) {
  const w = (rel, content) => {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content);
  };
  w(".claude/settings.json", JSON.stringify({
    permissions: {
      defaultMode: "bypassPermissions",
      allow: ["Bash(git:*)", "Bash(npm run test:*)", "Bash(gh pr view:*)", "Bash(rm -rf:*)"],
      deny: [],
    },
  }, null, 2));
  w(".claude.json", JSON.stringify({ mcpServers: { github: {}, postgres: {} }, projects: { "/work/app": { mcpServers: { linear: {} } } } }));
  w(".codex/config.toml", 'model = "gpt-6.1-sol"\n\n[profiles.night]\napproval_policy = "never"\nsandbox_mode = "danger-full-access"\n');
  w(".zshrc", 'export PATH="$HOME/bin:$PATH"\nalias cc="claude --dangerously-skip-permissions"\n');
  w(".aws/credentials", "[default]\naws_access_key_id = DEMO_NOT_A_KEY\naws_secret_access_key = demo\n\n[acme-prod]\naws_access_key_id = DEMO_NOT_A_KEY_2\naws_secret_access_key = demo\n");
  w(".kube/config", "apiVersion: v1\nclusters: []\ncontexts:\n- context:\n    cluster: kind-dev\n    user: kind-dev\n  name: kind-dev\n- context:\n    cluster: eks-prod\n    user: admin\n  name: eks-prod-us-east-1\ncurrent-context: eks-prod-us-east-1\nkind: Config\nusers: []\n");
  w(".npmrc", "//registry.npmjs.org/:_authToken=DEMO_NOT_A_TOKEN\n");
  w(".ssh/id_ed25519", sshKey("none"));
  w(".ssh/id_work", sshKey("aes256-ctr"));
  w(".ssh/config", "Host db-prod-1\n  HostName 10.0.0.5\nHost staging\n  HostName 10.0.1.5\n");
  w(".pgpass", "db.example.internal:5432:app:app:demo\n");
  w(".config/rclone/rclone.conf", "[gdrive]\ntype = drive\n\n[backups-b2]\ntype = b2\n");
  fs.mkdirSync(path.join(root, "Library", "CloudStorage", "Dropbox"), { recursive: true });
  fs.mkdirSync(path.join(root, "Library", "Mobile Documents", "com~apple~CloudDocs", "Documents"), { recursive: true });
  fs.mkdirSync(path.join(root, "project"), { recursive: true });
  w("project/.env", "STRIPE_SECRET_KEY=demo\nPORT=3000\nDATABASE_URL=postgres://u:p@db.example.internal/app\n");
  w("project/.env.example", "STRIPE_SECRET_KEY=\n");
  return root;
}

export const DEMO_GH_STATUS = `github.com
  ✓ Logged in to github.com account octocat (keyring)
  - Active account: true
  - Git operations protocol: https
  - Token: gho_************************************
  - Token scopes: 'delete_repo', 'gist', 'read:org', 'repo', 'workflow'
`;

export const DEMO_MOUNT = `/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
devfs on /dev (devfs, local, nobrowse)
//demo@nas.local/footage on /Volumes/footage (smbfs, nodev, nosuid, mounted by demo)
/dev/disk5s2 on /Volumes/Backup (apfs, local, nodev, nosuid, journaled, noowners)
`;

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const dir = process.argv[2];
  if (!dir) { console.error("usage: node scripts/demo-home.js <dir>"); process.exit(2); }
  buildDemoHome(path.resolve(dir));
  console.log(path.resolve(dir));
}
