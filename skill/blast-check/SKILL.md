---
name: blast-check
description: Before a long, unattended or risky agent run (overnight jobs, bypass/YOLO mode, migrations, cleanup scripts, anything that deletes), scan what this shell could reach with blastmap and propose the smallest changes that shrink it. Use when the user says "before I leave this running", "check my blast radius", "is it safe to run in bypass mode", or asks what an agent could delete.
---

# blast-check

Find out what a coding agent started from this shell could delete, publish or change, then shrink it before the run starts.

## Steps

1. Run the scan (read-only, never prints secret values):

   ```bash
   npx -y github:thinx-pro/blastmap --json
   ```

   If `npx` is unavailable, tell the user and stop. Don't try to work out the same things by reading credential files yourself.

2. Read `could` (plain-language capabilities) and the `high` findings first. Ignore `info` unless the user asks.

3. Tell the user in at most 8 lines:
   - the 3–5 most serious things the run could do (from `could`), worst first
   - for each, the smallest change that removes it **for this run only**, taken from the finding's `fix` or a narrower version of it. Prefer reversible, per-shell changes:
     - `unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY GH_TOKEN GITHUB_TOKEN` in the shell that launches the agent
     - `kubectl config use-context <non-prod>` or `export KUBECONFIG=<dev-only file>`
     - eject backup drives and unmount network shares that the task doesn't need
     - add `deny` rules (e.g. `Bash(rm -rf:*)`, `Read(./.env*)`) to the project's `.claude/settings.local.json`
     - `ssh-add -D` before an unattended run

4. Do **not** change credentials, revoke tokens, edit global config, unmount anything or delete anything yourself. Show the commands and let the user run them. A project-local `.claude/settings.local.json` deny rule is the only change you may offer to write, and only after the user says yes.

5. If the user goes ahead with the changes, run step 1 again and report the before/after counts (`counts.high`, `counts.medium`).

## Notes

- `--only agent,cloud` limits the scan; `--no-exec` skips `gh auth status`, `ssh-add -l`, `sudo -n true`, `mount` and `tmutil`.
- The scan sees the shell it runs in. If the agent will be launched from a different shell, terminal or launchd job, say that the result applies to this shell only.
