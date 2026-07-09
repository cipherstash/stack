---
"stash": patch
---

Refresh the bundled `stash-cli` agent skill and the CLI README against the current
command surface. The skills directory ships inside the `stash` tarball and is copied
into the user's `.claude/skills/` / `.codex/skills/` (or inlined into `AGENTS.md`) at
handoff time, so a stale skill becomes stale guidance in the user's project.

- **New `Start here` and `Authentication` sections.** Setup is driven through the CLI:
  agents read `stash manifest --json` first, then trigger `stash auth login --json` and
  surface the verification URL for a human to approve, then run `stash init`. Authenticating
  before `init` matters — `init`'s auth step is interactive and would otherwise try to open
  a browser on the agent's host.
- **New `Never read these` invariant**, mirrored into the `AGENTS.md` doctrine: agents must
  never read `~/.cipherstash/secretkey.json`, `~/.cipherstash/auth.json`, anything under
  `~/.cipherstash/workspaces/`, or `.env*`. The wizard already blocks these paths in code;
  the other handoff targets had no written rule.
- **Documents `manifest`, `doctor`, `wizard`, and `auth regions`**, which the skill omitted
  entirely, plus the non-interactive interface (per-command escape hatches, exit codes, the
  `DATABASE_URL` resolution order, the `auth login --json` NDJSON event contract).
- **Corrects the `db` → `eql` move.** `db install`, `db upgrade`, and `db status` are
  deprecated aliases that warn and forward; `db push`, `db activate`, `db validate`,
  `db test-connection`, and `db migrate` remain in the `db` group.
- **Scopes `db push` / `db activate` as EQL v2 + CipherStash Proxy only**, in both the skill
  and the README's recommended flow. SDK users hold their encryption config in application
  code and don't need them.
- Adds the missing `--database-url`, `--eql-version`, `--prisma-next`, `--proxy`/`--no-proxy`,
  and `--region` flags; corrects six programmatic API signatures; fixes the README's claim
  that `stash init` ends in an agent-handoff menu (that belongs to `stash plan` / `stash impl`);
  and marks `stash env` as the non-functional stub it currently is.
