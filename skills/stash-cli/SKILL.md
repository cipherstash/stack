---
name: stash-cli
description: Drive CipherStash setup and encryption migrations through the `stash` CLI — `init`, `plan`, `impl`, `status`, `auth login`, `eql install/upgrade/status`, `db validate`, `encrypt backfill/cutover/drop`, `schema build`, and `manifest --json`. Covers the agent / non-interactive interface, the credential rules for `~/.cipherstash`, and the rollout-then-cutover lifecycle. Use when setting up CipherStash EQL in a database, running any `stash` command, creating `stash.config.ts`, or rolling encryption out to production.
---

# CipherStash CLI (`stash`)

`stash` is the **dev-time CLI** for CipherStash. It owns authentication, project setup, the EQL (Encrypted Query Language) Postgres extension, and the machinery that migrates an existing plaintext column to an encrypted one. Its runtime counterpart is `@cipherstash/stack`, which encrypts and decrypts values in your application.

Think Prisma Migrate or Drizzle Kit: a dev-time tool that prepares the database, while the runtime SDK handles queries.

**All setup and migration work is driven through this CLI.** Don't hand-write EQL SQL, don't hand-edit `.cipherstash/`, and don't introspect the database yourself. The CLI owns that state; hand-edits desync it.

## Trigger

Use this skill when:

- The user wants to set up CipherStash or install EQL in a PostgreSQL database.
- Any `stash` command is being run: `init`, `plan`, `impl`, `status`, `auth`, `eql`, `db`, `encrypt`, `schema`, `manifest`, `doctor`, `telemetry`, `wizard`, `env`.
- A `stash.config.ts` file exists or needs to be created.
- A `.cipherstash/` directory exists (`context.json`, `plan.md`, `migrations.json`, `setup-prompt.md`).
- The user mentions "stash CLI", "EQL install", "encryption schema", or an encryption rollout/cutover.

Do **not** trigger when:

- Working with `@cipherstash/stack` (the runtime SDK) with no database setup involved — see the `stash-encryption` skill.
- Running the AI wizard directly — that's `@cipherstash/wizard`, a separate package.
- General PostgreSQL questions unrelated to CipherStash.

## Start here

The entry point, for humans and agents alike:

```bash
npx stash init              # PostgreSQL / Drizzle / Prisma
npx stash init --supabase   # Supabase
```

`stash init` installs the CLI as a project dev dependency, so subsequent commands can drop the `npx`. The CLI is package-manager aware — before init, use whichever one-shot runner your project uses (`npx`, `pnpm dlx`, `bunx`, `yarn dlx`). Installs are **pinned to the exact `@cipherstash/*` versions this CLI release shipped with** (never bare dist-tags, which can lag behind a release), and init flags any already-installed `@cipherstash/*` package whose resolved version differs from the release's. The fix depends on direction, and init says which applies: an **older** install should be aligned to the release (init offers the exact command); a **newer** install must NOT be downgraded — update the `stash` CLI to the matching release instead (init prints that command too). **Non-interactively, an older ("behind") skew is fatal** — init refuses with a non-zero exit and the align command rather than scaffolding against mismatched packages and reporting a false success. Interactively it offers to align. Likewise, if the EQL extension isn't installed at the end, init reports **"Setup incomplete"** and exits non-zero — it never claims a setup is complete when encryption would fail at query time. Integrations that install EQL through a migration are the exception and exit 0: **Prisma Next** installs it via the top-level `prisma-next migrate`, and the **Drizzle** flow *generates* an EQL migration, which init reports honestly as "EQL migration generated — apply it with `drizzle-kit migrate`" rather than claiming the extension is already installed.

**If you are an agent, do this first:**

1. **`npx stash manifest --json`** — the structured, version-stamped command surface. Read it before running anything else.
2. **`npx stash auth login --json --region <slug>`** — only if not already authenticated. Surface the URL to the human (see [Authentication](#authentication)). Do this *before* `init`.
3. **`npx stash init`** — now finds the token and proceeds without prompting.
4. **`stash plan` → `stash impl` → `stash status`** — pass `--target` when non-interactive.

### Ask the CLI, don't trust this file

```bash
npx stash manifest --json    # full command surface, stamped with the CLI version
npx stash <command> --help   # per-command flags, defaults, env vars, examples
```

`manifest --json` emits `{ name, version, groups[] }`, where each group has a `title` and `commands[]`, and each command carries `name`, `summary`, optional `long` and `examples[]`, and `flags[]` of `{ name, value?, description, default?, env? }`. `version` is the CLI's own, so anything generated from it names the version it describes. It is pure metadata, so it runs even when the native binary is broken.

`stash <cmd> --help` renders from the same registry: an exact match prints full help, a group prefix (`stash eql`) lists its subcommands.

**This file describes intent and lifecycle. The manifest is authoritative for flags.** If the two disagree, the manifest is right and this file is stale.

## Authentication

```bash
npx stash auth login
npx stash auth regions          # discover valid --region values
```

`auth login` runs an OAuth 2.0 device-code flow: pick a region, approve in a browser, then the device is bound to the workspace's default keyset. Credentials and a development key are written to the `~/.cipherstash` profile. Later commands authenticate from there without a fresh login.

**Agents: you can trigger the flow, but only a human can complete it.**

```bash
npx stash auth login --json --region us-east-1
```

`--json` emits newline-delimited JSON on stdout, one object per line, and deliberately does *not* open a browser — the human opens the URL, not the agent's host.

| Event | Meaning |
|---|---|
| `{ status: "authorization_required", userCode, verificationUri, verificationUriComplete, expiresIn }` | Emitted immediately. **Show `verificationUriComplete` to the user and wait.** |
| `{ status: "authorized", expiresAt, expiresAtIso }` | The human approved. |
| `{ status: "device_bound" }` | Device bound to the default keyset. Done. |
| `{ status: "error", code, message }` | Failure. Exit code 1. |

Operationally: after printing `authorization_required` the command **blocks,
polling, until the human approves or the code expires** (`expiresIn` is
~900 s). So run it as a background/async task with a generous timeout —
a short-timeout synchronous run kills the poll and the login never lands.
The working loop is:

1. Start `npx stash auth login --json --region <slug>` in the background.
2. Read the first stdout line; relay `verificationUriComplete` to the human
   (include `userCode` so they can cross-check what they're approving, and
   mention the ~15-minute expiry).
3. Leave the process running. Success is **exit 0 with `device_bound` as the
   final event** — the session and development key are then in the profile
   and every later command authenticates silently.
4. To confirm, trust the event stream or run any authenticated command —
   never inspect `~/.cipherstash` (see "Never read these").

**Authenticate before `stash init`.** Init's authenticate step uses the interactive path, so an agent running `init` unauthenticated makes the CLI try to open a browser on the agent's machine — and in a non-TTY it exits with `region_required` unless `--region` or `STASH_REGION` is set. Once a valid token exists, init logs `Using workspace X (region)` and moves on silently.

Flags: `--region <slug>` (env `STASH_REGION`), `--json`, `--no-open`, `--supabase` / `--drizzle` (referrer tracking only).

## Never read these

The CLI holds your credentials and reads them itself. No command needs you to open them.

**Never read, `cat`, `grep`, or echo:**

- `~/.cipherstash/secretkey.json` — the development key
- `~/.cipherstash/auth.json` — OAuth token and JWTs
- anything under `~/.cipherstash/workspaces/`
- value-bearing env files — `.env`, `.env.local`, `.env.production`, … — and any credentials file

`.env.example` is the exception: it holds placeholders, not values, and you are expected to edit it.

Referring to env key *names* (`CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, `CS_CLIENT_KEY`, `CS_CLIENT_ACCESS_KEY`, `DATABASE_URL`) in code and docs is fine. Their *values* are not. New keys go into `.env.example` as placeholders; ask the user to fill in the real value locally.

If a command fails on authentication, re-run `stash auth login`. Do not inspect the profile to diagnose it.

## Running non-interactively (agents, CI, pipes)

A command is interactive only when **stdin is a TTY and `CI` is not set** to `1`/`true` (case-insensitive). Otherwise prompts are skipped.

There is **no global `--non-interactive` or `--json` flag** (and no global `--yes` — but a few commands carry a scoped one, e.g. `plan --complete-rollout --yes`). Each command carries its own escape hatch:

| Need | Escape hatch |
|---|---|
| Region (`auth login`, `init`) | `--region <slug>` or `STASH_REGION` |
| Database URL (all `db` / `eql` / `schema` commands) | `--database-url <url>` or `DATABASE_URL` |
| Agent target (`plan`, `impl`) | `--target <claude-code\|codex\|agents-md\|wizard>` |
| Proxy choice (`init`) | `--proxy` / `--no-proxy` (default) |
| Dual-write confirmation (`encrypt backfill`) | `--confirm-dual-writes-deployed` |
| Machine-readable output | `--json` on `status`, `manifest`, `auth login`, `auth regions` |

When a required value is missing in a non-TTY context, the command exits non-zero with an actionable message naming the flag and env var — it never hangs.

**`plan` and `impl` need `--target` in a non-TTY.** Their agent-target picker reads from `/dev/tty`. Without `--target` they print a "no agent selected" hint and exit 0 *without performing the handoff*. `init` and `status` adapt automatically and are safe anywhere.

**Exit codes.** `1` on failure; `0` when a user cancels a prompt. In `--json` mode an `{ "status": "error", "code", "message" }` line is emitted before exiting 1.

**`stash status --json` has a stable shape** — `{ initialized, planExists, observedFromDb, active[], completed[] }`, each quest carrying `{ table, column, path, title, progress, complete, nextMove, objectives[] }`. It will not change without a major version bump. Prefer it over parsing `--plain`.

### How `DATABASE_URL` is resolved

First hit wins:

1. `--database-url <url>` flag
2. `DATABASE_URL` environment variable (including `.env*` files, loaded automatically)
3. `supabase status --output env` — only when `--supabase` is set or `supabase/config.toml` is detected
4. Interactive prompt — skipped under CI / non-TTY
5. Hard fail, naming the sources it tried

`stash.config.ts` is **not** a separate tier: the scaffolded config calls this same resolver, and the `--database-url` flag still wins. The one exception is a hand-edited config assigning a literal `databaseUrl` string — that bypasses the resolver entirely and beats both flag and env.

The resolved URL is returned in memory only. It is never written to disk or into `process.env`.

## Telemetry

The CLI collects **anonymous, opt-out** usage analytics — coarse events only
(command name, CLI version, OS/arch, Node version, success/failure, duration,
and a coarse caller class such as `claude-code`/`cursor`/`interactive` derived
from environment markers). Events carry a random install identifier — a UUID
generated locally and stored in `~/.cipherstash/telemetry.json`, not derived
from any machine, user, or hardware attribute — used only to de-duplicate
events in aggregate. It **never** collects plaintext, schema, table/column
names, connection strings, argument values, or any session/trace identifier. A
one-time notice is printed on first run, and nothing is sent on that first run.

Opt out in any of these ways (any one wins; env vars override the saved
preference):

| Mechanism | Effect |
|---|---|
| `DO_NOT_TRACK=1` | Honors the cross-tool standard; disables telemetry |
| `STASH_TELEMETRY_DISABLED=1` | Disables telemetry |
| `CI=true` (or common CI markers) | Auto-disabled in CI |
| `npx stash telemetry disable` | Persists opt-out to `~/.cipherstash/telemetry.json` |

`npx stash telemetry status` reports the current state and which setting governs
it; `npx stash telemetry enable` clears the saved opt-out (env overrides still
apply). State lives in `~/.cipherstash/telemetry.json` — a non-secret file
distinct from the auth credentials in that directory.

## Configuration

`stash.config.ts` in the project root:

```typescript
import { defineConfig } from 'stash'

export default defineConfig({
  databaseUrl: process.env.DATABASE_URL!,
  client: './src/encryption/index.ts',
})
```

| Option | Required | Default | Purpose |
|---|---|---|---|
| `databaseUrl` | yes | — | PostgreSQL connection string |
| `client` | no | `./src/encryption/index.ts` | Encryption client, loaded by `db validate`, `schema build`, `encrypt *` |

Resolved by walking up from `process.cwd()`, like `tsconfig.json`. `stash init` scaffolds it; `stash eql install` offers to.

## Setup lifecycle

Four explicit save-points. Each runs standalone; chain prompts make first-time setup one flow.

| Command | Owns | Ends with |
|---|---|---|
| `stash init` | Auth, database, proxy choice, encryption client, deps, EQL install, `.cipherstash/context.json` | Default-yes prompt → chains to `stash plan` |
| `stash plan` | Drafts `.cipherstash/plan.md` via agent handoff. State-driven: auto-detects rollout vs. cutover. | Default-yes prompt → chains to `stash impl` |
| `stash impl` | Executes the plan via agent handoff. Enforces the deploy gate. | Deploy-gate banner (rollout) or "verify state" |
| `stash status` | The rollout quest log — per-column "where am I", runs in ms | — |

### `init` — scaffold

Seven mechanical steps, no agent handoff. It prompts only when it can't pick a sensible default.

1. **Authenticate** — silent when a valid token exists.
2. **Resolve database** — per the resolution order above; verifies the connection.
3. **Resolve proxy choice** — CipherStash Proxy or direct SDK access (the default). Stored as `usesProxy` in `context.json`. Set by `--proxy` / `--no-proxy`; non-TTY without a flag defaults to SDK.
4. **Build schema** — auto-detects Drizzle (`drizzle.config.*`, `drizzle-orm`/`drizzle-kit`), Supabase (from the `DATABASE_URL` host), and Prisma Next. Writes a placeholder encryption client; prompts only if a file already exists there.
5. **Install dependencies** — one combined prompt for `@cipherstash/stack` and `stash`. Skipped when both are present.
6. **Install EQL** — always EQL v3. **Drizzle** projects generate a v3 install migration (the same output as `eql migration --drizzle`, including the `cs_migrations` tracking schema) so the install lands in your migration history — apply it with `drizzle-kit migrate`; requires `drizzle-kit` to be installed and configured. **Prisma Next** is skipped (it installs EQL via `prisma-next migrate`). Everything else runs `eql install` directly against the resolved database, and is skipped when EQL is already installed.
7. **Gather context** — detects available coding agents and writes `.cipherstash/context.json`.

Flags: `--supabase`, `--drizzle`, `--prisma-next`, `--proxy` / `--no-proxy`, `--region <slug>`.

| Generated file | Purpose |
|---|---|
| `./src/encryption/index.ts` | Placeholder encryption client — declare encrypted columns here, or let `plan`/`impl` do it |
| `.cipherstash/context.json` | Detected facts: integration, package manager, schemas, env key names, agents, `usesProxy`. CLI-owned; never hand-edit |
| `stash.config.ts` | Scaffolded if missing |

### `plan` — draft for review

```bash
stash plan
stash plan --complete-rollout                          # interactive: default-no confirm
stash plan --complete-rollout --yes --target claude-code   # non-interactive / CI
stash plan --target claude-code
```

Pre-flights `.cipherstash/context.json` (errors with "Run `stash init` first" if missing), then hands off to a coding agent: Claude Code, Codex, AGENTS.md (Cursor/Windsurf/Cline), or the CipherStash Agent (`@cipherstash/wizard`).

`plan` is **state-driven**. It reads `.cipherstash/migrations.json` and `cs_migrations`:

| Detected state | Plan written |
|---|---|
| No `dual_writing` event recorded | **Encryption rollout** — schema-add + dual-write code. Ends at the deploy gate. |
| A column has `dual_writing` or later | **Encryption cutover** — backfill, schema rename, read-path switch, drop. Requires the rollout to be deployed. |
| `--complete-rollout` passed | **Complete rollout** — schema-add through drop, no deploy gate. Needs consent: an interactive default-no confirm, or `--yes` non-interactively (without it, a non-interactive run **exits non-zero without drafting** rather than silently doing nothing). |

The agent writes a machine-readable header into the plan:

```
<!-- cipherstash:plan-summary { "step": "rollout"|"cutover"|"complete", "columns": [...] } -->
```

Each column carries `path: "new" | "migrate"`. `stash impl` parses this to render its confirmation panel and enforce the deploy gate.

To re-plan, delete `.cipherstash/plan.md` first — otherwise the agent is told to revise it rather than start fresh. `--complete-rollout` is the escape hatch for databases with no deployed application (local dev, sandboxes, test DBs); it's only safe when nothing in production writes to that database.

**The outro reports what actually happened.** The plan file is written by the handed-off agent, so `plan` verifies it on disk before claiming anything: `Plan drafted at .cipherstash/plan.md` appears only when the file exists after the handoff. If a launched agent exits without writing it, `plan` errors and **exits non-zero**. Deferred handoffs — `--target agents-md`, or a Claude Code / Codex target whose CLI isn't installed — end with `No plan drafted yet` and exit 0: the plan lands later, when you drive the agent yourself. A pre-existing plan the run didn't modify is reported as `left unchanged by this run`, not drafted. Either way, check that `.cipherstash/plan.md` exists before acting on it.

### `impl` — execute

```bash
stash impl
stash impl --target claude-code
stash impl --continue-without-plan
```

Behaviour depends on disk state. With a plan: parses the summary, enforces the deploy gate, confirms, then hands off. Without a plan in a TTY: offers "draft a plan first (recommended)" / "continue without a plan" (behind a default-no security confirm). Without a plan in a non-TTY: errors unless `--continue-without-plan` is passed, forcing explicit intent in CI.

`--continue-without-plan` skips *planning*, not safety. The security confirm still fires interactively, and the deploy gate applies regardless.

**Deploy-gate enforcement.** For a `cutover` plan, `impl` checks `cs_migrations` for a `dual_writing` (or later) event on every column in the plan summary. If any is missing it refuses, naming the columns. This catches the case where someone runs cutover work locally before the dual-write code is actually live in production.

After a successful `rollout` handoff, `impl` prints a deploy-gate banner: encrypted values are not flowing yet. After `cutover` or `complete`, it points at `stash status`.

### `status` — the rollout quest log

```bash
stash status
stash status --json     # stable shape, for scripts and agents
stash status --plain    # force plain text
stash status --quest    # force the fancy output
```

Reads `context.json`, `migrations.json`, and — best-effort — `cs_migrations` plus live EQL state. Database connectivity is optional; without it you get a manifest-only view and a footer note.

Renders one quest per tracked column: a title, a progress bar, objectives (`✓` done, `▸` active, `🔒` locked), and a one-line "Next move" naming the concrete command. Quests split into **active** and **completed**. Defaults to the quest shape in a TTY, plain text elsewhere.

**Re-read it after every transition** rather than tracking rollout state mentally. For raw database-only views, use `stash eql status` and `stash encrypt status`.

## Rolling encryption out to production

Two paths to a fully-encrypted column:

- **New encrypted column** — declared encrypted from the start. Single deploy. Run `plan` → `impl` straight through.
- **Existing column with live data** — two passes around a hard production-deploy gate: `plan` → `impl` → **you deploy the rollout PR** → `status` → `plan` → `impl`.

The split is invisible — keep running `plan` and `impl`; the CLI reads `cs_migrations` and knows where you are.

### Why the split exists

There is no atomic way to replace a populated plaintext column with an encrypted one without corrupting data. The rollout phase deploys the *capability* to write encrypted values (the twin column and the dual-write code). The cutover phase deploys the *transition*: backfill historical rows, rename-swap the columns, switch the application read path through the encryption client, then drop the plaintext column.

Backfill is only safe once dual-writes are running in production. Any row written *during* the backfill window must land in both columns — otherwise it stays plaintext-only and creates silent migration drift. The gate makes that precondition explicit.

## Command reference

Flags below are the decision-relevant ones. Run `stash <command> --help` for the complete, version-accurate list.

### Setup & workflow

| Command | Purpose |
|---|---|
| `init` | Scaffold a project (above) |
| `plan` | Draft `.cipherstash/plan.md` (above) |
| `impl` | Execute the plan (above) |
| `status` | Rollout quest log (above) |
| `manifest [--json]` | Print the structured, versioned command surface |
| `doctor` | Diagnose install problems (native binaries, runtime). Runs before the CLI body loads, so it works when the native binary is broken. |
| `telemetry [status\|enable\|disable]` | Manage anonymous usage analytics (below) |
| `wizard` | AI-guided encryption setup — thin wrapper over `@cipherstash/wizard` |

### Auth

`auth login`, `auth regions` — see [Authentication](#authentication).

### EQL

```bash
stash eql install
stash eql migration --drizzle
stash eql upgrade
stash eql status
```

> `stash db install`, `db upgrade`, and `db status` still work but print a deprecation warning and forward to `eql <sub>`. Use the `eql` spelling.

#### `eql install`

Gets a project from zero to installed EQL. It loads an existing `stash.config.ts` (or offers to scaffold one), scaffolds the encryption client if missing, then auto-detects the install path: **Drizzle** generates a migration via `drizzle-kit generate --custom` (apply it with `npx drizzle-kit migrate`); **Supabase without Drizzle** prompts between a migration file and a direct install, pre-selecting migration when `supabase/migrations/` exists; otherwise it installs directly.

| Flag | Description |
|---|---|
| `--force` | Reinstall even if EQL is present |
| `--dry-run` | Show what would happen |
| `--supabase` | Supabase-compatible install (no operator families; grants `anon`, `authenticated`, `service_role`) |
| `--drizzle` | Generate a Drizzle migration (`--name`, `--out` tune it — `--name` accepts letters, numbers, `-`, `_` only; `--out` is passed to `drizzle-kit --out`, so set it to match your `drizzle.config.ts`) |
| `--migration` / `--direct` | Supabase: write a migration file, or run SQL directly |
| `--migrations-dir <path>` | Supabase migrations directory (default `supabase/migrations`) |
| `--exclude-operator-family` | Skip operator families (non-superuser roles) |
| `--eql-version <2\|3>` | EQL generation. **Default `3`** (the native `public.eql_v3_*` domain schema — the documented approach). `2` is the legacy composite schema. |
| `--latest` | Fetch latest EQL from GitHub instead of the bundled copy (**v2 only**) |
| `--database-url <url>` | One-shot install (see below) |

`--migration`, `--direct`, and `--migrations-dir` require an explicit `--supabase`; they never auto-enable it.

**`eql install` for EQL v3 runs the direct path only.** Passing `--eql-version 3` with an explicit `--drizzle`, `--migration`, `--migrations-dir`, or `--latest` is an error. When Drizzle or a Supabase migrations directory is merely *auto-detected*, v3 falls back to a direct install and prints a notice. To get a **v3 install as a migration** (preferred for real projects), use `eql migration` (below) instead of `eql install --drizzle`.

**`--database-url` is a one-shot.** It installs against that database and leaves the project untouched — no config is loaded, and none is scaffolded, nor is an encryption client. This lets `npx stash eql install --database-url postgres://...` run in a bare project with no CipherStash dependencies. It also means the flag always wins: loading a config could pick up a parent-directory `databaseUrl` literal and install against the wrong database.

**`eql install --supabase --migration`** writes `supabase/migrations/00000000000000_cipherstash_eql.sql`. The all-zero timestamp guarantees it runs before any user migration referencing `eql_v2_encrypted`. Apply with `supabase db reset` (local) or `supabase migration up` (remote).

Direct installs (`--supabase --direct`) do **not** survive `supabase db reset` — the reset drops the database and replays only files in `supabase/migrations/`. Use `--migration` if you reset.

#### `eql migration`

Generates an **EQL v3 install migration** for your ORM, instead of running SQL directly against the database (`eql install`). Migration-first is the preferred path: the install lands in your migration history and ships to every environment through the ORM's own migrate step. v3 only — there is no `--eql-version` here.

```bash
stash eql migration --drizzle              # Drizzle custom migration in drizzle/
stash eql migration --drizzle --supabase   # also grant eql_v3 to anon/authenticated/service_role
```

| Flag | Description |
|---|---|
| `--drizzle` | Emit a Drizzle custom migration (via `drizzle-kit generate --custom`, then inject the SQL). Requires `drizzle-kit`. |
| `--prisma` | Emit a Prisma Next migration. **Not available yet** — the emitter is a follow-up (tracked in GitHub issue #690); fails with a pointer for now. Use `--drizzle` today. |
| `--supabase` | Append the Supabase role grants (`eql_v3` + `eql_v3_internal` → `anon`, `authenticated`, `service_role`). Harmless when you connect directly as `postgres`; needed when the same tables are reached via PostgREST/RLS. |
| `--name <name>` | Migration name (Drizzle). Default `install-eql`. Letters, numbers, `-`, and `_` only — anything else is rejected. |
| `--out <path>` | Output directory (Drizzle). Default `drizzle`. Passed straight to `drizzle-kit --out`, so set it to match your `drizzle.config.ts` if that writes elsewhere. |
| `--dry-run` | Show what would happen without writing anything. |

Pass exactly one of `--drizzle` / `--prisma`. The generated migration also installs the `cs_migrations` tracking schema, so one `drizzle-kit migrate` covers everything `stash encrypt …` needs.

After writing the migration, `--drizzle` sweeps the output directory for sibling migrations containing an in-place `ALTER COLUMN … SET DATA TYPE <eql_v2_encrypted | eql_v3_*>` — drizzle-kit emits these when you change a plaintext column to an encrypted one, and Postgres rejects them (there is no cast from `text`/`numeric` to an EQL type). Each is rewritten into an `ADD COLUMN` + `DROP` + `RENAME` sequence and the rewritten files are listed. This is equivalent to DROP+ADD — it fixes the type but does **not** preserve data — so it is safe **only on an empty table**. On a populated table the new column starts NULL and the old one is dropped in the same migration, destroying the plaintext; do not run it there. Use the staged `stash encrypt` path (add → backfill → cutover → drop) instead.

#### `eql upgrade`

The install SQL is safe to re-run — columns and data survive — but it is not fully idempotent: it begins with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`, which cascade-drops any **functional indexes** built on the `eql_v3` extractors (see `stash-indexing`). After an upgrade, recreate them: migration runners skip migrations already recorded as applied, so add a *new* migration that re-issues the `CREATE INDEX` statements (or run the DDL directly), then `ANALYZE` the affected tables. `upgrade` checks the current version, re-runs the install SQL, and reports the new one. If EQL isn't installed it points you at `eql install`. Same `--supabase`, `--exclude-operator-family`, `--eql-version`, `--latest`, `--dry-run`, `--database-url` flags.

#### `eql status`

Whether EQL is installed and at which version; database permission status; whether an active encrypt config exists (relevant only to Proxy users).

### Database

#### `db validate` — validate the encryption schema

| Rule | Severity |
|---|---|
| `freeTextSearch` on a non-string column | Warning |
| `orderAndRange` without operator families | Warning |
| No indexes on an encrypted column | Info |
| `searchableJson` without `dataType("json")` | Error |

Exits 1 on errors only. The "No indexes" Info finding applies to term-carrying (queryable) columns — resolve it with the functional-index recipes in the `stash-indexing` skill. Storage-only columns (bare `types.T`, `types.Boolean`) have no index option by design; for them the finding needs no action.

#### `db test-connection`

Verifies the database URL is valid and reachable. Reports database name, connected role, and server version.

#### `db migrate`

Not implemented — prints a warning and exits. Placeholder for future encrypt-config migration tooling.

### Schema

#### `schema build`

Connects to the database, lets you select tables and columns, and for each column picks a concrete EQL v3 domain (`TextSearch`, `IntegerOrd`, `TextEq`, …) — defaulting to the widest searchable domain for the column's type. Boolean columns are assigned the storage-only `types.Boolean` domain automatically; JSON columns are assigned the queryable `types.Json` domain, which supports encrypted containment and selector queries. Flags: `--supabase`, `--database-url`.

For AI-guided integration that edits your existing schema files in place, prefer `stash plan` → `stash impl`.

### Encrypt

The database-side toolset that takes an existing plaintext column the rest of the way, **after** the rollout PR is deployed and dual-writes are live. It drives `@cipherstash/migrate`, recording every transition in `cipherstash.cs_migrations` (installed by `eql install`) and reading intent from `.cipherstash/migrations.json`.

The phase ladder depends on the column's EQL version, which the commands detect from the column's **domain type** (EQL v3 types are self-describing; the `<col>_encrypted` naming is a convention only, never relied upon):

- **EQL v3 (the default):** `schema-added → dual-writing → backfilling → backfilled → dropped`. There is no cut-over — the application switches to the encrypted column by name, then the plaintext column is dropped.
- **EQL v2:** `schema-added → dual-writing → backfilling → backfilled → cut-over → dropped`, where cut-over renames the encrypted twin into the original column name.

#### `encrypt status` / `encrypt plan`

`status` renders per-column phase, indexes, backfill progress, and any drift between intent and observed state. `plan` lists what would change to reconcile them. Both are read-only.

#### `encrypt backfill`

```bash
stash encrypt backfill --table users --column email
stash encrypt backfill --table users --column email --chunk-size 5000
```

Chunked, resumable, idempotent. Walks the table in keyset-pagination order, encrypts each chunk via `bulkEncryptModels`, and writes one `UPDATE ... FROM (VALUES ...)` per chunk in a transaction that also checkpoints to `cs_migrations`. SIGINT/SIGTERM finishes the current chunk and exits cleanly; re-running resumes. The `<col> IS NOT NULL AND <col>_encrypted IS NULL` guard makes concurrent runners and re-runs converge.

Backfill **auto-detects the target column's EQL version** from its Postgres domain type and records it (plus the version-appropriate target phase) in `.cipherstash/migrations.json`. On an EQL v3 column it finishes by printing the v3 next steps: switch the application to `<col>_encrypted` by name, then `stash encrypt drop` — there is no cut-over.

**Dual-write precondition.** The application must already write both `<col>` and `<col>_encrypted` on every insert and update. Otherwise rows written *during* the backfill land in plaintext only, silently. The first run prompts (interactive) or requires `--confirm-dual-writes-deployed` (non-interactive), then records `dual_writing`. Resumes don't re-prompt.

| Flag | Description |
|---|---|
| `--table` / `--column` | Required |
| `--chunk-size <n>` | Default 1000. Lower for lock contention, raise for wide rows. |
| `--pk-column <name>` | Override primary-key detection. Required for composite PKs. |
| `--encrypted-column <name>` | Override the `<col>_encrypted` target name |
| `--schema-column-key <key>` | Override the schema lookup key |
| `--confirm-dual-writes-deployed` | Non-interactive equivalent of the prompt |
| `--force` | Re-encrypt every plaintext row, including ones with existing ciphertext. Recovery path for drift. Expensive, not destructive. Flagged in the audit trail. |

#### `encrypt cutover`

```bash
stash encrypt cutover --table users --column email
```

**EQL v2 only** — v3 has no cut-over: the application switches to the encrypted column by name. Running this command on a **backfilled** v3 column reports "not applicable" (exit 0) with the next step; before backfill completes it exits 1 and says to finish the backfill (never "switch now" onto a half-populated column). For v2, the preconditions are: the column is in the `backfilled` phase, **and** a pending EQL configuration exists (on a v3-only database — no `eql_v2_configuration` table — it explains that and exits 1).

In one transaction it renames `<col>` → `<col>_plaintext` and `<col>_encrypted` → `<col>`, advances the pending config to `encrypting`, activates it, and appends a `cut_over` event. With a Proxy URL configured (`--proxy-url` or `CIPHERSTASH_PROXY_URL`) it then calls `eql_v2.reload_config()` so Proxy picks up the new shape.

> **After cutover, `<col>` holds ciphertext — the read path is not automatic.** Wire reads through the encryption client (`decryptModel(row, table)` for Drizzle, the `encryptedSupabase` wrapper for Supabase, otherwise `decrypt` / `bulkDecryptModels`) before returning values to callers. Skip this and your read paths hand raw EQL payloads to end users. The integration skill has the exact API. **CipherStash Proxy is the one exception** — it decrypts on the wire, so Proxy users need no application change. The cutover plan written by `stash plan` includes this read-path switch as an explicit step.
>
> **Known gap (v2).** The pending-configuration precondition is satisfied by `stash db push`. SDK-only users (who otherwise never need `db push`) must therefore run it once before `encrypt cutover`. This gap is specific to the legacy v2 path and is not being decoupled — EQL v3 columns sidestep it entirely (no configuration table, no cut-over; see above), which is how [issue #585](https://github.com/cipherstash/stack/issues/585) was resolved when v3 became the default.

Flags: `--table`, `--column`, `--proxy-url <url>`, `--migrations-dir <path>`.

#### `encrypt drop`

```bash
stash encrypt drop --table users --column email
```

Version-aware. For **EQL v2** columns in the `cut-over` phase it emits `ALTER TABLE <table> DROP COLUMN <col>_plaintext;` (the post-rename name). For **EQL v3** columns it runs from the `backfilled` phase and drops the ORIGINAL `<col>` — v3 has no rename, so make sure the application reads/writes the encrypted column first. Before generating, the v3 path **verifies live coverage** (refuses if any row still has `<col>` set with the encrypted column NULL — e.g. rows written without dual-writes since the backfill; re-run `encrypt backfill` to fix). Either way it does **not** apply the migration — review and run your own migrate command.

Flags: `--table`, `--column`, `--migrations-dir <path>`.

### Deployment

#### `env`

```bash
stash env --name my-app-prod           # print the four CS_* vars to stdout
stash env --name my-app-prod --write   # write .env.production.local (mode 0600)
stash env --name staging --write .env.staging.local   # custom target path
stash env --name edge-dev --json       # NDJSON events, no prompts
```

Mints deployment credentials from the local device-code session (`stash auth
login`) — no dashboard copy-paste. It creates a fresh ZeroKMS client and a
CipherStash access key (both named `--name`), then emits the four env vars a
deployed app needs:

```dotenv
CS_WORKSPACE_CRN=crn:<region>:<workspace-id>
CS_CLIENT_ID=<uuid>
CS_CLIENT_KEY=<hex>
CS_CLIENT_ACCESS_KEY=CSAK…
```

Things to know:

- **The access key is shown exactly once** — CTS cannot re-reveal it. Pipe the
  output straight into your secret store (`supabase secrets set --env-file`,
  `vercel env add`, `wrangler secret put`, …). `CS_CLIENT_KEY` and
  `CS_CLIENT_ACCESS_KEY` are secrets; never commit them.
- **Stdout is pipe-clean.** Only the dotenv block (or the `--json` events)
  goes to stdout; progress UI and prompts go to stderr. `stash env --name x
  > prod.env` and pipes into dotenv consumers are safe.
- **The key is member-role, always** — pinned in the request and verified on
  the response. The CLI deliberately cannot mint admin keys — use the
  dashboard for those. *Creating* a key does, however, require your own user
  to have the admin role in the workspace (403 otherwise).
- **Non-interactive runs require `--name`** — without it the command exits 1
  with an actionable message before touching the network, and `--write`
  refuses to overwrite an existing file (also before anything is minted).
  In `--json` mode failures arrive as `{ status: "error", code, message }`
  on stdout.
- **`--json` + `--write` compose**: the file is written and the JSON
  confirmation (`{ status: "written", path, … }`) is deliberately
  secret-free, so captured CI logs never contain the key.
- Each run mints a **new** credential; a duplicate name is rejected by the
  server — rerun with a different `--name`.
- This is also the local-dev path for runtimes that can't reach
  `~/.cipherstash` (Supabase Edge Functions run in a container; Workers have
  no filesystem): mint a key, feed it via `supabase functions serve
  --env-file` or the platform's secret store, and use
  `@cipherstash/stack/wasm-inline` with explicit config.

Flags: `--name <name>`, `--write [path]`, `--json`.

## Programmatic API

```typescript
import {
  defineConfig, loadStashConfig, resolveDatabaseUrl,
  EQLInstaller, loadBundledEqlSql, downloadEqlSql,
} from 'stash'
```

| Export | Signature |
|---|---|
| `defineConfig` | `(config: StashConfig) => StashConfig` — identity function for type-checking |
| `loadStashConfig` | `(resolverOptions?: ResolveDatabaseUrlOptions, knownConfigPath?: string) => Promise<ResolvedStashConfig>` — walks up for the config, validates with Zod, applies defaults, exits 1 if missing or invalid |
| `resolveDatabaseUrl` | `(opts?: ResolveDatabaseUrlOptions) => Promise<string>` — the resolution chain documented above |
| `loadBundledEqlSql` | `(options?: { supabase?, excludeOperatorFamily?, eqlVersion?: 2 \| 3 }) => string` |
| `downloadEqlSql` | `(options?: { excludeOperatorFamily?, supabase? } \| boolean) => Promise<string>` — latest EQL from GitHub releases |

### `EQLInstaller`

```typescript
const installer = new EQLInstaller({ databaseUrl: 'postgresql://...' })

await installer.checkPermissions()                  // PermissionCheckResult
await installer.isInstalled({ eqlVersion: 3 })      // boolean
await installer.getInstalledVersion()               // string | 'unknown' | null
await installer.install({ supabase: true })         // executes in a transaction
```

`isInstalled`, `getInstalledVersion`, and `install` all accept `eqlVersion?: 2 | 3` (default `3`, matching the CLI's `--eql-version` default), selecting the `eql_v3` or `eql_v2` schema. `install` also takes `excludeOperatorFamily`, `supabase`, and `latest` (v2 only).

```typescript
type PermissionCheckResult = {
  ok: boolean           // all required permissions present
  missing: string[]     // what's absent
  isSuperuser: boolean  // drives the automatic no-operator-family fallback
}
```

Required: `SUPERUSER`, **or** `CREATE` on the database *and* on the `public` schema. If `pgcrypto` is absent, also `SUPERUSER` or `CREATEDB`.

## Requirements

- Node.js >= 22
- PostgreSQL with sufficient permissions (see `checkPermissions()`)
- `stash.config.ts` with a valid `databaseUrl` — or run `stash init` / `stash eql install` to scaffold it
- Optional peer dependency: `@cipherstash/stack` >= 0.6.0 (required for the commands that load your encryption client)

## Common issues

**Permission errors during install.** The role needs `CREATE` on the database and the `public` schema, or `SUPERUSER`. Check the CLI output for exactly what's missing.

**Config not found.** `stash.config.ts` must be in the project root or a parent, and must `export default defineConfig(...)`. Fastest fix: `stash init`. For a CLI-only setup, `stash eql install` scaffolds it too.

**Supabase.** Always pass `--supabase` (or `supabase: true`). It selects a compatible install script and grants `anon`, `authenticated`, and `service_role`.

**`ORDER BY` on encrypted columns:** on EQL v3, ordering works on OPE-backed columns — Drizzle emits `ORDER BY eql_v3.ord_term(col)`, and the Supabase adapter's `order()` sorts by the `col->op` term. ORE-flavour (`*OrdOre`) domains need a custom operator class the installer creates with `CREATE OPERATOR CLASS` — supported on self-hosted Postgres and on AWS RDS/Aurora, but not on cloud-hosted Supabase (the one confirmed platform whose install role cannot create operator classes; the installer skips the opclass there and disables the `*OrdOre` domains). Storage-only and equality/match-only columns have no ordering term. For those, order by a plaintext column or sort application-side. (The legacy v2 surface — bare `eql_v2_encrypted` — cannot order encrypted columns without operator families.) The ordering extractors are also the index expressions — see the `stash-indexing` skill for the `CREATE INDEX` recipes.

**The native binary won't load.** Run `stash doctor`.

## Related skills

- **`stash-encryption`** — the encryption API, schema definition, and the canonical rollout/cutover model.
- **`stash-drizzle`** / **`stash-supabase`** / **`stash-dynamodb`** — integration-specific patterns.
- **`@cipherstash/wizard`** — AI-guided setup as a standalone package (`npx @cipherstash/wizard`), also reachable as `stash wizard`.
