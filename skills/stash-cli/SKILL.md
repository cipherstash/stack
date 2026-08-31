---
name: stash-cli
description: Drive CipherStash setup and encryption migrations through the `stash` CLI — `init`, `plan`, `impl`, `status`, `auth login`, `eql preflight/install/verify/migration/repair/upgrade/status/validate`, `encrypt backfill/drop`, `schema build`, and `manifest --json`. Covers the agent / non-interactive interface, credential rules, and the staged EQL v3 rollout lifecycle.
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
npx stash init              # PostgreSQL / Drizzle / Prisma (auto-detected)
npx stash init --supabase   # Supabase
npx stash init --prisma     # Prisma Next
npx stash init --drizzle --supabase   # Drizzle on Supabase (the flags combine)
```

`stash init` installs the CLI as a project dev dependency, so subsequent commands can drop the `npx`. The CLI is package-manager aware — before init, use whichever one-shot runner your project uses (`npx`, `pnpm dlx`, `bunx`, `yarn dlx`). Installs are **pinned to the exact `@cipherstash/*` versions this CLI release shipped with** (never bare dist-tags, which can lag behind a release), and init flags any already-installed `@cipherstash/*` package whose resolved version differs from the release's. The fix depends on direction, and init says which applies: an **older** install should be aligned to the release (init offers the exact command); a **newer** install must NOT be downgraded — update the `stash` CLI to the matching release instead (init prints that command too). **Non-interactively, an older ("behind") skew is fatal** — init refuses with a non-zero exit and the align command rather than scaffolding against mismatched packages and reporting a false success. Interactively it offers to align. **Init installs the agent skills first, before anything else.** The per-integration set — the `stash-*` skills bundled in the `stash` tarball, chosen by integration — is copied into `.claude/skills/` when Claude Code is detected — the `claude` binary on `PATH`, or a `.claude/` directory in the project — and into `.codex/skills/` for Codex, both when both are detected. `--target claude-code|codex` names the destination explicitly and skips detection. Skills install ahead of authentication deliberately: it is the only step needing neither network nor credentials, so the guidance survives a run that later fails at auth, at the database URL, or at EQL — which is when it is needed most. The summary reports the outcome either way, and `.cipherstash/context.json` records the names under `installedSkills`. When no agent is detected nothing is written and the summary says so, with the command that will install them. Likewise, if the EQL extension isn't installed at the end, init reports **"Setup incomplete"** and exits non-zero — it never claims a setup is complete when encryption would fail at query time. Integrations that install EQL through a migration are the exception and exit 0: **Prisma Next** installs it via the top-level `prisma-next migrate`, and the **Drizzle** and **local Supabase** flows (a Supabase project with a local `supabase/` directory — a hosted one with no CLI scaffolding installs directly) *generate* an EQL migration, which init reports honestly as "EQL migration generated — apply it with `drizzle-kit migrate`" (Supabase: `supabase db reset` locally, `supabase db push` remotely) rather than claiming the extension is already installed. Re-running init over a project whose install migration is already on disk reports "EQL migration **already present**" — same apply step, same zero exit, no claim that this run generated anything.

**If you are an agent, do this first:**

1. **`npx stash manifest --json`** — the structured, version-stamped command surface. Read it before running anything else.
2. **`npx stash auth login --json --region <slug>`** — only if not already authenticated. Surface the URL to the human (see [Authentication](#authentication)). Do this *before* `init`.
3. **`npx stash init`** — now finds the token and proceeds without prompting. It installs the per-integration skills into `.claude/skills/` or `.codex/skills/` as its **first** step, before authenticating, so read them from there once init has run — pass `--target` if you want to name the destination yourself. If the summary says `No agent skills installed`, no agent was detected: run `stash plan --target <name>` to install them.
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
| `{ status: "error", code, message, hint? }` | Failure. Exit code 1. `hint` is present only when the failure has a remedy; `{cli}` in it is already resolved. |

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

Flags: `--region <slug>` (env `STASH_REGION`), `--json`, `--no-open`, `--supabase` / `--drizzle` / `--prisma` (referrer tracking only).

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
| Agent target (`plan`, `impl`) | `--target <claude-code\|codex\|agents-md\|lovable\|wizard>` |
| Skills destination (`init`) | `--target <claude-code\|codex>` — selects the destination only; `init` performs no handoff |
| Dual-write confirmation (`encrypt backfill`) | `--confirm-dual-writes-deployed` |
| Machine-readable output | `--json` on `status`, `manifest`, `auth login`, `auth regions` |

When a required value is missing in a non-TTY context, the command exits non-zero with an actionable message naming the flag and env var — it never hangs.

**`init --target` is not the same flag as `plan --target` / `impl --target`.** On `plan` and `impl`, `--target` selects the agent to hand off to. On `init` it selects only where the bundled skills are copied — `claude-code` → `.claude/skills/`, `codex` → `.codex/skills/` — and skips agent detection; `init` never performs a handoff. `agents-md`, `lovable` and `wizard` are accepted but install no skill directories, because those handoffs inline the skill bodies into `AGENTS.md` instead. The flag is optional everywhere: without it, `init` detects the agent itself.

**`plan` and `impl` need `--target` in a non-TTY.** Their agent-target picker reads from `/dev/tty`. Without `--target` they print a "no agent selected" hint and exit 0 *without performing the handoff*. `init` and `status` adapt automatically and are safe anywhere.

**Exit codes.** `1` on failure; `0` when a user cancels a prompt. In `--json` mode an `{ "status": "error", "code", "message", "hint"? }` line is emitted before exiting 1. `hint` appears only when the failure carries a remedy — read it, because for a terminal failure it is the part that says retrying cannot help.

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

### TLS to the database

Every CLI database connection honours `sslmode` and `sslrootcert` from the connection string, and the `PGSSLMODE` / `PGSSLROOTCERT` environment variables when the URL carries no TLS parameters (URL parameters win, libpq precedence — and unlike raw node-postgres, `PGSSLROOTCERT` is actually consumed):

- `sslmode=verify-full` (and `require` / `verify-ca` / `prefer`, which the CLI treats identically — full verification, matching node-postgres's current behaviour) verifies the server certificate. CA resolution order: `sslrootcert=<path>` in the URL (libpq semantics — that file becomes the only trust anchor; `sslrootcert=system` selects the system store) → the `PGSSLROOTCERT` environment variable → for `*.supabase.co` / `*.supabase.com` hosts, the CLI's **bundled Supabase root CA** (appended to the system roots) → the system trust store.
- Supabase therefore verifies out of the box — direct hosts and the pgBouncer pooler alike. No certificate download needed.
- `sslmode=no-verify` is honoured but prints a one-line stderr warning: the connection is encrypted, the server is not authenticated. `sslmode=disable` turns TLS off.
- **Never set `NODE_TLS_REJECT_UNAUTHORIZED=0`** — it disables TLS verification for every connection in the process, including the ones carrying CipherStash credentials. A certificate-verification failure from any CLI command names the host and the supported remedies (shaped centrally in the connection factory); follow those instead.
- URLs using client certificates (`sslcert` / `sslkey`) or the raw `ssl` param are passed to node-postgres untouched.

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
| `client` | no | `./src/encryption/index.ts` | Encryption client, loaded by `eql validate` and `encrypt backfill` (`schema build` only writes here; `encrypt drop` resolves against the database). **Not required in Prisma Next projects** — see below. |

In a **Prisma Next** project there is deliberately no client file: encrypted columns are declared in the PSL contract. When the configured `client` path is missing, `encrypt backfill` — the only command that loads it — detects Prisma Next, reads the emitted `contract.json` (searched at `src/prisma/`, `prisma/`, then the project root), and derives the schemas with the adapter's own `deriveStackSchemasV3`, so the CLI's schema view matches the application's. (`encrypt status` and `encrypt drop` never read the client file; they resolve against the database.) Both `@cipherstash/stack-prisma` and `@cipherstash/stack` are resolved from *your* project, not the CLI's dependency tree. Run `prisma-next contract emit` first; if the contract declares no `cipherstash.*()` column, the command says so rather than reporting a missing client file.

Resolved by walking up from `process.cwd()`, like `tsconfig.json`. `stash init` scaffolds it; `stash eql install` offers to.

## Setup lifecycle

Four explicit save-points. Each runs standalone; chain prompts make first-time setup one flow.

| Command | Owns | Ends with |
|---|---|---|
| `stash init` | Auth, database, encryption client, deps, EQL install, `.cipherstash/context.json` | Default-yes prompt → chains to `stash plan` |
| `stash plan` | Drafts `.cipherstash/plan.md` via agent handoff. State-driven: auto-detects rollout vs. cutover. | Default-yes prompt → chains to `stash impl` |
| `stash impl` | Executes the plan via agent handoff. Enforces the deploy gate. | Deploy-gate banner (rollout) or "verify state" |
| `stash status` | The rollout quest log — per-column "where am I", runs in ms | — |

### `init` — scaffold

Seven mechanical steps, no agent handoff. It prompts only when it can't pick a sensible default.

1. **Install agent skills** — copies the per-integration `stash-*` skills into `.claude/skills/` and/or `.codex/skills/`, per detection or `--target`. First deliberately: it needs no network and no credentials, so the guidance survives a failure in any step below.
2. **Authenticate** — silent when a valid token exists.
3. **Resolve database** — per the resolution order above; verifies the connection.
4. **Build schema** — auto-detects Drizzle, Supabase, and Prisma Next, writes the placeholder encryption client, and writes `.cipherstash/context.json`. **Prisma Next is the exception:** it derives schemas from `contract.json`, so no encryption-client file is written and none is needed.
5. **Install dependencies** — one combined prompt for `@cipherstash/stack` and `stash`.
6. **Install EQL** — always EQL v3, migration-first wherever there is a migration history to land in. Drizzle generates `eql migration --drizzle`; a Supabase project with a local `supabase/` directory generates `eql migration --supabase`; Prisma Next installs through `prisma-next migrate`; everything else (including a hosted Supabase project with no CLI scaffolding) installs directly. The migration routes leave EQL **generated, not applied** — the summary says so, and you run the migrate step yourself.
7. **Gather context** — summarises what was detected.

Flags: `--supabase`, `--drizzle`, `--prisma`, `--region <slug>`, `--target <claude-code|codex>`.

**The integration flags combine.** `stash init --drizzle --supabase` is a Drizzle project on Supabase: the EQL migration goes into your Drizzle migrations folder (drizzle-kit owns the history there) with the Supabase role grants appended, both adapter packages are installed, and the database-URL resolver may use `supabase status` to find a local stack. `--prisma` combined with another flag still takes the Prisma Next route. Combined flags are recorded together as the referrer (`drizzle-supabase`), exactly as `stash auth login --drizzle --supabase` does. This is `init` only — `eql migration` takes exactly one target (see below).

| Generated file | Purpose |
|---|---|
| `./src/encryption/index.ts` | Placeholder encryption client — declare encrypted columns here, or let `plan`/`impl` do it. **Not written for Prisma Next** (`--prisma`), which derives schemas from `contract.json` |
| `.cipherstash/context.json` | Detected facts: integration, package manager, schemas, env key names, and the skills installed (`installedSkills`). CLI-owned; never hand-edit |
| `.claude/skills/` or `.codex/skills/` | The per-integration `stash-*` skills, when an agent is detected or `--target` names one |
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
| A column has `dual_writing` or later | **Encryption cutover** — backfill, switch schema/query references to the EQL v3 encrypted column by name, wire the read path, then drop plaintext. Requires the rollout to be deployed. |
| `--complete-rollout` passed | **Complete rollout** — schema-add through drop, no deploy gate. Needs consent: an interactive default-no confirm, or `--yes` non-interactively (without it, a non-interactive run **exits non-zero without drafting** rather than silently doing nothing). |

The agent writes a machine-readable header into the plan:

```
<!-- cipherstash:plan-summary { "step": "rollout"|"cutover"|"complete", "columns": [...] } -->
```

Each column carries `path: "new" | "migrate"`. `stash impl` parses this to render its confirmation panel and enforce the deploy gate.

To re-plan, delete `.cipherstash/plan.md` first — otherwise the agent is told to revise it rather than start fresh. `--complete-rollout` is the escape hatch for databases with no deployed application (local dev, sandboxes, test DBs); it's only safe when nothing in production writes to that database.

**The outro reports what actually happened.** The plan file is written by the handed-off agent, so `plan` verifies it on disk before claiming anything: `Plan drafted at .cipherstash/plan.md` appears only when the file exists after the handoff. If a launched agent exits without writing it, `plan` errors and **exits non-zero**. Deferred handoffs — `--target agents-md`, `--target lovable`, or a Claude Code / Codex target whose CLI isn't installed — end with `No plan drafted yet` and exit 0: the plan lands later, when you drive the agent yourself. The `lovable` target writes the same AGENTS.md (with the skills inlined) but its next steps go through Lovable's GitHub sync: commit and push the generated files, then add a Knowledge note in the Lovable project settings pointing the agent at `AGENTS.md` and `.cipherstash/setup-prompt.md` — Lovable does not auto-load AGENTS.md the way Cursor or Windsurf do. A pre-existing plan the run didn't modify is reported as `left unchanged by this run`, not drafted. Either way, check that `.cipherstash/plan.md` exists before acting on it.

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

There is no atomic way to replace a populated plaintext column with an encrypted one without corrupting data. The rollout phase deploys the *capability* to write encrypted values (the twin column and the dual-write code). The cutover phase deploys the *transition*: backfill historical rows, switch schema/query references to the EQL v3 encrypted column by name, wire the application read path through the encryption client, then drop the plaintext column. There is no rename swap.

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
stash eql preflight
stash eql install
stash eql verify
stash eql migration --drizzle
stash eql migration --supabase
stash eql repair --drizzle
stash eql upgrade
stash eql status
```

> `stash db install`, `db upgrade`, and `db status` still work but print a deprecation warning and forward to `eql <sub>`. Use the `eql` spelling.

#### `eql preflight`

Read-only report of whether the connected role can install EQL, run before anything is attempted. It probes: `current_user`, superuser, **membership of `postgres`**, `CREATE` on the database and on `public`, `pgcrypto`, whether the role **can create an operator class**, and whether the `eql_v3` / `eql_v3_internal` schemas already exist. Each blocked row names the statement it blocks. Exits 1 when a gap would abort `eql install`; `--json` emits the structured result for agents (stdout is pure JSON).

Membership of `postgres` is reported but never blocks: `eql install` handles a non-member role by skipping the owner-scoped `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements, which are **optional** — the install is complete without them (see `eql install` below). This matters on managed platforms whose database role is not `postgres` and not a member of it (e.g. Lovable's `sandbox_exec`).

**The `ORE operator class` row never blocks either** (`canCreateOperatorClass` in `--json`; `creatable` / `not creatable` / `unknown`). It answers the one schema-design question you want settled *before* writing types: `not creatable` means `eql install` will skip the ORE operator class and install the bundle's loud-failure fallback in its place, so **declare ordered columns `types.*Ord`, not `types.*OrdOre`** — every write to an `_ord_ore` domain on such a database fails its `eql_ore_unavailable` CHECK. This is probed, not inferred from `superuser`: `CREATE OPERATOR CLASS` is superuser-gated in stock PostgreSQL, but AWS RDS and Aurora let their admin role create one while cloud-hosted Supabase does not — so a role with `rolsuper = f` is not evidence either way. The probe attempts the DDL inside a transaction it always rolls back, so preflight stays read-only; `unknown` means it could not ask (a read-only replica, say) and must not be read as either answer.

| Flag | Description |
|---|---|
| `--json` | Machine-readable result instead of the table. Stdout is pure JSON even on failure: success is `{ status: 'ok', ... }`, blockers are `{ status: 'blocked', ... }` (exit 1), and failures — including a missing/malformed DATABASE_URL — are the shared `{ status: 'error', code, message }` envelope |
| `--database-url <url>` | Probe that database (no config needed). A hand-set literal `databaseUrl` in stash.config.ts still wins, with a warning (stderr in `--json` mode) |

#### `eql install`

Gets a project from zero to a direct EQL v3 install. It loads an existing `stash.config.ts` (or offers to scaffold one), scaffolds the encryption client if missing, and applies the pinned `@cipherstash/eql` bundle. To put the installation in migration history instead, use `eql migration` — `--drizzle` for Drizzle, `--supabase` for a Supabase project.

**On Supabase with a local `supabase/` directory, use `eql migration --supabase`, not this.** A direct install does not survive `supabase db reset`, which drops the database and replays `supabase/migrations/`. Reserve `eql install --supabase` for a hosted project administered without the Supabase CLI.

| Flag | Description |
|---|---|
| `--force` | Reinstall even if EQL is present |
| `--dry-run` | Show what would happen |
| `--supabase` | Supabase-compatible install; grants `anon`, `authenticated`, and `service_role` |
| `--database-url <url>` | One-shot install (see below) |

**Non-`postgres` roles.** The Supabase grants include three owner-scoped `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements that only a member of `postgres` can run. When the connecting role is not a member (checked up front), the install still succeeds and is **complete**: the bundle and every plain `GRANT` are applied, covering all existing objects. The skipped statements are printed under "Optional SQL — requires postgres" purely as information — they only cover EQL objects `postgres` might later create outside stash tooling, and every `stash eql install`/`eql upgrade` re-grants all objects anyway (the generated Supabase migration wraps them in a membership guard, so it is safe for any role). Do not treat them as a required follow-up, and never work around a grants failure by disabling anything — the install itself is no longer rolled back by a grants failure (the bundle commits in its own transaction; grants run after it), and a plain re-run of `eql install` re-applies the grants on an already-installed database.

The removed `--eql-version`, `--latest`, `--drizzle`, `--migration`, `--direct`, `--migrations-dir`, and `--exclude-operator-family` options fail clearly instead of being ignored. A request for EQL v2 points dump-recovery users to the upstream EQL 2.3.1 SQL release. New installs are EQL v3 only; its pinned bundle self-adapts when a database role cannot create the optional operator family.

**`--database-url` is a one-shot.** It installs against that database and leaves the project untouched — no config is loaded, and none is scaffolded, nor is an encryption client. This lets `npx --package=stash@1.1.1 stash eql install --database-url 'postgres://...'` run in a bare project with no CipherStash dependencies while pinning the CLI to this skill's release. It also means the flag always wins: loading a config could pick up a parent-directory `databaseUrl` literal and install against the wrong database.

**The install verifies the bundle before it runs it.** Before connecting, `eql install` hashes the SQL it resolved from `@cipherstash/eql` and compares it against the `installSqlSha256` that release attests to. A mismatch refuses — naming both digests and the resolved path — rather than executing SQL the version number does not vouch for; nothing is opened and nothing is sent. In practice this only fires on a corrupt or tampered `node_modules`, since the bundle and its manifest are emitted by the same build.

**The install also verifies itself afterwards.** `eql install` ends by running the same surface check as `eql verify` (below) — on the fresh-install path *and* on the already-installed early exit, so a plain re-run over a damaged database fails rather than printing "Nothing to do." It exits 1 if the surface is incomplete; if the check itself cannot run (connection dropped mid-verify), it warns and points at `stash eql verify` instead of failing the committed install. A version mismatch with the pinned bundle also warns rather than fails there — nothing was actually checked, and a no-op re-run over an older EQL must stay exit 0 for idempotent provisioning scripts. (`eql verify` itself stays strict and exits 1 on a mismatch.)

#### `eql verify`

Read-only check that the **installed EQL surface is complete**, independent of any application schema. It compares what the database actually has against everything the pinned bundle installs — every domain, function overload, operator, cast, and the ORE operator class — via catalog queries, and reports damage grouped per domain. This catches the failure `eql validate` cannot: a partial install where the domains exist but some comparison functions or operators do not, so `weight >= x` errors at query time long after "install succeeded".

Expected absences read as info, not damage: on managed Postgres the bundle legitimately skips the ORE operator class (creating one requires superuser) and poisons the `_ord_ore` domains to fail loudly — `eql verify` reports that as the supported configuration it is. Exit 0 means exactly one thing: the surface was checked and found complete. Genuine damage, EQL not installed, and a version mismatch with the pinned bundle all exit 1 — on a mismatch the object-level diff is skipped (the pinned bundle is the wrong manifest to compare against) and the command suggests `eql upgrade` (or a one-shot `eql install --force --database-url ...` for a database without a `stash.config.ts` — `eql upgrade` needs one); "could not verify" never reads as "verified".

Run it whenever query-time behaviour looks inconsistent with a "successful" install — e.g. an `operator does not exist` or `function ... does not exist` error naming an `eql_v3` object.

| Flag | Description |
|---|---|
| `--json` | Machine-readable report. `status` is the discriminator: `complete` (the only exit-0 status), `incomplete`, `not-installed`, or `version-mismatch`; `findings[]` carries per-object damage with a `domain` attribution |
| `--database-url <url>` | One-shot, like `eql install`'s: bypasses config loading entirely, so the database you name is the database that gets judged |

#### `eql migration`

Generates an **EQL v3 install migration**, instead of running SQL directly against the database (`eql install`). Migration-first is the preferred path: the install lands in your migration history and ships to every environment through the same migrate step as the rest of your schema. On Supabase it is the *only* durable path — `supabase db reset` replays the migrations directory, so a direct install is wiped by the next reset. v3 only — there is no `--eql-version` here.

```bash
stash eql migration --drizzle              # Drizzle custom migration in drizzle/
stash eql migration --drizzle --supabase   # also grant eql_v3 to anon/authenticated/service_role
stash eql migration --supabase             # supabase/migrations/<timestamp>_cipherstash_eql.sql
```

**`--supabase` plays two roles.** On its own it is the target: write the install into `supabase/migrations/`. Combined with `--drizzle` it is a modifier on the Drizzle migration, adding the role grants. Only a bare `--supabase` selects the Supabase emitter.

| Flag | Description |
|---|---|
| `--drizzle` | Emit a Drizzle custom migration (via `drizzle-kit generate --custom`, then inject the SQL). Requires `drizzle-kit`, and a `drizzle.config.ts` that can read `DATABASE_URL` — stash loads your `.env`/`.env.local` and passes the URL it resolves down to the child, so the usual `dotenv -e .env.local -- drizzle-kit …` wrapper is not needed. |
| `--prisma` | **Not needed** — Prisma Next installs the EQL bundle through its own migration framework (the extension pack's `migrations/cipherstash/` contract space; run `prisma-next migrate`). The flag exists only to say so and point you there. |
| `--supabase` | Alone: write the install into `supabase/migrations/`, so it survives `supabase db reset`. With `--drizzle`: append the Supabase role grants (`eql_v3` + `eql_v3_internal` → `anon`, `authenticated`, `service_role`) instead. Harmless when you connect directly as `postgres`; needed when the same tables are reached via PostgREST/RLS. |
| `--name <name>` | Migration name (Drizzle). Default `install-eql`. Letters, numbers, `-`, and `_` only — anything else is rejected. |
| `--out <path>` | Where the migration is written. Drizzle: your `drizzle.config.ts` `out` decides that — stash follows the path drizzle-kit reports and warns if it differs from this flag. `--out` is only the fallback directory to search (default `drizzle`) when drizzle-kit reports no path. Supabase: leave it alone — see below. |
| `--force` | Regenerate the Supabase install migration in place when one already exists (keeping its version, so an applied ledger stays consistent). Without it, a second run exits 1. Re-applying the replaced file takes a specific recipe — see "Re-applying after `--force`" below. Not needed for `--drizzle` — drizzle-kit numbers each generated migration. |
| `--dry-run` | Show what would happen without writing anything. |

The Supabase file is timestamped at generation time, so it sorts **after** everything already applied and pushes with no extra flag. That is worth having, because an out-of-order version is not merely skipped: `supabase db push` aborts the *entire* push with `Found local migration files to be inserted before the last migration on remote database.` and applies nothing, until you re-run it with `--include-all`. The file carries the EQL bundle, the role grants, and the `cipherstash.cs_migrations` tracking schema, so one `supabase db reset` provisions everything `stash encrypt` needs.

**Sorting last is wrong if the project already has encrypted-column migrations.** A project that ran `stash eql install` first, then wrote migrations adding `public.eql_v3_*` columns against the live database, ends up with an install stamped today — i.e. *after* those migrations. `supabase db reset` replays the directory in version order with no dependency awareness, so they run first and the reset fails with `type "eql_v3_text_search" does not exist`. The command detects this before writing (on `--dry-run` too) and warns, naming the offending files. It does not fix it: rename the install migration to a version below the earliest of them so it replays first. How that back-dated version reaches a remote depends on what that remote actually has — check it, don't go by memory: `psql "$REMOTE_DATABASE_URL" -Atc "select eql_v3.version()"`. That function is created by the bundle's last statements, so it answers "is the whole install there"; a probe for the `eql_v3` schema does not, because the schema is created by the bundle's first statements and survives an install that aborted partway. If it prints a version, EQL is present and only the ledger row is missing — mark the version applied without executing any SQL: `supabase migration repair --status applied <version>`. ⚠️ Do not push the file there instead: the bundle opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE` (and `eql_v3_internal`), so re-applying it drops every index, constraint, and RLS policy that references those schemas — see "Re-applying after `--force`" below. If the check errors, that remote genuinely still needs the SQL applied: `supabase db push --include-all`, because the back-dated version lands as a gap in the middle of that history. ⚠️ Never mark that remote applied. Every other remedy here fails loudly and can be retried; this one fails silently — the ledger row claims SQL that never ran, so no later push installs EQL, and the first migration referencing `eql_v3` fails with nothing pointing at the cause.

**Re-applying after `--force`.** `--force` rewrites the install in place and keeps its version, so a database that already applied that version still has the old bundle — and `supabase db push` will *not* re-apply it. The Supabase CLI decides what is pending by comparing versions, never file content (seed files are hashed; migrations are not), so a version already in the ledger is simply never re-run and push reports `Remote database is up to date.` The working recipe:

```bash
supabase db reset                                      # local — replays every migration

supabase migration repair --status reverted <version>  # remote — clear the ledger row first
supabase db push                                       # ...then re-apply
```

`migration repair` updates the tracking table only; it applies no SQL. Add `--include-all` to that push only if it aborts with `Found local migration files to be inserted before the last migration on remote database.` — which happens when migrations sort *after* the install, the usual shape once encrypted-column migrations have been written against it. Reverting the newest version instead leaves it at the tail of remote history, where a plain push applies it. Don't reach for the flag pre-emptively: it applies every out-of-order migration you have, not just this one. ⚠️ Before doing this to a populated database: the EQL bundle opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE` (and `eql_v3_internal`), so re-applying also drops every index, constraint, and RLS policy that references those schemas. That is free on a fresh `supabase db reset` and destructive on a live remote.

**Do not pass `--out` with a bare `--supabase`.** The Supabase CLI's migrations directory is not configurable: `supabase db reset` and `supabase db push` read `<project>/supabase/migrations` and nothing else, there is no `config.toml` key to move it, and `--workdir` / `SUPABASE_WORKDIR` relocates the whole `supabase/` directory rather than this one. An install written anywhere else is simply never applied — the same "EQL is missing after a reset" failure that makes `eql install --supabase` the wrong tool on a CLI-scaffolded project. The command warns rather than refusing, because a project may have its own step that applies that directory; if you do not, drop the flag. (`--out` with `--drizzle --supabase` is unaffected — there it is drizzle-kit's output directory.)

Pass exactly one target: `--drizzle`, `--supabase`, or `--prisma`. (`--drizzle --supabase` is not two targets — see above.) Either generated migration also installs the `cs_migrations` tracking schema, so one migrate step covers everything `stash encrypt …` needs.

After writing the migration, `--drizzle` sweeps the output directory for sibling migrations containing an in-place `ALTER COLUMN … SET DATA TYPE <eql_v2_encrypted | eql_v3_*>` — drizzle-kit emits these when you change a plaintext column to an encrypted one, and Postgres rejects them (there is no cast from `text`/`numeric` to an EQL type). Each is rewritten into a staged `ADD COLUMN` for the encrypted twin, while preserving the source column, and the rewritten files are listed. The rewrite never emits `DROP COLUMN` or `RENAME COLUMN`. If the sweep cannot prove a column's source type, finds that the encrypted twin already exists, or encounters another unsafe form, it leaves that statement untouched and the command exits non-zero so you review the migration directory before running `drizzle-kit migrate`. Populated plaintext tables then take the staged EQL v3 rollout from there: dual-write, backfill, switch the application to the encrypted column by name, and drop plaintext only after verification.

The sweep is fail-closed: it rewrites a statement only when the same directory also contains the `CREATE TABLE` or `ADD COLUMN` that declared the column, and the column is not already encrypted **in the corpus**. Declarations inside a `DO $$ … END $$;` block count toward "already encrypted" — that DDL really executes — but a *plaintext* declaration inside one does not count as declaring the column, since the block may be conditional. That is a guarantee about what the migration files say, not about the live database — the sweep never queries the database, so a column that has drifted from its migration history (altered by hand via psql or the Supabase dashboard, or changed by dynamic `EXECUTE` SQL the sweep cannot read) can already hold ciphertext while the corpus still describes it as plaintext. A statement it cannot place — the declaration lives in another migration directory, or the history was squashed — is listed as needing review rather than rewritten, and the command exits non-zero if any such statement remains. Check the column's actual type in the database before applying a flagged or corpus-cleared rewrite by hand.

**After a successful sweep, reconcile your ORM schema.** The rewrite repairs SQL only, so the database ends up with both `email` (unchanged, still plaintext) and `email_encrypted`, while your `schema.ts` and drizzle-kit's `meta/*_snapshot.json` both still declare `email` as the encrypted domain and know nothing about the twin. `drizzle-kit generate` will **not** warn you: it diffs your schema against its snapshot, reads neither the `.sql` nor the database, and those two still agree. The command prints the divergence per column, naming the table, both columns and the domain. Until you reconcile it, reads of the source column hand plaintext to a decrypt path expecting an EQL envelope, writes store an EQL envelope in a plaintext column and *succeed*, and the new encrypted column is unreachable through the ORM. See `skills/stash-drizzle` for the reconciliation, including the step that is easy to miss: because the snapshot has never seen the encrypted twin, `drizzle-kit generate` **always** emits an `ADD COLUMN` for it, and the swept migration already adds that column — so the regenerated statement has to be deleted (or made `IF NOT EXISTS`) or migrate fails with `column already exists`.

The sweep runs *after* the install migration is written, so it only sees migrations that already exist. The broken `ALTER COLUMN` is normally generated later, by your next `drizzle-kit generate` — use `eql repair` for that, rather than regenerating an install migration you do not need.

#### `eql repair`

Runs the same sweep as `eql migration --drizzle`, standalone: it repairs an existing migration directory without generating anything. This is the command for the usual failure — `drizzle-kit generate` emitted an in-place `ALTER COLUMN … SET DATA TYPE <eql_v3_*>` after EQL was installed, and `drizzle-kit migrate` fails on it.

```bash
stash eql repair --drizzle                                  # sweep drizzle/
stash eql repair --drizzle --dry-run                        # preview; writes nothing
stash eql repair --drizzle --out db/migrations \
  --database-url postgres://…                               # skip already-applied migrations
```

| Flag | Description |
|---|---|
| `--drizzle` | Required. Repair a Drizzle migration directory. |
| `--out <path>` | Directory to sweep. Default `drizzle`; set it to match your `drizzle.config.ts`. |
| `--dry-run` | Report what would be rewritten without writing anything. |
| `--database-url <url>` | Check which migrations the database has already applied, and leave those alone. Also read from `DATABASE_URL`. |
| `--migrations-table <[schema.]table>` | Drizzle's migration ledger, when `drizzle.config.ts` overrides `migrations.table` / `migrations.schema`. Defaults to `drizzle.__drizzle_migrations`. Only read alongside `--database-url`. |

What it rewrites, what it refuses, and the schema reconciliation afterwards are identical to the `eql migration --drizzle` sweep above — both call the same rewriter and print the same report. It exits non-zero if any statement is left unrepaired.

**Already-applied migrations are refused, not repaired.** Nearly every ALTER-to-encrypted statement is un-runnable, so its migration failed and is safe to rewrite. The exception is a `jsonb` column changed to an EQL domain on an empty table: base types are compatible, so it applies. Rewriting that migration afterwards leaves its `.sql` describing a shape the database never got from it, and a fresh CI or staging database replaying the rewritten file diverges from the one you developed on — silently, since nothing records that they should differ. With `--database-url`, repair reads `drizzle.__drizzle_migrations` and treats a migration as applied when its journal `when` is at or below the latest `created_at` — the same timestamp comparison `drizzle-kit migrate` itself makes (hashes are written but never compared). Applied migrations are listed and left untouched, and the command exits non-zero.

Without a database URL the repair proceeds and warns that applied state could not be verified: the journal proves a migration exists, not that it ran. Pass `--database-url` whenever you have run `drizzle-kit migrate` since generating the migrations. If the check is requested but cannot run (connection refused, bad credentials), nothing is rewritten and the command exits non-zero rather than silently repairing unverified.

**If `drizzle.config.ts` overrides `migrations.table` / `migrations.schema`, pass `--migrations-table`.** The probe cannot discover a renamed ledger, and a missing one is ambiguous — it means either `drizzle-kit migrate` never ran here, or the check looked in the wrong place. Repair reports that state as *unverified* rather than as "nothing applied" and says which relation it tried, so a custom-ledger project is never told its applied migrations are safe to rewrite. Naming the ledger turns the check back on. The value must be a plain table name, optionally schema-qualified; anything else is rejected before connecting.

An applied migration carrying a statement the sweep would have skipped anyway — an undeclared source column, an already-encrypted one, an existing twin — is reported with that skip reason, not as an applied-migration refusal. Its applied-ness is not why it was left alone.

#### `eql upgrade`

The install SQL is safe to re-run — columns and data survive — but it cascade-drops functional indexes that depend on `eql_v3`; recreate them afterward. `upgrade` is v3-only and accepts `--supabase`, `--dry-run`, and `--database-url`.

#### `eql status`

Whether EQL is installed and at which version, plus database permission status. It retains read-only EQL v2/config-table diagnostics for existing deployments.

On a v3 install it also reports the **ORE operator class** state, so the ordering trade `eql install` named once is recoverable later without re-reading scrollback: either the class is present (`types.*OrdOre` usable), or it was skipped and every `_ord_ore` domain carries the loud-failure fallback — the supported managed-Postgres configuration, where ordered columns must be `types.*Ord`. Anything else is damage and points at `eql install --force`. Run `eql verify` for the full surface check.

The ORE row is only reported when the installed EQL **is** the version this CLI pins. The `_ord_ore` domains the poison CHECKs are counted over come from the pinned bundle, so a database running a different EQL cannot be classified against it at all — `status` says the state was not compared and points at `eql upgrade` rather than inventing a damage verdict. Same rule as `eql verify`'s version mismatch: "could not compare" is never rendered as an answer.

#### `eql validate` — validate the encryption schema

```bash
stash eql validate [--supabase] [--database-url <url>]
```

Reads the tables passed to `Encryption({ schemas })` — through the client's `getSchemas()` accessor, so it sees the **concrete domain** of every column, which the built encrypt config does not carry — and checks them against the EQL v3 vocabulary. If a database is reachable it then checks the declaration against what that database actually has.

`getSchemas()` is a recent addition. Against a project on an older `@cipherstash/stack` — or a client whose `getSchemas()` is missing, malformed, or throws — validate says so and falls back to the built encrypt config: the index-derived rules still run, but the rules that need a domain (ORE portability and drift) are skipped. Upgrading `@cipherstash/stack` restores them.

Schema checks (no database needed):

| Rule | Severity |
|---|---|
| An `_ord_ore` domain is declared (`types.NOrdOre`, `types.TextOrdOre`) | Warning |
| Storage-only column — encrypts and decrypts, carries no query terms | Info |
| Searchable `boolean` column | Error |
| Free-text `match` index on a non-text domain | Error |
| Encrypted-JSONB (`ste_vec`) index without `types.Json` | Error |

Database checks (skipped with a notice, not a failure, when no database is reachable):

| Rule | Severity |
|---|---|
| EQL v3 is not installed — reported once, and the remaining database checks are skipped | Error |
| A declared table lives in a different schema than the one searched | Warning |
| A declared table is in the searched schema but invisible to the connected role (missing grant) | Warning |
| A declared table name carries a schema qualifier (`schema.table`) — not checked | Warning |
| A declared table exists in no schema at all | Error |
| A declared column is missing from a table that was found | Error |
| The database column's domain differs from the declared one | Error |
| The database column is still plain (no EQL domain) | Error |
| An `_ord_ore` domain on a database whose EQL install could not create the ORE operator class | Error |
| A queryable column with no functional index over its term extractor | Info |
| A declared table name that resolved in the searched schema also exists in another one | Info |

Exits 1 on errors only; warnings and info do not fail the command.

**Validate inspects one schema** — `current_schema()`, the head of `search_path` — but distinguishes four reasons a table can be missing from it, so only the last fails the command. Reported once per table, not once per column.

| The table is… | Finding |
|---|---|
| in another schema (Prisma `multiSchema`, a tenant schema) | Warning naming that schema and the connection option to reach it |
| in the searched schema but invisible to the connected role | Warning with the `GRANT SELECT` to run — `information_schema` reports only what the role holds a privilege on, so a missing grant is not a missing migration |
| declared as `schema.table` | Warning — validate matches table names unqualified and cannot check this. Declare it unqualified and point the connection at its schema |
| absent everywhere | Error — the migration has not been applied |

The `schema.table` case is deliberately not resolved by splitting the name: the only column reader is scoped to `current_schema()`, so `app.users` would silently validate against `public.users` and report an unrelated table's drift as this one's. An explicit "not checked" beats a confident wrong answer.

**An unqualified name that exists in more than one schema is reported too**, as an Info. A bare declared name resolves through `search_path`, so when the same name lives in both the searched schema and another — `users` in `public` and in Supabase's `auth`, which nearly every project has — the declaration does not pin which relation the application reads. Validate names the one it checked (`"public"."users"`), names the others, and gives the connection option to inspect one of those instead. It stays Info rather than Warning on purpose: it must not fail an ordinary Supabase project or report it as unclean, and unlike the four cases above this one *did* check a table — it is qualifying which, not reporting that nothing happened.

**The `_ord_ore` finding is about portability.** `CREATE OPERATOR CLASS` requires superuser, so managed Postgres (Supabase and most hosted providers) installs EQL without the ORE btree operator class, and the bundle then poisons every `_ord_ore` domain with an always-raising CHECK. Prefer the `_ord` (OPE) twin unless you control the database role. With a database reachable, validate confirms which case you are in and upgrades the Warning to an Error when the operator class is genuinely absent.

The "no functional index" Info applies only to term-carrying (queryable) columns — resolve it with the recipes in the `stash-indexing` skill. Storage-only columns (bare `types.T`, `types.Boolean`) have no index option by design, and `types.Json` is served by a GIN index over the column rather than a scalar extractor; neither is reported.

**Not checked:** the ordered domains reject empty strings through a value-level CHECK enforced at encrypt time. Nothing in the schema or in `information_schema` predicts it, so validate cannot catch it statically.

`stash db validate` still routes here, with a deprecation warning.

### Database

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

The authored lifecycle is EQL v3 only: `schema-added → dual-writing → backfilling → backfilled → dropped`. There is no rename cut-over — the application switches to the encrypted column by name, then the plaintext column is dropped. Status readers still display legacy v2 manifest/history fields, but mutation commands refuse an unclassified `eql_v2_encrypted` target.

#### `encrypt status` / `encrypt plan`

`status` renders per-column phase, indexes, backfill progress, and any drift between intent and observed state. `plan` lists what would change to reconcile them. Both are read-only.

#### `encrypt backfill`

```bash
stash encrypt backfill --table users --column email
stash encrypt backfill --table users --column email --chunk-size 5000
```

Chunked, resumable, idempotent. Walks the table in keyset-pagination order, encrypts each chunk via `bulkEncryptModels`, and writes one `UPDATE ... FROM (VALUES ...)` per chunk in a transaction that also checkpoints to `cs_migrations`. SIGINT/SIGTERM finishes the current chunk and exits cleanly; re-running resumes. The `<col> IS NOT NULL AND <col>_encrypted IS NULL` guard makes concurrent runners and re-runs converge.

Backfill requires a `public.eql_v3_*` target column, records version 3 and the `dropped` target phase in `.cipherstash/migrations.json`, then prints the next steps: switch the application to the encrypted column by name and run `stash encrypt drop`. A missing, plaintext, or legacy v2 target is rejected before encryption begins.

**Prisma Next.** Works with no encryption client file — schemas come from the emitted `contract.json` (see [`client`](#configuration)). Backfill also bootstraps the `cipherstash.cs_migrations` tracking schema itself, since the Prisma Next flow installs EQL through the `prisma-next` migration graph rather than `stash eql install` (which is what creates that schema elsewhere). Both steps are idempotent.

**Dual-write precondition.** The application must already write both `<col>` and `<col>_encrypted` on every insert and update. Otherwise rows written *during* the backfill land in plaintext only, silently. The first run prompts (interactive) or requires `--confirm-dual-writes-deployed` (non-interactive), then records `dual_writing`. Resumes don't re-prompt.

**Keyset precondition — the backfill's client must resolve to the same keyset as the application's.** Backfill encrypts through whatever credentials its environment *resolves*: `CS_*` variables when present, otherwise the native auto strategy falls back to the local `~/.cipherstash` dev profile — so a shell without the variables silently runs as your laptop's client. What must match between backfill and app is the **keyset** their clients resolve to, not the credential strings (`stash-zerokms` is canonical). Two clients bound to the same keyset interoperate fully — search included, since index terms come from a per-keyset key. A backfill bound to a *different* keyset is the quiet failure: the app can still decrypt those rows if granted that keyset, but its query terms derive under its own keyset, so encrypted search returns zero rows for them — no error. Export the target environment's `CS_*` values in the shell running the backfill (non-negotiable in CI/production) so the ciphertext lands in that environment's keyspace and the run is attributed to its client. See [`env`](#env) and `stash-auth`.

| Flag | Description |
|---|---|
| `--table` / `--column` | Required |
| `--chunk-size <n>` | Default 1000. Lower for lock contention, raise for wide rows. |
| `--pk-column <name>` | Override primary-key detection. Required for composite PKs. |
| `--encrypted-column <name>` | Override the `<col>_encrypted` target name |
| `--schema-column-key <key>` | Override the schema lookup key |
| `--confirm-dual-writes-deployed` | Non-interactive equivalent of the prompt |
| `--force` | Re-encrypt every plaintext row, including ones with existing ciphertext. Recovery path for drift. Expensive, not destructive. Flagged in the audit trail. |

#### `encrypt drop`

```bash
stash encrypt drop --table users --column email
```

Runs from the `backfilled` phase and drops the original plaintext `<col>`. It verifies live coverage first and refuses if any row still has plaintext set with the encrypted column NULL. Legacy EQL v2 targets are rejected; the old rename/drop lifecycle is no longer automated. The command generates a migration but does not apply it.

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

> **What must match between writers and readers is the keyset, not the
> credential string.** The client minted here is created against the
> workspace default keyset, so it interoperates — search included — with any
> other client resolving to that keyset (index terms come from a per-keyset
> key; `stash-zerokms` is canonical). A client bound to a *different* keyset
> fails loudly where it lacks a grant — but where it *is* granted, decrypt
> still works while its searches run in its own keyspace and silently return
> zero rows (the asymmetry `stash-zerokms` documents). Still mint one
> credential set per
> environment and export it for every process touching that environment's
> data — for isolation, attribution, and revocability (`stash-auth`), not
> because credential strings must be identical.

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
  In `--json` mode failures arrive as `{ status: "error", code, message, hint? }`
  on stdout.
- **`usage_limit_exceeded` is not a session problem.** The command renews the
  device session before minting anything, and CipherStash refuses that renewal
  with a 402 when the organisation is over its billing allowance. That case
  reports `usage_limit_exceeded` rather than `session_invalid`, and points at
  [dashboard.cipherstash.com/billing](https://dashboard.cipherstash.com/billing) rather than at
  `stash auth login` — logging in again cannot mint a credential that is being
  withheld on billing grounds. Same for `stash auth login` itself, which fails
  with `USAGE_LIMIT_EXCEEDED` on the `--json` stream.

  **`org_not_provisioned` is the sibling case**, and equally terminal: the
  organisation is not registered with the usage system at all, so there is no
  plan to upgrade and it goes to [support](https://cipherstash.com/support). `stash env` reports it
  under its own code rather than `session_invalid`, for the same reason —
  branching on `code` is how an agent decides whether a re-login is worth
  attempting, and both of these answer no.

  On `--json`, the remedy for either arrives in `hint`, not in `message`. See
  the `stash-auth` skill for the full taxonomy.
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
  EQLInstaller, loadBundledEqlSql,
} from 'stash'
```

| Export | Signature |
|---|---|
| `defineConfig` | `(config: StashConfig) => StashConfig` — identity function for type-checking |
| `loadStashConfig` | `(resolverOptions?: ResolveDatabaseUrlOptions, knownConfigPath?: string) => Promise<ResolvedStashConfig>` — walks up for the config, validates with Zod, applies defaults, exits 1 if missing or invalid |
| `resolveDatabaseUrl` | `(opts?: ResolveDatabaseUrlOptions) => Promise<string>` — the resolution chain documented above |
| `loadBundledEqlSql` | `() => string` — pinned EQL v3 SQL from `@cipherstash/eql` |

### `EQLInstaller`

```typescript
const installer = new EQLInstaller({ databaseUrl: 'postgresql://...' })

await installer.preflight()                         // PreflightResult
await installer.checkPermissions()                  // deprecated adapter over preflight()
await installer.isInstalled()                       // boolean (v3)
await installer.getInstalledVersion()               // string | 'unknown' | null
await installer.install({ supabase: true })         // InstallResult
await installer.applySupabaseGrants()               // InstallResult (grants only, idempotent)
```

`install` installs EQL v3 only and accepts `supabase`. `isInstalled` and `getInstalledVersion` retain an optional `{ eqlVersion: 2 | 3 }` solely for read-only diagnostics of existing v2 databases.

```typescript
type PreflightResult = {
  ok: boolean                       // no blocking gaps
  missing: string[]                 // blocking gaps, each naming what it blocks
  currentUser: string
  isSuperuser: boolean
  memberOfPostgres: boolean | null  // null: no postgres role exists; false never blocks (it only skips optional statements)
  hasDatabaseCreate: boolean
  hasPublicCreate: boolean          // false (blocking) when the public schema is missing entirely
  pgcryptoInstalled: boolean
  pgcryptoSchema: string | null     // blocks (even superusers) when outside extensions/public — the bundle aborts
  eqlV3SchemaPresent: boolean
  eqlV3InternalSchemaPresent: boolean
  canDropEqlV3Schema: boolean | null          // null: schema absent; false blocks reinstall (DROP SCHEMA ... CASCADE)
  canDropEqlV3InternalSchema: boolean | null
}

type InstallResult = {
  // The skipped ALTER DEFAULT PRIVILEGES FOR ROLE postgres statements (with an
  // explanatory header) when the role is not a member of postgres; null when
  // every grant ran. Optional SQL — surface as information, never as a
  // required step: stash re-grants every object on each install/upgrade.
  deferredGrantsSql: string | null
}
```

The bundle runs in its own transaction; the Supabase grants run after its commit, so a grants failure no longer rolls back a working install.

Required: `SUPERUSER`, **or** `CREATE` on the database *and* on the `public` schema. If `pgcrypto` is absent, also `SUPERUSER` or `CREATEDB`.

## Requirements

- Node.js >= 22
- PostgreSQL with sufficient permissions (check with `stash eql preflight`)
- `stash.config.ts` with a valid `databaseUrl` — or run `stash init` / `stash eql install` to scaffold it
- Optional peer dependency: `@cipherstash/stack` >= 0.6.0 (required for the commands that load your encryption client)

## Common issues

**Permission errors during install.** The role needs `CREATE` on the database and the `public` schema, or `SUPERUSER`. Run `stash eql preflight` for a row-by-row report of exactly what's missing and which statement each gap blocks.

**Config not found.** `stash.config.ts` must be in the project root or a parent, and must `export default defineConfig(...)`. Fastest fix: `stash init`. For a CLI-only setup, `stash eql install` scaffolds it too.

**Supabase.** Always pass `--supabase` (or `supabase: true`). It selects a compatible install script and grants `anon`, `authenticated`, and `service_role`.

**`ORDER BY` on encrypted columns:** on EQL v3, ordering works on OPE-backed columns — Drizzle emits `ORDER BY eql_v3.ord_term(col)`, and the Supabase adapter's `order()` sorts by the `col->op` term. ORE-flavour (`*OrdOre`) domains need a custom operator class the installer creates with `CREATE OPERATOR CLASS` — supported on self-hosted Postgres and on AWS RDS/Aurora, but not on cloud-hosted Supabase (the one confirmed platform whose install role cannot create operator classes; the installer skips the opclass there and disables the `*OrdOre` domains). Storage-only and equality/match-only columns have no ordering term. For those, order by a plaintext column or sort application-side. (The legacy v2 surface — bare `eql_v2_encrypted` — cannot order encrypted columns without operator families.) The ordering extractors are also the index expressions — see the `stash-indexing` skill for the `CREATE INDEX` recipes.

**The native binary won't load.** Run `stash doctor`.

## Related skills

- **`stash-encryption`** — the encryption API, schema definition, and the canonical rollout/cutover model.
- **`stash-drizzle`** / **`stash-supabase`** / **`stash-dynamodb`** — integration-specific patterns.
- **`@cipherstash/wizard`** — AI-guided setup as a standalone package (`npx @cipherstash/wizard`), also reachable as `stash wizard`.
