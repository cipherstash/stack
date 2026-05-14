---
name: stash-cli
description: Configure and use the `stash` package for project initialization, EQL database setup, encryption schema management, and Supabase integration. Replaces the legacy `@cipherstash/stack-forge` skill. The AI wizard is now a separate package (`@cipherstash/wizard`).
---

# CipherStash CLI

Configure and use `stash` for project initialization, EQL database setup, encryption schema management, and Supabase integration. Previously published as `@cipherstash/stack-forge`; the `stash-forge` binary is now consolidated under `stash`. The AI-powered wizard formerly bundled here lives in [`@cipherstash/wizard`](https://www.npmjs.com/package/@cipherstash/wizard).

## Trigger

Use this skill when:
- The user asks about setting up CipherStash EQL in a database
- Code imports `stash` (or legacy `@cipherstash/stack-forge`)
- A `stash.config.ts` file exists or needs to be created
- The user wants to install, configure, or manage the EQL extension in PostgreSQL
- The user is using any of the setup-lifecycle commands: `init`, `plan`, `impl`, `status`
- The user mentions "stash CLI", "stash db", "stack-forge", "stash-forge", "EQL install", or "encryption schema"
- The user has a `.cipherstash/` directory with `context.json`, `plan.md`, or `setup-prompt.md`

Do NOT trigger when:
- The user is working with `@cipherstash/stack` (the runtime SDK) without needing database setup
- The user is running the AI wizard — that's `@cipherstash/wizard`, a separate package
- General PostgreSQL questions unrelated to CipherStash

## What is stash?

`stash` is a **dev-time CLI and TypeScript library** for managing CipherStash EQL (Encrypted Query Language) in PostgreSQL databases. It is a companion to the `@cipherstash/stack` runtime SDK — it handles project setup and database tooling during development while `@cipherstash/stack` handles runtime encryption/decryption operations.

Think of it like Prisma Migrate or Drizzle Kit: a dev-time tool that prepares your database while the runtime SDK handles queries.

The binary is named `stash`. Top-level commands: `init`, `plan`, `impl`, `status`, `auth`, `db`, `schema`, `env`.

### Setup lifecycle (the recommended flow)

The setup lifecycle is split across four explicit save-points. Each command can be run standalone, but the chain prompts make first-time setup a single flow:

| Command | Owns | Ends with |
|---------|------|-----------|
| `stash init` | Auth, database, dep install, EQL install, encryption client scaffold, `.cipherstash/context.json` | Default-yes prompt → chains to `stash plan` |
| `stash plan` | Drafts `.cipherstash/plan.md` via agent handoff. State-driven — auto-detects whether to plan an encryption rollout or an encryption cutover. | Default-yes prompt → chains to `stash impl` |
| `stash impl` | Executes the plan via agent handoff. Refuses cutover-step plans without a recorded `dual_writing` event; prints the deploy-gate banner after a rollout-step run. | Deploy-gate banner (rollout) or "verify state" (cutover/new) |
| `stash status` | The encryption-rollout quest log — per-column "where am I" map, runs in ms | — |

### Running from automation (non-TTY)

If you're invoking `stash plan` or `stash impl` from a non-TTY context — CI, a pipe, or an agent's Bash tool — **always pass `--target <claude-code|codex|agents-md|wizard>`**. Both commands present an interactive agent-target picker that reads from `/dev/tty`; without `--target` they print a "no agent selected" hint and exit 0 without performing the handoff. With `--target`, the picker is skipped and the named handoff runs non-interactively.

```bash
stash plan --target claude-code
stash impl --target agents-md
```

`stash init` and `stash status` are safe to call from any context — they detect non-TTY and adapt automatically.

### Rolling encryption out to production

Two paths to a fully-encrypted column:

- **New encrypted column** — declared encrypted from the start. Single deploy. Use the `stash plan` → `stash impl` chain straight through.
- **Existing column with live data** — split across two passes around a hard production-deploy gate.

For migrate columns, the flow is:

1. **`stash plan`** detects that no `dual_writing` event is recorded and writes an encryption-rollout plan: schema-add for the encrypted twin and the application-side dual-write code. (If using CipherStash Proxy, the plan also includes `stash db push` to register the pending config.)
2. **`stash impl`** executes that plan and stops with a deploy-gate banner. Encrypted values are not flowing yet — the dual-write code has to be running in production before backfill is safe.
3. **You ship and deploy** the rollout PR.
4. **`stash status`** confirms dual-writes are live.
5. **`stash plan`** detects `dual_writing` and writes a separate cutover plan: backfill, schema rename, cutover, read-path switch, drop. (For Proxy users, the plan also includes `stash db push` after schema rename to register the new shape.)
6. **`stash impl`** executes the cutover.

The split is invisible to the user — they just keep running `stash plan` and `stash impl`; the CLI knows where they are.

For users without a deployed application to gate on (local dev, sandboxes, freshly-seeded test DBs), `stash plan --complete-rollout` produces a single end-to-end plan with no deploy gate. The flag prints a default-no confirm with a loud warning before generating; only safe when no production app writes to this database.

Use `stash status` at any time to see which save-points are complete and what each rollout's next move is.

> **Note:** Until issue [#447](https://github.com/cipherstash/stack/issues/447) follow-up lands, `stash encrypt cutover` requires a pending EQL configuration (set by `stash db push`). SDK users must run `stash db push` once before `stash encrypt cutover` to satisfy this precondition. Tracked separately and will be addressed in a follow-up.

## Configuration

### 1. Create `stash.config.ts` in the project root

```typescript
import { defineConfig } from 'stash'

export default defineConfig({
  databaseUrl: process.env.DATABASE_URL!,
  client: './src/encryption/index.ts',
})
```

`db install` will scaffold this file for you if it's missing.

### Config options

```typescript
type StashConfig = {
  databaseUrl: string          // Required: PostgreSQL connection string
  client?: string              // Optional: path to encryption client (default: './src/encryption/index.ts')
}
```

- `defineConfig()` provides TypeScript type-checking for the config file.
- `client` points to the encryption client file used by `db push` and `db validate` to load the encryption schema.
- Config is loaded automatically from `stash.config.ts` by walking up from `process.cwd()` (like `tsconfig.json` resolution).
- `.env` files are loaded automatically via `dotenv` before config evaluation.

## CLI Usage

The primary interface is the `stash` package. `stash init` installs it as a project dev dependency, so after init you invoke commands directly:

```bash
stash <command> [options]
```

Through your package manager (`pnpm exec`, `bun x`, `yarn`, or via `npm run`-style scripts), `stash` resolves to the project-local binary. **Before init has run** — for example when you're scaffolding the very first command — use your package manager's one-shot runner: `bunx stash init`, `pnpm dlx stash init`, `yarn dlx stash init`, or `npx stash init`. The CLI is package-manager-aware; pick whichever your project uses.

### `init` — Scaffold a CipherStash project

```bash
stash init
stash init --supabase
stash init --drizzle
```

Init is the **scaffold** save-point. It does mechanical setup only — no agent handoff. Six phases, prompts only when it can't make a sensible default:

1. **Authenticate** — only prompts when not already logged in (otherwise logs `Using workspace X (region)` and proceeds).
2. **Resolve database** — picks up `DATABASE_URL` from `.env`/`.env.local` or prompts for it. Verifies the connection.
3. **Build schema** — auto-detects your framework (Drizzle from `drizzle.config.*` / `drizzle-orm` / `drizzle-kit` in `package.json`; Supabase from the `DATABASE_URL` host) and silently writes a placeholder client to `./src/encryption/index.ts`. Only prompts you if a file already exists at that path.
4. **Install dependencies** — single combined prompt for `@cipherstash/stack` and `stash`. Skipped entirely when both are already in `node_modules`.
5. **Install EQL** — runs the equivalent of `stash db install` against the resolved database (Drizzle migration, Supabase migration, or direct, per detection). Skipped if EQL is already installed.
6. **Gather context** — detects available coding agents (Claude Code, Codex, Cursor, Windsurf, Cline) and writes `.cipherstash/context.json` with integration, package manager, schemas, env keys, and detected agents.

When init finishes, it prints a checkmark panel of completed phases and an interactive **chain prompt** (default-yes): *"Continue to `stash plan` now to draft your encryption plan?"* Yes auto-launches `stash plan`. No prints "Next: run `stash plan` to draft your encryption plan." Non-TTY (CI, pipes) skips the prompt and prints the hint.

The `--supabase` and `--drizzle` flags tailor the intro message and EQL install variant. File scaffolding uses the same auto-detection regardless.

#### Generated files

| File | Purpose |
|------|---------|
| `./src/encryption/index.ts` | Placeholder encryption client — edit to declare encrypted columns (or let `stash plan`/`stash impl` do it for you). |
| `.cipherstash/context.json` | Detected facts about the project (integration, pm, schemas, env keys, agents). Read by `plan`, `impl`, and `status`. Never hand-edit. |
| `stash.config.ts` | Scaffolded if missing — points the CLI at `databaseUrl` and the encryption client. |

### `plan` — Draft a reviewable encryption plan

```bash
stash plan
stash plan --complete-rollout
stash plan --target claude-code        # non-interactive — skip the agent picker
```

`plan` is the **draft for review** save-point. Pre-flights `.cipherstash/context.json` (errors with a "Run `stash init` first" pointer if missing). Hands off to a coding agent — all four targets are offered: Claude Code, Codex, AGENTS.md (for Cursor/Windsurf/Cline), and the CipherStash Agent (`@cipherstash/wizard`).

`--target <claude-code|codex|agents-md|wizard>` skips the interactive agent-target picker. **Required when invoking `plan` from a non-TTY context** (CI, pipes, an agent's Bash tool) — without it, `plan` prints a "no agent selected" hint and exits 0 without performing the handoff. In a TTY, `--target` is optional; it just bypasses the picker.

`plan` is **state-driven**. It reads `.cipherstash/migrations.json` and `cs_migrations` and dispatches to one of three plan templates:

| Detected state | Plan written |
|---|---|
| Manifest empty, fresh project, or no `dual_writing` events recorded | **Encryption rollout** — schema-add and dual-write code. (Proxy users also: `stash db push` to register pending.) Ends at the deploy gate. |
| At least one column has a `dual_writing` (or later) event recorded | **Encryption cutover** — backfill and schema rename. (Proxy users also: `stash db push` to register the renamed shape.) Requires the rollout to already be deployed. |
| `--complete-rollout` flag passed | **Complete rollout** — schema-add through drop, no deploy gate. Escape hatch for databases without a deployed application. Default-no confirm with a loud warning before generating. |

The chosen template drives the agent's prompt body for the Claude Code, Codex, and AGENTS.md handoffs. The wizard handoff receives `--mode plan` on argv and reads the resolved step from `.cipherstash/context.json` (the `planStep` field). Every target produces a valid plan-mode artifact at `.cipherstash/plan.md`.

The agent writes a machine-readable header `<!-- cipherstash:plan-summary { "step": ..., "columns": [...] } -->` at the top of the plan. `step` is `"rollout" | "cutover" | "complete"`; each column entry carries `path: "new" | "migrate"`. `stash impl` parses this header to render a confirmation panel and to enforce the deploy gate.

Ends with a default-yes prompt: *"Continue to `stash impl` now?"* Yes auto-launches `stash impl`.

To re-plan, delete `.cipherstash/plan.md` first — `stash plan` will warn (non-blocking) if a plan already exists, since the agent will be told to revise it rather than start fresh.

#### Why the rollout/cutover split

There is no atomic way to replace a populated plaintext column with an encrypted one without corrupting data. The rollout phase deploys the *capability* to write encrypted values (the encrypted twin column and the application-side dual-write code). The cutover phase deploys the *transition* (backfill historical rows, then rename swap so reads decrypt). Backfill is only safe once dual-writes are running in production, because any row written during the backfill window must be picked up by both columns — otherwise it lands in plaintext only and creates silent migration drift. The split makes that pre-condition explicit.

### `impl` — Execute the plan

```bash
stash impl
stash impl --continue-without-plan
stash impl --target claude-code        # non-interactive — skip the agent picker
```

`impl` is the **execute** save-point. Pre-flights `.cipherstash/context.json`. Behaviour branches on disk state:

| State | Behaviour |
|-------|-----------|
| Plan exists, TTY, no `--target` | Parses the summary block. Enforces the deploy gate (see below). Renders a confirm panel describing the plan scope. Default-yes confirm, then the agent-target picker. |
| Plan exists, TTY, `--target X` | Same confirm panel, but skips the picker and runs handoff `X`. |
| Plan exists, non-TTY, `--target X` | Logs the plan path, skips both the confirm and the picker, runs handoff `X`. |
| Plan exists, non-TTY, no `--target` | Logs the plan path, prints a "No agent selected — pass `--target`" hint, and exits 0 without performing the handoff. The deploy-gate check still runs first. |
| No plan, TTY | Interactive `p.select`: "Draft a plan first (recommended)" / "Continue without a plan" / cancel. "Draft" delegates to `stash plan`. "Continue" goes through a security confirm (default-no) before implementing. |
| No plan, `--continue-without-plan` | Skips the picker, runs the security confirm (still default-no), then implements. |
| No plan, non-TTY, no flag | Errors out with "Run `stash plan` first, or pass `--continue-without-plan` to skip planning." Forces explicit intent in CI. |

`--target <claude-code|codex|agents-md|wizard>` skips the interactive agent-target picker. **Required when invoking `impl` from a non-TTY context** (CI, pipes, an agent's Bash tool); without it, `impl` exits cleanly with a hint rather than hanging on `/dev/tty`. In a TTY, `--target` is optional.

Once the user clears the gate, `impl` dispatches to a handoff target (Claude Code, Codex, AGENTS.md for Cursor/Windsurf/Cline, or `@cipherstash/wizard`) and the agent executes the plan: schema edits, migrations, `stash db push`, `stash encrypt {backfill,cutover,drop}` as appropriate.

#### Deploy-gate enforcement

For plans with `step: "cutover"`, `impl` queries `cs_migrations` for every column listed in the plan-summary block and verifies that each one has a `dual_writing` (or later) event recorded. If any are missing, `impl` refuses to proceed and points the user at re-running `stash plan` after their rollout PR is deployed. The error names the specific columns that are not yet recorded.

This is the safety net for the case where someone runs cutover work locally before the dual-write code is actually live in production. The encrypt commands themselves also gate on the same event before doing anything destructive, but `impl` checks early so the confirm prompt never appears for an unsafe plan.

#### Outro

After a successful handoff:

- **`step: "rollout"`** — prints a deploy-gate banner explaining that encrypted values are not yet flowing because the dual-write code is not deployed, with the next-step sequence (deploy → `stash status` → `stash plan`).
- **`step: "cutover"` or `step: "complete"`** — prints a generic "verify state" outro pointing at `stash status`.
- **No plan / no summary** — same generic outro.

`--continue-without-plan` exists to support scripts and one-off implementations where planning isn't needed. It is **not** a way to bypass safety — the security confirm still fires when interactive, and the cutover-step deploy-gate check applies regardless.

### `status` — The encryption-rollout quest log

```bash
stash status
stash status --quest        # force the fancy output anywhere
stash status --plain        # force the plain-text fallback anywhere
stash status --json         # structured output for scripts
```

`status` is the **map**. Reads `.cipherstash/context.json` (was init run?), `.cipherstash/migrations.json` (which columns are tracked?), and — best-effort — `cs_migrations` plus `eql_v2_configuration` for live per-column state. DB connectivity is optional; when missing, the command falls back to a manifest-only view and surfaces a footer note.

Renders one **quest** per tracked column. Each quest carries:

- A title (`Encrypt users.email` for migrate columns; `Add encrypted column orders.note` for new columns).
- A progress bar and an `N/M objectives` count.
- A list of objectives with `✓` for done, `▸` for the active "you are here" objective, and `🔒` for locked.
- A one-line "Next move" hint naming the concrete CLI invocation when relevant (`stash encrypt backfill --table users --column email`, etc.).

Quests separate into **active** (something to do next) and **completed** (🏆 line per column).

Output mode:

- **TTY by default** — the quest-log shape with emoji and progress bars.
- **Non-TTY by default** — a plain-text fallback with the same content (no emoji, bracketed status markers `[x]` / `[>]` / `[ ]`). Designed for CI logs, pipes, and agents reading the output.
- **`--quest`** forces the fancy shape anywhere; **`--plain`** forces the plain shape anywhere; **`--json`** emits a structured JSON document.

Use the JSON form for scripts; it has a stable shape (`active`, `completed`, per-quest `objectives`, `progress`, `nextMove`) that does not break without a major version bump.

Run `status` after every transition during a rollout. It is the canonical "where am I?" surface; agents working through the rollout should re-read it as they go rather than tracking state mentally.

For the deeper, raw views that touch only the database, use `stash db status` (EQL installation state) and `stash encrypt status` (per-column migration phase, EQL state, backfill progress with drift detection).

### `auth login` — Authenticate with CipherStash

```bash
stash auth login
```

Opens a browser-based device code flow and saves a token to `~/.cipherstash/auth.json`. Database-touching commands check for this file before running.

### `db install` — Configure the database and install EQL extensions

```bash
stash db install
stash db install --supabase
stash db install --supabase --migration
stash db install --supabase --direct
stash db install --drizzle
stash db install --force
```

`stash init` runs `db install` automatically as part of its EQL install phase. Run `db install` directly when you skipped init, when you need flags init doesn't expose (`--migration`, `--migrations-dir`, `--exclude-operator-family`), or when re-installing/upgrading EQL on its own.

`db install` is the single command that gets a project from zero to installed EQL:

1. Scaffolds `stash.config.ts` if missing (auto-detects an existing client file at common locations, otherwise prompts).
2. Loads the config.
3. **Safety net:** scaffolds the encryption client file at `config.client` if it doesn't exist (no-op when present). Lets users who skip `init` still end up with a working client file.
4. Detects Supabase (`DATABASE_URL` host) and Drizzle (lockfile / `drizzle-orm` dep) automatically.
5. For Drizzle: generates a Drizzle migration containing the EQL SQL (`drizzle-kit generate --custom --name=...`).
6. For Supabase non-Drizzle: prompts between writing a Supabase migration file and direct install. Pre-selects migration when `supabase/migrations/` exists.
7. Otherwise: installs EQL directly into the database.

**Flags:**

| Flag | Description |
|------|-------------|
| `--force` | Reinstall even if EQL is already installed |
| `--dry-run` | Show what would happen without making changes |
| `--supabase` | Supabase-compatible install (no operator families + grants `anon`, `authenticated`, `service_role`) |
| `--exclude-operator-family` | Skip operator family creation (useful for non-superuser roles) |
| `--drizzle` | Generate a Drizzle migration instead of direct install |
| `--latest` | Fetch latest EQL from GitHub instead of using the bundled version |
| `--name <value>` | Migration name when using `--drizzle` (default: `install-eql`) |
| `--out <value>` | Drizzle output directory when using `--drizzle` (default: `drizzle`) |
| `--migration` | Write the EQL SQL into a Supabase migration file (requires `--supabase`) |
| `--direct` | Run the EQL SQL directly against the database (requires `--supabase`; mutually exclusive with `--migration`) |
| `--migrations-dir <path>` | Override the Supabase migrations directory (requires `--supabase`; default: `supabase/migrations`) |

`--migration`, `--direct`, and `--migrations-dir` only make sense in the Supabase flow and require `--supabase` to be passed explicitly. They never auto-enable `--supabase`.

#### `db install --drizzle`

When `--drizzle` is passed, the CLI:
1. Runs `drizzle-kit generate --custom --name=<name>` to scaffold an empty migration.
2. Loads the bundled EQL install SQL (or downloads from GitHub with `--latest`).
3. Writes the SQL into the generated migration file.

You then run `npx drizzle-kit migrate` to apply it. Requires `drizzle-kit` as a dev dependency.

#### `db install --supabase --migration`

Writes the EQL SQL to `supabase/migrations/00000000000000_cipherstash_eql.sql`. The all-zero timestamp ensures this migration runs before any user migrations that reference `eql_v2_encrypted`. Run `supabase db reset` (local) or `supabase migration up` (remote) to apply it.

Direct-push installs (`--supabase --direct`) do **not** survive `supabase db reset` — the reset drops the database and reruns only files in `supabase/migrations/`. Use `--migration` for projects that use `supabase db reset`.

### `db upgrade` — Upgrade EQL extensions

```bash
stash db upgrade
stash db upgrade --dry-run
stash db upgrade --supabase
stash db upgrade --latest
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would happen without making changes |
| `--supabase` | Use Supabase-compatible upgrade |
| `--exclude-operator-family` | Skip operator family creation |
| `--latest` | Fetch latest EQL from GitHub instead of bundled |

The EQL install SQL is idempotent and safe to re-run. The command checks the current version, re-runs the install SQL, then reports the new version. If EQL is not installed, it suggests running `db install` instead.

### `db validate` — Validate encryption schema

```bash
stash db validate
stash db validate --supabase
stash db validate --exclude-operator-family
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--supabase` | Check for Supabase-specific issues |
| `--exclude-operator-family` | Check for issues when operator families are excluded |

**Validation rules:**

| Rule | Severity | Description |
|------|----------|-------------|
| `freeTextSearch` on non-string column | Warning | Free-text search only works with string data |
| `orderAndRange` without operator families | Warning | ORDER BY won't work without operator families |
| No indexes on encrypted column | Info | Column is encrypted but not searchable |
| `searchableJson` without `json` data type | Error | searchableJson requires `dataType("json")` |

Validation also runs automatically before `db push` — issues are logged as warnings but don't block the push.

### `db push` — Register the encryption schema with EQL

Synchronises the CipherStash configuration in `eql_v2_configuration` with what your encryption client declares.

**Required for CipherStash Proxy users** — Proxy needs to know which columns to encrypt/decrypt.

**Not needed for SDK users** — Drizzle, Supabase, and plain PostgreSQL SDK users have their encryption config in application code. The database does not need a copy. See the "Known gap" note below.

```bash
stash db push
stash db push --dry-run
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--dry-run` | Load and validate the schema, then print it as JSON. No database changes. |

When pushing, the CLI:

1. Loads the encryption client from the path in `stash.config.ts`.
2. Runs schema validation (warns but doesn't block).
3. Transforms SDK data types to EQL-compatible `cast_as` values (see table below).
4. Connects to Postgres and decides where to write based on existing state:
   - **No active EQL config exists** (first push) → writes directly to `active`. Encryption is live immediately. No further step required.
   - **Active config already exists** → writes the new config as `pending`, replacing any prior pending. The active config keeps serving until you finalise the change with one of the activation commands below.

**Activation after a `pending` push:**

| Situation | Command |
|-----------|---------|
| Adding a brand-new encrypted column (no rename) | `stash db activate` |
| Cutting over from a `<col>_encrypted` twin (path 3 lifecycle) | `stash encrypt cutover --table T --column C` |

> **Known gap:** `stash encrypt cutover` currently requires a pending EQL configuration (satisfied by `stash db push`). SDK-only users running the migrate-existing-column flow will encounter this precondition. Work to decouple `encrypt cutover` from EQL config for SDK-only users (using direct SQL rename instead) is tracked as follow-up work to [issue #447](https://github.com/cipherstash/stack/issues/447) and will be addressed in a future release.

**SDK to EQL type mapping:**

| SDK type (`dataType()`) | EQL `cast_as` |
|-------------------------|---------------|
| `string` | `text` |
| `text` | `text` |
| `number` | `double` |
| `bigint` | `big_int` |
| `boolean` | `boolean` |
| `date` | `date` |
| `json` | `jsonb` |

### `db activate` — Promote pending → active without renaming

Runs `eql_v2.migrate_config()` followed by `eql_v2.activate_config()` inside a single transaction, advancing any `pending` row to `active` (and marking the prior `active` as `inactive`). No physical column renames.

```bash
stash db activate
```

Use after `stash db push` when the new config purely adds columns or changes index ops without renaming any column. For path 3 (existing populated column → encrypted), use `stash encrypt cutover` instead — it does the same activation plus the physical rename.

Errors out with a clear message when there is no pending configuration to activate.

### `db status` — Show EQL installation status

```bash
stash db status
```

Reports:
- Whether EQL is installed and which version.
- Database permission status.
- Whether an active encrypt config exists in `eql_v2_configuration` (only relevant for CipherStash Proxy).

### `db test-connection` — Test database connectivity

```bash
stash db test-connection
```

Verifies the database URL in your config is valid and the database is reachable. Reports the database name, connected role, and PostgreSQL server version. Useful for debugging connection issues before running `db install`.

### `db migrate` — Run pending encrypt config migrations

```bash
stash db migrate
```

Not yet implemented — placeholder for future encrypt-config migration tooling.

### `encrypt` — Drive the encryption-cutover work for a column

The `encrypt` group is the cutover-step toolset: it runs the database-side work that takes an existing plaintext column the rest of the way to encrypted, after the encryption-rollout PR is deployed and dual-writes are live in production. The internal event log uses `schema-added → dual-writing → backfilling → backfilled → cut-over → dropped` as machine-readable phase names; the user-facing story is the rollout/cutover model documented in the `stash-encryption` skill.

It drives the `@cipherstash/migrate` library, which records every transition in a `cipherstash.cs_migrations` table (installed by `stash db install`) and reads the user's intent from `.cipherstash/migrations.json`. This section documents the CLI surface.

The examples below show the bare `stash` form, which works after `stash init` adds the CLI as a project dev dep. See the "CLI Usage" section above for how to invoke it through your package manager before that.

#### `encrypt status` — Show per-column phase, EQL state, and backfill progress

```bash
stash encrypt status
stash encrypt status --table users
```

Reads three sources in parallel — the `migrations.json` manifest (intent), the live `eql_v2_configuration` row (EQL state), and the latest `cs_migrations` event per column (runtime state) — and renders a table per column with phase, indexes, progress, and any drift between intent and observed state.

#### `encrypt plan` — Diff intent vs. observed state

```bash
stash encrypt plan
```

Like `status`, but explicitly lists what would change to reconcile observed state with `.cipherstash/migrations.json`. Read-only — does not mutate the DB or the manifest.

#### `encrypt backfill` — Resumably encrypt plaintext into the encrypted column

```bash
stash encrypt backfill --table users --column email
stash encrypt backfill --table users --column email --chunk-size 5000
stash encrypt backfill --table users --column email --confirm-dual-writes-deployed
stash encrypt backfill --table users --column email --force
```

Chunked, resumable, idempotent backfill. Walks the table in keyset-pagination order, encrypts each chunk via `bulkEncryptModels` from `@cipherstash/stack`, and writes a single `UPDATE ... FROM (VALUES ...)` per chunk inside a transaction that also checkpoints to `cs_migrations`. SIGINT/SIGTERM finishes the current chunk and exits cleanly; re-running picks up from the last checkpoint. The `<col> IS NOT NULL AND <col>_encrypted IS NULL` guard makes concurrent runners and re-runs safe — they converge.

**Dual-write precondition.** Backfill requires the application to already be writing to both `<col>` (plaintext) and `<col>_encrypted` (ciphertext) on every insert/update — otherwise rows inserted *during* the backfill land in plaintext only and create silent migration drift. The first run on a column prompts the user (interactive) or accepts `--confirm-dual-writes-deployed` (non-interactive, with a loud warning), then records the `dual_writing` transition in `cs_migrations`. Subsequent runs / resumes don't need the prompt — the bookmark is persisted.

Flags:

- `--table <name>` / `--column <name>` — required.
- `--chunk-size <n>` — default 1000. Lower for lock contention, raise for wide rows.
- `--pk-column <name>` — override primary-key auto-detection. Required for composite PKs (pick one comparable column).
- `--encrypted-column <name>` — override `<col>_encrypted` if your schema uses a non-standard target name.
- `--schema-column-key <key>` — override the key used to look up the column in the `EncryptedTable` schema; defaults to the encrypted column name.
- `--confirm-dual-writes-deployed` — non-interactive equivalent of saying yes to the dual-write prompt. Use in CI/scripts.
- `--force` — re-encrypt every plaintext row, including rows that already have a (potentially stale) ciphertext. Recovery path for drift caused by dual-writes that weren't actually deployed when an earlier backfill ran. Expensive but not destructive — re-encrypting a correctly-encrypted value just rewrites the same payload. Audit-trail-flagged via `details.force = true` in `cs_migrations`.

#### `encrypt cutover` — Rename swap encrypted → primary column AND promote pending → active

```bash
stash encrypt cutover --table users --column email
```

**Precondition:** the column must be in the `backfilled` phase per `cs_migrations`, AND a pending EQL configuration must exist (registered via `stash db push` against a schema where the column is declared under its final name without the `_encrypted` suffix).

In a single transaction, the command:

1. Runs `eql_v2.rename_encrypted_columns()` to rename `<col>` → `<col>_plaintext` and `<col>_encrypted` → `<col>`.
2. Runs `eql_v2.migrate_config()` to advance the pending config to `encrypting`.
3. Runs `eql_v2.activate_config()` to promote it to `active` (and mark the prior active config as `inactive`).
4. Appends a `cut_over` event to `cs_migrations` for the column.

If a Proxy URL is configured (via `--proxy-url` or `CIPHERSTASH_PROXY_URL`), it then connects to the Proxy and calls `eql_v2.reload_config()` so Proxy picks up the new shape immediately. App reads of `<col>` now return decrypted ciphertext transparently — no app code change required for reads.

#### `encrypt drop` — Generate a migration that removes the plaintext column

```bash
stash encrypt drop --table users --column email
```

For columns in the `cut_over` phase. Detects the user's migration tooling (Drizzle today; Prisma + raw-SQL planned) and emits a migration file containing `ALTER TABLE <table> DROP COLUMN <col>_plaintext;`. Does not apply the migration — the user reviews and runs their normal migrate command. Records the `dropped` event only after a follow-up `encrypt status` confirms the column is gone from `information_schema.columns`.

### `schema build` — Generate an encryption client from your database

```bash
stash schema build
stash schema build --supabase
```

Connects to your database, lets you select tables and columns to encrypt, asks about searchable indexes, and generates a typed encryption client file. Reads `databaseUrl` from `stash.config.ts`.

For AI-guided schema integration that edits your existing schema files in place, the recommended path is `stash plan` followed by `stash impl` — these add a planning save-point and can hand off to Claude Code, Codex, an AGENTS.md-driven editor, or the in-house `@cipherstash/wizard` package. `npx @cipherstash/wizard` standalone is still available for users who want to skip the plan checkpoint.

### `env` — Print production env vars for deployment

```bash
stash env
stash env --write
```

Experimental. Prints the environment variables (`CS_*`) you need to deploy a CipherStash-backed app. With `--write`, writes them into a `.env.production` file.

## Programmatic API

### `defineConfig(config: StashConfig): StashConfig`

Identity function that provides type-safe configuration for `stash.config.ts`.

### `loadStashConfig(): Promise<ResolvedStashConfig>`

Finds and loads `stash.config.ts` from the current directory or any parent. Validates with Zod. Applies defaults (e.g. `client` defaults to `'./src/encryption/index.ts'`). Exits with code 1 if config is missing or invalid.

### `loadBundledEqlSql(options?): string`

Load the bundled EQL install SQL as a string:

```typescript
import { loadBundledEqlSql } from 'stash'

const sql = loadBundledEqlSql()                                // standard
const sql = loadBundledEqlSql({ supabase: true })              // supabase variant
const sql = loadBundledEqlSql({ excludeOperatorFamily: true }) // no operator family
```

### `downloadEqlSql(excludeOperatorFamily?): Promise<string>`

Download the latest EQL install SQL from GitHub releases.

### `EQLInstaller`

```typescript
import { EQLInstaller } from 'stash'

const installer = new EQLInstaller({ databaseUrl: 'postgresql://...' })
```

#### `installer.checkPermissions(): Promise<PermissionCheckResult>`

Checks that the database role has the required permissions to install EQL.

```typescript
type PermissionCheckResult = {
  ok: boolean       // true if all permissions are present
  missing: string[] // list of missing permissions (empty if ok)
}
```

Required permissions (one of):
- `SUPERUSER` role (sufficient for everything), OR
- `CREATE` privilege on database + `CREATE` privilege on `public` schema
- If `pgcrypto` is not installed: also needs `SUPERUSER` or `CREATEDB`

#### `installer.isInstalled(): Promise<boolean>`

Returns `true` if the `eql_v2` schema exists in the database.

#### `installer.getInstalledVersion(): Promise<string | null>`

Returns the installed EQL version string, `'unknown'` if schema exists but no version metadata, or `null` if not installed.

#### `installer.install(options?): Promise<void>`

Executes the EQL install SQL in a transaction.

```typescript
await installer.install({
  excludeOperatorFamily?: boolean  // Skip operator family creation
  supabase?: boolean               // Use Supabase-compatible install + grant roles
  latest?: boolean                 // Fetch latest from GitHub instead of bundled
})
```

## Full programmatic example

```typescript
import { EQLInstaller, loadStashConfig } from 'stash'

const config = await loadStashConfig()
const installer = new EQLInstaller({ databaseUrl: config.databaseUrl })

// Check permissions first
const permissions = await installer.checkPermissions()
if (!permissions.ok) {
  console.error('Missing permissions:', permissions.missing)
  process.exit(1)
}

// Install if not already present
if (await installer.isInstalled()) {
  const version = await installer.getInstalledVersion()
  console.log(`EQL already installed (version: ${version})`)
} else {
  await installer.install()
  console.log('EQL installed successfully')
}
```

## Requirements

- Node.js >= 22
- PostgreSQL database with sufficient permissions (see `checkPermissions()`)
- A `stash.config.ts` file with a valid `databaseUrl` (or run `stash init` / `stash db install` to scaffold it)
- Peer dependency: `@cipherstash/stack` >= 0.6.0

## Common issues

### Permission errors during install

The database role needs `CREATE` privileges on the database and public schema, or `SUPERUSER`. Run `checkPermissions()` or check the CLI output for details on what's missing.

### Config not found

`stash.config.ts` must be in the project root or a parent directory. The file must `export default defineConfig(...)`. The fastest fix is `stash init`, which scaffolds the config (and authenticates, installs deps, installs EQL, and writes `.cipherstash/context.json` in the same run). For a CLI-only setup, `stash db install` also scaffolds the config.

### Supabase environments

Always use `--supabase` (or `supabase: true` programmatically) when targeting Supabase. This uses a compatible install script and grants permissions to `anon`, `authenticated`, and `service_role` roles.

### Operator families and ORDER BY

When EQL is installed with `--supabase` or `--exclude-operator-family`, PostgreSQL operator families are not created. This means `ORDER BY` on encrypted columns is **not currently supported** — regardless of the client or ORM used (Drizzle, Supabase JS SDK, raw SQL, etc.).

Sort application-side after decrypting the results as a workaround.

Operator family support for Supabase is being developed with the Supabase and CipherStash teams and will be available in a future release. This limitation applies to any database environment where operator families are not installed.

## Related skills

- **`@cipherstash/wizard`** — AI-guided encryption setup. Reads your codebase, asks which columns to encrypt, edits your schema and call sites in place. Run with `npx @cipherstash/wizard`. Separate package from this CLI.
- **`stash-encryption`** — Defines encrypted schemas and uses `Encryption()` / `encryptModel` / `decryptModel` at runtime via `@cipherstash/stack`.
- **`stash-drizzle`** / **`stash-supabase`** — Drizzle and Supabase integrations.
