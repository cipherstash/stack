# stash

[![npm version](https://img.shields.io/npm/v/stash.svg?style=for-the-badge&labelColor=000000)](https://www.npmjs.com/package/stash)
[![License: MIT](https://img.shields.io/npm/l/stash.svg?style=for-the-badge&labelColor=000000)](https://github.com/cipherstash/stack/blob/main/LICENSE.md)

The single CLI for CipherStash. It handles authentication, project initialization, EQL database lifecycle (install, upgrade, validate, push, migrate), and schema building. Install it as a devDependency alongside the runtime SDK `@cipherstash/stack`.

---

## Quickstart

```bash
npm install -D stash
npx stash auth login    # authenticate with CipherStash
npx stash init          # scaffold, introspect, install EQL
```

`stash init` does the scaffold-once work as one flow: authenticate, resolve `DATABASE_URL`, choose Proxy or direct SDK access, introspect your database and scaffold an encryption client, install dependencies, install the EQL extension, and write `.cipherstash/context.json`. It stops there, at a clean save-point, and offers to continue into `stash plan`.

The agent handoff belongs to the next two commands — `stash plan` drafts a reviewable `.cipherstash/plan.md`, and `stash impl` executes it. Both present the same four targets:

- **Hand off to Claude Code** — copies the per-integration set of skills (`stash-encryption`, `stash-<integration>`, `stash-cli`) into `.claude/skills/`, writes `.cipherstash/context.json` and `setup-prompt.md`, then launches `claude` interactively.
- **Hand off to Codex** — copies the same skills into `.codex/skills/`, writes a sentinel-managed `AGENTS.md` (durable doctrine), plus `.cipherstash/` context files, then launches `codex`.
- **Use the CipherStash Agent** — runs the in-house wizard (`@cipherstash/wizard`).
- **Write AGENTS.md** — for editor agents (Cursor / Windsurf / Cline) that don't auto-load skill directories. Writes a single `AGENTS.md` with the doctrine *plus* the relevant skill content inlined under a sentinel block, and stops.

Pass `--target <claude-code|codex|agents-md|wizard>` to skip the picker. **It is required when running `plan` or `impl` non-interactively** (CI, pipes, an agent's shell) — the picker reads from `/dev/tty`, so without it the command prints a hint and exits without handing off.

A project-specific action plan is written to `.cipherstash/setup-prompt.md` regardless of which target you pick — it tells the agent exactly what's already done and what's left, with the right commands for your package manager and ORM. The matching context (selected columns, env keys, paths, versions) is at `.cipherstash/context.json`.

If neither `claude` nor `codex` is on PATH, the handoff still writes the rules files and prints install instructions — your progress is never wasted.

---

## Recommended flow

```
npx stash auth login
    └── npx stash init      ← introspects DB, installs EQL, writes context.json
            └── npx stash plan   ← drafts .cipherstash/plan.md for review
                    └── npx stash impl   ← agent edits schema files / generates migrations
                            └── npx stash status   ← where am I?
```

`stash` covers authentication, initialization, EQL install/upgrade/status, schema introspection, the encryption rollout and cutover commands, and a `stash wizard` subcommand that thin-wraps [`@cipherstash/wizard`](https://www.npmjs.com/package/@cipherstash/wizard). The wizard package itself is a separate npm install — kept out of the `stash` bundle so the agent SDK doesn't bloat the CLI.

> `stash db push` is **not** part of the default flow. It registers the encryption config in `public.eql_v2_configuration`, which only [CipherStash Proxy](https://github.com/cipherstash/proxy) reads. SDK users (Drizzle, Supabase, plain PostgreSQL) keep that config in application code and can skip it.

---

## Configuration

`stash.config.ts` is the single source of truth for database-touching commands. Create it in your project root:

```typescript filename="stash.config.ts"
import { defineConfig } from 'stash'

export default defineConfig({
  databaseUrl: process.env.DATABASE_URL!,
  client: './src/encryption/index.ts',
})
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `databaseUrl` | Yes | — | PostgreSQL connection string |
| `client` | No | `./src/encryption/index.ts` | Path to your encryption client file |

The CLI loads `.env` files automatically before reading the config, so `process.env` references work without extra setup. The config file is resolved by walking up from the current working directory.

Commands that consume `stash.config.ts`: `eql install`, `eql upgrade`, `db push`, `db validate`, `eql status`, `db test-connection`, `schema build`. `eql install` will scaffold `stash.config.ts` for you if it's missing.

---

## Commands reference

### `npx stash init`

Set up CipherStash end-to-end: authenticate, introspect your database, install dependencies, install EQL, and hand off the rest to your local coding agent.

```bash
npx stash init [--supabase] [--drizzle] [--region <slug>]
```

| Flag | Description |
|------|-------------|
| `--supabase` | Use the Supabase-specific setup flow |
| `--drizzle` | Use the Drizzle-specific setup flow |
| `--region <slug>` | Region to authenticate against (e.g. `us-east-1`). Skips the interactive region picker. Also settable via `STASH_REGION`. |

What `init` does, in order:

1. **Authenticate** — re-uses an existing token if found, otherwise opens the browser device-code flow.
2. **Resolve `DATABASE_URL`** — flag → env → `supabase status` → interactive prompt → hard-fail. The same resolver `eql install` uses.
3. **Generate the encryption client** — connects to your database, lists tables, and prompts you to multi-select which columns to encrypt. Writes `./src/encryption/index.ts` with the right shape for the detected ORM (Drizzle / Supabase / plain Postgres). Falls back to a placeholder if the database has no tables yet.
4. **Install dependencies** — `@cipherstash/stack` (runtime) and `stash` (dev), with a confirmation prompt.
5. **Install EQL** — runs `stash eql install` against the resolved URL after a y/N confirm.
6. **Hand off** — four-option menu (Claude Code / Codex / CipherStash Agent / write `AGENTS.md`). See the Quickstart section above for what each option writes and spawns.

The full pipeline state — integration, columns, env-key names, paths, versions — is captured in `.cipherstash/context.json`. The action plan at `.cipherstash/setup-prompt.md` tells whichever agent picks up next what's already done and what's left.

`CIPHERSTASH_WIZARD_URL` overrides the gateway endpoint for the rulebook fetch. Useful for local-dev against a wizard gateway running on `localhost`.

**Running `init` non-interactively** (CI, agents, pipes): every prompt has an escape hatch, so `init` never blocks waiting on a TTY. Provide the region up front (`--region` / `STASH_REGION`) if you aren't already logged in, the database URL (`--database-url` / `DATABASE_URL`), the proxy choice (`--proxy` / `--no-proxy`), and — for the closing agent handoff — nothing is required (init exits at a clean checkpoint and points you at `stash plan --target …`). When a required value is missing in a non-TTY context the command exits non-zero with an actionable message rather than hanging.

```bash
STASH_REGION=us-east-1 DATABASE_URL=postgres://… npx stash init --no-proxy
```

---

### `npx stash auth login`

Authenticate with CipherStash using a browser-based device code flow.

```bash
npx stash auth login [--region <slug>] [--json] [--no-open]
```

| Flag | Description |
|------|-------------|
| `--region <slug>` | Region to authenticate against (e.g. `us-east-1`). Skips the interactive region picker. Also settable via `STASH_REGION`. |
| `--json` | Emit newline-delimited JSON events instead of prose (see below). Implies non-interactive — never renders the region picker, and never auto-opens a browser (the human opens the URL you hand them). |
| `--no-open` | Don't auto-open the verification URL in a browser (already implied by `--json`). |
| `--supabase` / `--drizzle` | Track the integration as the referrer. |

Saves the token to `~/.cipherstash/auth.json`. Database-touching commands check for this file before running.

#### Triggering auth from an agent (device-code flow)

The device-code flow is designed so an **agent can trigger** authentication but only a **human completes** it in the browser. Run `auth login --json` in the background and read the first line — `authorization_required` carries the verification URL to hand to the user:

```bash
npx stash auth login --region us-east-1 --json
```

```jsonc
// stdout is newline-delimited JSON, one event per line:
{"status":"authorization_required","userCode":"ABCD-1234","verificationUri":"https://…/activate","verificationUriComplete":"https://…/activate?user_code=ABCD-1234","expiresIn":899}
// … the process then blocks polling until the human authorizes in the browser …
{"status":"authorized","expiresAt":1751990400,"expiresAtIso":"2025-07-08T12:00:00.000Z"}
{"status":"device_bound"}
```

Errors are emitted as `{"status":"error","code":"…","message":"…"}` and exit non-zero. In a non-TTY context without `--region`/`STASH_REGION` the command exits immediately with `code: "region_required"` instead of hanging on the picker.

---

### `npx stash auth regions`

List the regions you can authenticate against — a first-contact affordance so you (or an agent) can discover valid `--region` / `STASH_REGION` values up front instead of learning them from an error.

```bash
npx stash auth regions          # human-readable list
npx stash auth regions --json   # machine-readable [{ "slug": "…", "label": "…" }]
```

```jsonc
// --json output:
[{"slug":"us-east-1","label":"us-east-1 (Virginia, USA)"}, {"slug":"us-east-2","label":"us-east-2 (Ohio, USA)"}, …]
```

> The region list is currently maintained in the CLI. The intended long-term source of truth is the CipherStash region API (tracked by a `TODO` in `src/commands/auth/region.ts`); when that lands, this command and the runtime SDK should both read from it.

---

### `npx stash wizard`

Launch the CipherStash AI wizard. Thin wrapper around [`@cipherstash/wizard`](https://www.npmjs.com/package/@cipherstash/wizard) — the wizard ships as a separate npm package so the agent SDK stays out of the `stash` bundle, but you don't need to remember a second tool name.

```bash
npx stash wizard [...flags]
```

Any flags after `wizard` are forwarded verbatim to the wizard package. On the first run the package manager downloads the wizard (~5s); subsequent runs are instant.

---

### `npx stash eql install`

Configure your database and install CipherStash EQL extensions in a single command. Run this after `npx stash init`. (`npx stash db install` is a deprecated alias — it still works but prints a warning.)

When `stash.config.ts` is missing, the command auto-detects your encryption client file (or asks for the path) and writes the config before installing. Supabase and Drizzle are detected from your `DATABASE_URL` and project files, so the matching flags default on. Install uses bundled SQL for offline, deterministic runs.

```bash
npx stash eql install [options]
```

| Flag | Description |
|------|-------------|
| `--force` | Reinstall even if EQL is already installed |
| `--dry-run` | Show what would happen without making changes |
| `--supabase` | Supabase-compatible install (no operator families + grants Supabase roles) |
| `--exclude-operator-family` | Skip operator family creation |
| `--drizzle` | Generate a Drizzle migration instead of direct install |
| `--latest` | Fetch the latest EQL from GitHub |
| `--name <value>` | Migration name (Drizzle mode, default: `install-eql`) |
| `--out <value>` | Drizzle output directory (default: `drizzle`) |

The `--supabase` flag uses a Supabase-specific SQL variant and grants `USAGE`, table, routine, and sequence permissions on the `eql_v2` schema to the `anon`, `authenticated`, and `service_role` roles.

> **Good to know:** Without operator families, `ORDER BY` on encrypted columns is not supported. Sort application-side after decrypting results as a workaround. This applies to both `--supabase` and `--exclude-operator-family` installs.

---

### `npx stash eql upgrade`

Upgrade an existing EQL installation to the version bundled with the package (or the latest from GitHub).

```bash
npx stash eql upgrade [options]
```

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would happen without making changes |
| `--supabase` | Use Supabase-compatible upgrade |
| `--exclude-operator-family` | Skip operator family creation |
| `--latest` | Fetch the latest EQL from GitHub |

The install SQL is idempotent and safe to re-run. If EQL is not installed, the command suggests running `npx stash eql install` instead.

---

### `npx stash db push`

Push your encryption schema to the database. **Only required when using CipherStash Proxy.** If you use the SDK directly with Drizzle, Supabase, or plain PostgreSQL, skip this step.

```bash
npx stash db push [--dry-run]
```

| Flag | Description |
|------|-------------|
| `--dry-run` | Load and validate the schema, print as JSON. No database changes. |

When pushing, the CLI loads the encryption client from `stash.config.ts`, runs schema validation (warns but does not block), maps SDK types to EQL types, and upserts the config row in `eql_v2_configuration`.

**SDK to EQL type mapping:**

| SDK `dataType()` | EQL `cast_as` |
|------------------|---------------|
| `string` / `text` | `text` |
| `number` | `double` |
| `bigint` | `big_int` |
| `boolean` | `boolean` |
| `date` | `date` |
| `json` | `jsonb` |

---

### `npx stash db validate`

Validate your encryption schema for common misconfigurations.

```bash
npx stash db validate [--supabase] [--exclude-operator-family]
```

| Rule | Severity |
|------|----------|
| `freeTextSearch` on a non-string column | Warning |
| `orderAndRange` without operator families | Warning |
| No indexes on an encrypted column | Info |
| `searchableJson` without `dataType("json")` | Error |

The command exits with code 1 on errors (not on warnings or info). Validation also runs automatically before `db push`.

---

### `npx stash db migrate`

Run pending encrypt config migrations.

```bash
npx stash db migrate
```

> **Good to know:** This command is not yet implemented.

---

### `npx stash eql status`

Show the current state of EQL in your database.

```bash
npx stash eql status
```

Reports EQL installation status and version, database permission status, and whether an active encrypt config exists in `eql_v2_configuration` (relevant only for CipherStash Proxy).

---

### `npx stash db test-connection`

Verify that the database URL in your config is valid and the database is reachable.

```bash
npx stash db test-connection
```

Reports the database name, connected role, and PostgreSQL server version.

---

### `npx stash schema build`

Build an encryption client file from your database schema using DB introspection.

```bash
npx stash schema build [--supabase]
```

Connects to your database, lets you select tables and columns to encrypt, asks about searchable indexes, and generates a typed encryption client file.

Reads `databaseUrl` from `stash.config.ts`.

---

## Drizzle migration mode

Use `--drizzle` with `npx stash eql install` to add EQL installation to your Drizzle migration history instead of applying it directly. `--drizzle` is auto-detected when your project has `drizzle-orm`, `drizzle-kit`, or a `drizzle.config.*` file, so you usually don't need to pass it explicitly.

```bash
npx stash eql install --drizzle
npx drizzle-kit migrate
```

How it works:
1. Runs `npx drizzle-kit generate --custom --name=<name>` to create an empty migration.
2. Loads the bundled EQL SQL (or fetches from GitHub with `--latest`).
3. Writes the EQL SQL into the generated migration file.

With a custom name or output directory:

```bash
npx stash eql install --drizzle --name setup-eql --out ./migrations
npx drizzle-kit migrate
```

`drizzle-kit` must be installed in your project (`npm install -D drizzle-kit`). The `--out` directory must match your `drizzle.config.ts`.

---

## Required database permissions

Before installing EQL, the CLI verifies that the connected role has:

- `CREATE` on the database (for `CREATE SCHEMA` and `CREATE EXTENSION`).
- `CREATE` on the `public` schema (for `CREATE TYPE public.eql_v2_encrypted`).
- `SUPERUSER` or extension owner privileges (for `CREATE EXTENSION pgcrypto`, if not already installed).

If permissions are insufficient, the CLI exits with a message listing what is missing.

---

## Programmatic API

```typescript
import {
  defineConfig,
  loadStashConfig,
  EQLInstaller,
  loadBundledEqlSql,
  downloadEqlSql,
} from 'stash'
```

### `defineConfig`

Type-safe identity function for `stash.config.ts`:

```typescript filename="stash.config.ts"
import { defineConfig } from 'stash'

export default defineConfig({
  databaseUrl: process.env.DATABASE_URL!,
  client: './src/encryption/index.ts',
})
```

### `loadStashConfig`

Finds and loads the nearest `stash.config.ts`, validates it with Zod, applies defaults, and returns the typed config:

```typescript
import { loadStashConfig } from 'stash'

const config = await loadStashConfig()
// config.databaseUrl — validated non-empty string
// config.client — defaults to './src/encryption/index.ts'
```

### `EQLInstaller`

Programmatic access to EQL installation:

```typescript
import { EQLInstaller } from 'stash'

const installer = new EQLInstaller({ databaseUrl: process.env.DATABASE_URL! })

const permissions = await installer.checkPermissions()
if (!permissions.ok) {
  console.error('Missing permissions:', permissions.missing)
  process.exit(1)
}

if (!(await installer.isInstalled())) {
  await installer.install({ supabase: true })
}
```

| Method | Returns | Description |
|--------|---------|-------------|
| `checkPermissions()` | `Promise<PermissionCheckResult>` | Check required database permissions |
| `isInstalled()` | `Promise<boolean>` | Check if the `eql_v2` schema exists |
| `getInstalledVersion()` | `Promise<string \| null>` | Get the installed EQL version |
| `install(options?)` | `Promise<void>` | Execute the EQL install SQL in a transaction |

Install options: `excludeOperatorFamily`, `supabase`, `latest` (all boolean).

### `loadBundledEqlSql`

Load the bundled EQL install SQL as a string:

```typescript
import { loadBundledEqlSql } from 'stash'

const sql = loadBundledEqlSql()
const sql = loadBundledEqlSql({ supabase: true })
const sql = loadBundledEqlSql({ excludeOperatorFamily: true })
```

### `downloadEqlSql`

Download the latest EQL install SQL from GitHub:

```typescript
import { downloadEqlSql } from 'stash'

const sql = await downloadEqlSql()             // standard
const sql = await downloadEqlSql(true)         // no operator family variant
```

---

## Relationship to `@cipherstash/stack`

`@cipherstash/stack` is the runtime SDK. It stays lean with no heavy dependencies like `pg` and ships in your production bundle. `stash` is a devDependency: it handles database tooling and schema lifecycle at development time. Think of it like Drizzle Kit — a companion tool that prepares the database while the runtime SDK handles queries.

---

## Links

- [Documentation](https://cipherstash.com/docs)
- [Discord](https://discord.gg/cipherstash)
- [Support](mailto:support@cipherstash.com)
