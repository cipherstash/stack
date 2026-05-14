# @cipherstash/cli

## 0.15.0

### Minor Changes

- dc02d0b: Add `@cipherstash/prisma-next` — searchable application-layer encryption for Postgres with Prisma Next. The framework's migration system installs the EQL bundle in the same `prisma-next migration apply` sweep that creates the application schema; no separate `stash db install` step.

  **`@cipherstash/prisma-next` (new package, initial release)**

  - **Six encrypted column types** — `EncryptedString`, `EncryptedDouble`, `EncryptedBigInt`, `EncryptedDate`, `EncryptedBoolean`, `EncryptedJson` — declared via PSL constructors (`cipherstash.Encrypted*()`) or TS factories (`encryptedString()`, etc.).
  - **17 query operators** — 13 predicate operators surfaced as column methods (`cipherstashEq`, `cipherstashIlike`, `cipherstashGt`, `cipherstashBetween`, `cipherstashInArray`, `cipherstashJsonbPathExists`, …) and 4 free-standing helpers (`cipherstashAsc`, `cipherstashDesc`, `cipherstashJsonbPathQueryFirst`, `cipherstashJsonbGet`).
  - **Per-codec search-mode flags** (`equality`, `freeTextSearch`, `orderAndRange`, `searchableJson`) drive the EQL search-config indices the codec lifecycle hook emits at migration time. Defaults to `true` across the board.
  - **One-call setup** via `cipherstashFromStack({ contractJson })` from `@cipherstash/prisma-next/stack` — derives the stack `encryptedTable` / `encryptedColumn` schemas from `contract.json` (single source of truth, no duplicate hand-written declarations), constructs the `@cipherstash/stack` `EncryptionClient`, builds the framework-native `CipherstashSdk` adapter, and returns ready-to-spread `{ extensions, middleware, encryptionClient }` for `postgres<Contract>({...})`.
  - **Layered API** — `deriveStackSchemas(contractJson)` and `createCipherstashSdk(client, schemas)` exposed as primitives for advanced users (custom keysets, multi-tenant routing, non-stack KMS).
  - **Bulk-encrypt middleware** (`bulkEncryptMiddleware(sdk)`) coalesces every plaintext placeholder across a query into one `bulkEncrypt` SDK round-trip per `(table, column)` group. `decryptAll(rows)` does the symmetric coalescing on the read side.
  - **Misconfig diagnostic** — if the user constructs the runtime descriptor but forgets to register `bulkEncryptMiddleware(sdk)` against the same SDK, the codec's encode throws a `RUNTIME.ENCODE_FAILED` envelope with a copy-pasteable wiring snippet at the first encrypted write.
  - **Subpath exports** — `./stack`, `./control`, `./runtime`, `./middleware`, `./pack`, `./column-types`; tree-shakable along the control / runtime / middleware seams.
  - **Contributes an EQL contract space** — installs the `eql_v2` schema, `eql_v2_encrypted` composite type, `ore_*` types, EQL functions / operators / casts via the cipherstash extension's baseline migration. Runs in the same control-plane sweep as the application schema.
  - **Full docs**: https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next.

  **`stash` (new feature)**

  - **`stash init --prisma-next`** — new init provider for Prisma Next projects. Reuses `authenticate` + `resolve-database` + `install-deps` (additionally installs `@cipherstash/prisma-next`), skips `install-eql` (the framework handles it via `prisma-next migration apply`) and `build-schema` (`cipherstashFromStack` derives schemas from the contract — no hand-written encryption client file). Detected automatically when a `prisma-next.config.*` or `@cipherstash/prisma-next` dependency is present in the project.
  - **`detectPrismaNext(cwd)`** — new export from `commands/db/detect.ts` mirroring the existing `detectDrizzle` / `detectSupabase` helpers.

## 0.14.1

### Patch Changes

- 3a38f1a: `stash status` now detects when a plan has been drafted but the rollout hasn't started yet. Previously, with no `cs_migrations` activity, status reported "your encryption rollout has not begun" and pointed the user at `stash plan` — even when `.cipherstash/plan.md` already existed. It now recognises that case and points the user at `stash impl` to execute the plan instead.

## 0.14.0

### Minor Changes

- 1a97d40: Add plan-mode support to the wizard so `stash plan` can hand off to the CipherStash Agent. The wizard now accepts `--mode <plan|implement>` (default `implement` for back-compat). In plan mode it skips the column-selection TUI, forwards `mode: 'plan'` to the gateway (which returns a planning prompt whose deliverable is `.cipherstash/plan.md`), and skips the post-agent install/push/migrate and call-site-scan steps. Implement mode is unchanged.

  `stash plan`'s handoff picker now offers all four targets (Claude Code, Codex, AGENTS.md, CipherStash Agent) — the wizard is no longer gated out of plan mode. `stash impl`'s picker is unchanged.

### Patch Changes

- 440879b: feat(cli): pass `--allow-dangerously-skip-permissions` when `stash init` launches Claude Code, so the user can opt in to skip-permissions mode mid-session without relaunching. Codex and Wizard handoffs are unchanged.

## 0.13.0

### Minor Changes

- e16b282: Split agent handoff out of `stash init` into a new `stash impl` command. `init` now owns scaffolding only (auth, database, encryption client, EQL extension) and exits at a clean checkpoint pointing at `stash impl`. `stash impl` derives plan-vs-implement mode from disk state — if `.cipherstash/plan.md` is missing it asks the agent to draft a plan; if it exists, the agent executes the plan as the source of truth. `--continue-without-plan` skips the planning checkpoint after an interactive confirmation. The earlier in-init `Plan first / Go straight to implementation` picker is removed in favour of the new command boundary.
- db163e1: `stash impl` now renders a plan summary panel and asks the user to confirm before launching the implementation agent. When a plan exists, the CLI parses a machine-readable `<!-- cipherstash:plan-summary {...} -->` block (the planning agent is instructed to emit one at the top of `.cipherstash/plan.md`) and prints column counts, per-column paths, and whether the work is single-deploy or staged across 4 deploys. Default-yes on the confirm so the path of least resistance is to proceed; saying No exits cleanly. Older plans without the summary block fall back to a soft "open in your editor" panel — never an error. Non-TTY runs (CI, pipes) skip the confirm and proceed.
- 59b138b: Extract planning into its own `stash plan` command. Three commands now own the setup lifecycle:

  - `stash init` — scaffold (auth, db, deps, EQL). Ends with a chain prompt to `stash plan`.
  - `stash plan` — draft a reviewable plan at `.cipherstash/plan.md`. Ends with a chain prompt to `stash impl`.
  - `stash impl` — execute. With a plan, shows the summary panel and confirms. Without one, presents a `Draft a plan first / Continue without a plan` picker (the second option goes through a security confirm). `--continue-without-plan` skips the picker.

  `stash status` reflects the new flow — its "Plan written" stage and `Next:` line route to `stash plan` when init is done but no plan exists. Non-TTY runs of `stash impl` without a plan now error out with a clear next-action rather than guessing intent.

- db163e1: Add `stash status` — a top-level lifecycle map for the project. Reads `.cipherstash/context.json`, `.cipherstash/plan.md`, and `.cipherstash/setup-prompt.md` from disk to render a panel showing whether init is done, whether a plan has been written, and whether an agent has been engaged. Points at `stash db status` for EQL install info and `stash encrypt status` for per-column migration phase. Runs in milliseconds — no auth, no database connection required. The existing `stash db status` is unchanged.

## 0.12.1

### Patch Changes

- 439c63e: Fix backfill CLI wrapper to resolve schema column metadata correctly and surface configuration errors with author-controlled messages while keeping generic diagnostics for unexpected failures.

## 0.12.0

### Minor Changes

- f315334: `stash init` can now hand off the rest of setup to whichever coding agent the user is set up with — and it leaves them with a project-specific action plan and the right reference material, not just generic rules.

  The new pipeline:

  1. **Authenticate** (unchanged).
  2. **Resolve `DATABASE_URL`** — uses the same resolver as `stash db install` (flag → env → `supabase status` → interactive prompt). Hard-fails with an actionable message if nothing resolves.
  3. **Build the encryption client.** When the database has tables, `init` introspects them and generates a real client from the user's selection. When the database is empty, it falls back to a placeholder so fresh projects still work — and the action prompt notes the placeholder so the agent reshapes it later.
  4. **Install dependencies** — `@cipherstash/stack` (runtime) + `stash` (CLI dev dep).
  5. **Install EQL into the database** — y/N confirm, then runs `stash db install` programmatically against the URL we already resolved. No second prompt for credentials.
  6. **Pick a handoff** from the four-option menu. Each handoff installs the right artifacts for the chosen tool:
     - **Hand off to Claude Code** — copies the per-integration set of authored skills (`stash-encryption` + `stash-<integration>` + `stash-cli`) into `.claude/skills/`, writes `.cipherstash/context.json` and `.cipherstash/setup-prompt.md`, spawns `claude`. Default when `claude` is on PATH.
     - **Hand off to Codex** — writes a sentinel-managed `AGENTS.md` (durable doctrine) + copies the same skills into `.codex/skills/` (procedural workflows), writes `context.json` + `setup-prompt.md`, spawns `codex`. Default when `codex` is on PATH and `claude` is not. Follows OpenAI's Codex guidance: AGENTS.md for repo doctrine, skills for repeatable workflows.
     - **Use the CipherStash Agent** — writes `context.json` and runs `stash wizard`. Fallback for users without a local CLI agent. The wizard installs its own skills.
     - **Write AGENTS.md** — for editor agents (Cursor, Windsurf, Cline) that don't auto-load skill directories. Writes a single `AGENTS.md` with the doctrine _plus_ the relevant skill content inlined under a sentinel block, so the agent has the API details without needing to follow file references. Plus `context.json` + `setup-prompt.md`. No spawn.

  Detection is non-blocking: if the chosen CLI agent (`claude` or `codex`) isn't installed, init still writes the artifacts and prints install + manual-launch instructions. Progress is never wasted.

  `.cipherstash/setup-prompt.md` is the headline artifact. It's the project-specific action plan — _"init has done X and Y; you need to do Z next, with these exact commands and paths"_ — generated from the current init state. The launch prompt for Claude / Codex points the agent at this file first; the installed skills provide the reusable rulebook the prompt references. For IDE users, it's ready to paste into the first chat.

  Per-integration skill subset:

  ```text
  drizzle    → stash-encryption + stash-drizzle  + stash-cli
  supabase   → stash-encryption + stash-supabase + stash-cli
  postgresql → stash-encryption + stash-cli
  ```

  The skills themselves are the authored ones at the repo root (`/skills/`); they ship inside the CLI tarball via `tsup` so init can copy them locally without a network round-trip. The AGENTS.md doctrine fragment ships the same way.

  Re-running `init` is safe — `AGENTS.md` uses sentinel-marker upsert (`<!-- cipherstash:rulebook start/end -->`), so the managed region is replaced in place and any user edits outside it are preserved. Skill directories are overwritten so the user always gets the latest content. `setup-prompt.md` is regenerated wholesale each run since it's meant to reflect the current state.

  `.cipherstash/context.json` is the universal "what shape is this project" payload — integration, encryption client path, schema, env key names (never values), package manager, install command, CLI version, names of installed skills, generation timestamp.

- ce70b4d: Add `stash wizard` as a thin wrapper subcommand around `@cipherstash/wizard`.

  The wizard ships as a separate npm package so the heavy agent SDK stays out of the `stash` CLI bundle. Until now, users had to remember a second tool name (`npx @cipherstash/wizard`); the wrapper exposes the same capability under the existing `stash` surface so the user only has to think about one CLI.

  `stash wizard` detects the project's package manager and spawns the wizard via the matching one-shot runner — `npx`, `pnpm dlx`, `yarn dlx`, or `bunx` — with `stdio: 'inherit'` so the wizard owns the terminal cleanly. Any flags after `wizard` are forwarded verbatim, so `stash wizard --debug` works.

  On a cold cache (the wizard package isn't installed in the project) the runner downloads it before launching — a few seconds. The wrapper prints an explicit "first run downloads ~5s" line in that case so the CLI doesn't appear hung. On a warm cache, just a "Launching the CipherStash wizard…" line, then the wizard takes over.

  Existing copy that pointed at `npx @cipherstash/wizard` (init's next-steps for base / Drizzle / Supabase, `db install`'s post-install note) now uses `stash wizard`.

- add4357: Add `stash encrypt` command group and `@cipherstash/migrate` library for plaintext → encrypted column migrations.

  New CLI commands:

  - `stash encrypt status` — per-column migration status (phase, backfill progress, drift between intent and state, EQL registration).
  - `stash encrypt plan` — diff `.cipherstash/migrations.json` (intent) vs observed state.
  - `stash encrypt backfill --table <t> --column <c>` — resumable, idempotent, chunked encryption of plaintext into `<col>_encrypted`. Uses the user's encryption client (Protect/Stack). SIGINT-safe; re-run to resume. The first run on a column prompts to confirm dual-writes are deployed (or accept `--confirm-dual-writes-deployed` for non-interactive contexts), records the `dual_writing` transition in `cs_migrations`, then runs the chunked encryption loop. `--force` re-encrypts every plaintext row regardless of current state — recovery path for drift caused by an earlier backfill running before dual-writes were actually live.
  - `stash encrypt cutover --table <t> --column <c>` — runs `eql_v2.rename_encrypted_columns()` inside a transaction; optionally forces Proxy config refresh via `CIPHERSTASH_PROXY_URL`. After cutover, apps reading `<col>` transparently receive the encrypted column.
  - `stash encrypt drop --table <t> --column <c>` — generates a migration file that drops the old plaintext column.

  `stash db install` now also installs a `cipherstash.cs_migrations` table used to track per-column migration runtime state (current phase, backfill cursor, rows processed). The table is append-only (event-log shape) and kept separate from `eql_v2_configuration` which remains the authoritative EQL intent store used by Proxy.

  The new `@cipherstash/migrate` package exposes the same primitives as a library for users who want to embed backfill in their own workers or cron jobs — all commands are thin wrappers around its exports (`runBackfill`, `appendEvent`, `latestByColumn`, `progress`, `renameEncryptedColumns`, `reloadConfig`, `readManifest`, `writeManifest`).

### Patch Changes

- 39af183: Make `--help` banners and the post-install "Next steps" panel show commands using the package manager the user actually invoked the CLI with, instead of always emitting `npx`.

  A user who runs `bunx @cipherstash/cli --help` now sees:

  ```
  Usage: bunx @cipherstash/cli <command> [options]
  …
  Examples:
    bunx @cipherstash/cli init
    bunx @cipherstash/cli auth login
    bunx @cipherstash/cli db install
  ```

  instead of `npx @cipherstash/cli …` regardless of how they invoked it. Same for `pnpm dlx`, `yarn dlx`, and the default `npx` path.

  Concretely:

  - `--help` (top-level) — usage line and all six examples in `bin/stash.ts`.
  - `--help` (auth) — usage line and the two `auth login` examples in `commands/auth/index.ts`.
  - `db install`'s "Next steps" note — the `wizard` invocation now matches the user's runner.
  - The `@cipherstash/stack is required for this command` hint shown by `requireStack` (when `db push`/`validate`/`schema build` are run before the runtime SDK is installed) now suggests the package manager's install command and the user's runner for the follow-up `init` invocation.

  No public-API change. Detection sources unchanged from #379: `npm_config_user_agent` first, then lockfile, then `npx` fallback.

- a8dbb65: Render every user-facing CLI string and execute every shell-out under the detected package manager (`npx` / `bunx` / `pnpm dlx` / `yarn dlx`), completing the work started in #379. Affected surfaces: `@cipherstash/cli` top-level + `auth` + `env` help, `db install` Drizzle migration steps, `db migrate` not-implemented warning, the Supabase migration SQL header, the Supabase status fallback exec, the `@cipherstash/protect` `stash` Stricli help (set/get/list/delete), the `@cipherstash/wizard` usage line and agent command allowlist, and the `@cipherstash/drizzle` `generate-eql-migration` help + drizzle-kit invocation. A new `pnpm run lint:runners` lint runs in CI and fails on any reintroduction of a hardcoded runner literal.
- Updated dependencies [add4357]
  - @cipherstash/migrate@0.2.0

## 0.11.0

### Minor Changes

- de9c02c: Rename the CLI package from `@cipherstash/cli` to `stash`. The published code, commands, and flags are unchanged — this is a pure rename so the day-to-day invocation drops from `npx @cipherstash/cli ...` to `npx stash ...`.

  **Migration**

  1. Update your `package.json` devDependencies:

     ```diff
     -  "@cipherstash/cli": "^0.10.0"
     +  "stash": "^0.10.1"
     ```

  2. Update the `defineConfig` import in `stash.config.ts`:

     ```diff
     - import { defineConfig } from '@cipherstash/cli'
     + import { defineConfig } from 'stash'
     ```

  3. Update any `npx @cipherstash/cli ...` / `bunx @cipherstash/cli ...` / `pnpm dlx @cipherstash/cli ...` / `yarn dlx @cipherstash/cli ...` invocations in scripts, CI, READMEs, and team docs to use `stash` instead. Programmatic exports (`defineConfig`, `loadStashConfig`, `EQLInstaller`, `loadBundledEqlSql`, `downloadEqlSql`, `PermissionCheckResult`) are re-exported from `stash` with the same shapes.

  **Wizard impact (`@cipherstash/wizard`)**

  The wizard's post-agent step and its prerequisite / agent-error hints now reference `stash` (e.g. `Run: bunx stash auth login`, `Running bunx stash db install...`) rather than `@cipherstash/cli`. The wizard package name and `stash-wizard` binary are unchanged — only the strings the wizard prints and the commands it shells out to are affected.

- 8ee11fd: Layered `DATABASE_URL` resolution for DB / schema commands.

  Previously, any DB-touching command (`db install`, `db push`, `db upgrade`, `db status`, `db validate`, `db test-connection`, `schema build`) failed with the cryptic Zod error:

  ```
  Error: Invalid stash.config.ts
    - databaseUrl: Invalid input: expected nonoptional, received undefined
  ```

  if `DATABASE_URL` wasn't already in the environment. The CLI auto-loaded `.env.local` / `.env.development.local` / `.env.development` / `.env`, but had no story for `--database-url` flags, local Supabase, or pasted-once values.

  The scaffolded `stash.config.ts` now calls a resolver directly:

  ```ts
  import { defineConfig, resolveDatabaseUrl } from "stash";

  export default defineConfig({
    databaseUrl: await resolveDatabaseUrl(),
    client: "./src/encryption/index.ts",
  });
  ```

  `resolveDatabaseUrl()` walks sources in order; first hit wins:

  1. `--database-url <url>` flag — new, accepted on all seven DB / schema commands. Used for this run only; never written to disk.
  2. `process.env.DATABASE_URL` — covers shell exports, mise, direnv, dotenv-cli, the existing dotenv loads.
  3. `supabase status --output env` → `DB_URL` — auto-engaged when `--supabase` is set or a `supabase/config.toml` is detected. Useful for local Supabase users who haven't exported the URL yet.
  4. Interactive prompt — opens with a tip listing the alternatives (flag, env, the user's actual dotenv file). Skipped under `CI=true` or non-TTY stdin.
  5. Hard fail with a source-naming error message.

  The connection string is **never persisted to disk** — `stash.config.ts` only contains the `await resolveDatabaseUrl()` call, never a literal URL. The resolver also doesn't mutate `process.env`; CLI flag context is threaded into the config evaluation via `AsyncLocalStorage` so concurrent loads stay isolated. Source labels are logged on non-env paths (`Using DATABASE_URL from --database-url flag` / `from supabase status` / `from prompt`) but the URL itself is never echoed.

  `db test-connection`'s connection-failure hint is now source-aware: it points users at `--database-url`, the env var, and the actual dotenv file in their project (`.env.local` if present, `.env` otherwise) — not the misleading `stash.config.ts` it used to suggest.

## 0.10.1

### Patch Changes

- f34fe9d: Show and execute commands using the detected package manager's runner (`npx` / `bunx` / `pnpm dlx` / `yarn dlx`) instead of always emitting `npx`. A user who runs `bunx @cipherstash/cli init` now sees a "Next Steps" panel that suggests `bunx @cipherstash/cli db install` and `bunx @cipherstash/wizard`, and the wizard's post-agent step both displays and shells out to `bunx @cipherstash/cli db push` (was: `Failed: npx @cipherstash/cli db push`). Wizard prerequisite messages and AI-agent error hints (e.g. on a 401, `Run: bunx @cipherstash/cli auth login`) follow the same rule. Detection sources are unchanged: `npm_config_user_agent` first, then lockfile, then `npx` fallback.

## 0.10.0

### Minor Changes

- 79f4a0b: Fix `loadStashConfig` to correctly unwrap the default export from `stash.config.ts`. Previously, any database-touching command (`db install`, `db push`, `db validate`, `db status`, `db test-connection`, `schema build`) would fail validation against a perfectly valid config with:

  ```
  Error: Invalid stash.config.ts

    - databaseUrl: Invalid input: expected nonoptional, received undefined
  ```

  The issue: in jiti 2.x, the `interopDefault: true` option passed to `createJiti(...)` only applies to the deprecated synchronous `jiti(id)` callable form. The async `jiti.import()` ignores it and always returns the full module namespace. With `export default defineConfig({...})` that meant Zod was validating `{ default: { databaseUrl, client } }` and reporting `databaseUrl` as undefined even when the user's config plainly set it.

  Switched to jiti's per-call `{ default: true }` option, which does work on `jiti.import()`. Added an integration test that exercises real jiti against a real temp `stash.config.ts` so future regressions get caught — the previous mocked test was passing the bug straight through.

  This bug surfaced after `db install` started loading `stash.config.ts` (during the onboarding overhaul), but affected every other command that reads the config.

## 0.9.0

### Minor Changes

- 5d3eb13: Reduce friction in `stash init`.

  - **No more "How will you connect to your database?" prompt.** Init now auto-detects Drizzle (from `drizzle.config.*` or `drizzle-orm`/`drizzle-kit` in `package.json`) and Supabase (from the host in `DATABASE_URL`), and silently picks the matching encryption client template. Falls back to a generic Postgres template otherwise.
  - **No more "Where should we create your encryption client?" prompt.** Init writes to `./src/encryption/index.ts` by default. The "file already exists, what would you like to do?" prompt still appears so existing client files aren't silently overwritten.
  - **Single combined dependency-install prompt.** Previously init asked twice (once for `@cipherstash/stack`, once for `@cipherstash/cli`). It now asks once, listing both, and runs the installs in sequence. When both packages are already in `node_modules`, no prompt appears at all.
  - **Already-authenticated users skip the "Continue with workspace X?" prompt.** Init logs `Using workspace X` and proceeds. Run `stash auth login` directly to switch workspaces.

  `stash db install` now also calls into the same encryption-client scaffolder as a safety net — users who run `db install` without `init` first still get a working client file generated at the path their `stash.config.ts` points to.

- 5d3eb13: **Breaking:** the `stash wizard` command has been removed. The AI-guided encryption setup is now its own package — run it via `npx @cipherstash/wizard` (or `pnpm dlx`, `bunx`, `yarn dlx`).

  The wizard was pulling `@anthropic-ai/claude-agent-sdk` (47MB unpacked) into every `npx @cipherstash/cli` invocation, even for fast commands like `init`, `auth`, and `db install`. Splitting it out keeps cli's dependency tree small and lets each package manager handle the wizard's install natively — no more shelling out to `npm` from inside the cli, no Yarn PnP / Bun-only failure modes.

  The next-steps output from `init` and `db install` still recommends `npx @cipherstash/wizard` as the automated path. The `schema build` command no longer offers a wizard/builder selection prompt — it goes straight to the schema builder.

## 0.8.0

### Minor Changes

- 34432e9: Added --migration and --direct options to Supabase EQL install steps

## 0.7.1

### Patch Changes

- a0760f6: Detect the package manager from `npm_config_user_agent` when running `stash init`. Running `bunx @cipherstash/cli init`, `pnpm dlx @cipherstash/cli init`, or `yarn dlx @cipherstash/cli init` now uses the invoking tool for dependency installation (`bun add`, `pnpm add`, `yarn add`) instead of falling back to `npm install`. Lockfile detection is still preferred when present, so projects with an existing convention are unaffected. Fixes `EUNSUPPORTEDPROTOCOL` failures on `workspace:*` deps in Bun-managed projects.

## 0.7.0

### Minor Changes

- 7f5a05a: Fixed issue where the wizard was checking CipherStash auth based on path and now leverages the auth npm package.

## 0.6.1

### Patch Changes

- 8513705: Fix mangled `eql_v2_encrypted` type in drizzle-kit migrations.

  - `@cipherstash/stack/drizzle`'s `encryptedType` now returns the bare `eql_v2_encrypted` identifier from its Drizzle `customType.dataType()` callback. Returning the schema-qualified `"public"."eql_v2_encrypted"` (0.15.0) triggered a drizzle-kit quirk that wraps the return value in double-quotes and prepends `"{typeSchema}".` in ALTER COLUMN output — producing `"undefined".""public"."eql_v2_encrypted""`, which Postgres cannot parse.
  - `stash db install` / `stash wizard`'s migration rewriter now matches all four forms drizzle-kit may emit (`eql_v2_encrypted`, `"public"."eql_v2_encrypted"`, `"undefined"."eql_v2_encrypted"`, `"undefined".""public"."eql_v2_encrypted""`) and rewrites each into the safe `ADD COLUMN … DROP COLUMN … RENAME COLUMN` sequence.

  Users on 0.15.0 who hit this in generated migrations should upgrade and re-run `npx drizzle-kit generate` + `stash db install` (or re-run the wizard).

## 0.6.0

### Minor Changes

- 9944a25: Update cipherstash auth to 0.36.0

## 0.5.0

### Minor Changes

- 1929c8f: Mark secrets as a coming soon feature and remove existing SDK integration.

## 0.4.0

### Minor Changes

- 1e0d4c1: Support CipherStash rebrand with new docs links.

## 0.3.0

### Minor Changes

- 0d21e9b: Fix invalid client error.

## 0.2.0

### Minor Changes

- 4d0dfc5: Fixed peer dependency by lazy loading commands requiring @cipherstash/stack.

## 0.1.0

### Minor Changes

- 068f820: Release the consolidated CipherStash CLI npm package.

> Renamed from `@cipherstash/stack-forge`. The standalone `@cipherstash/wizard` package was absorbed into this CLI as `npx @cipherstash/cli wizard`. The single binary is now invoked via `npx @cipherstash/cli` (replaces `stash-forge` and `cipherstash-wizard`).

## 0.4.0

### Minor Changes

- 5245cd7: Improved CLI setup and initialization commands.

## 0.3.0

### Minor Changes

- 6f27ec3: Improve CLI user experience for developer onboarding.

## 0.2.0

### Minor Changes

- 3414761: Add additional CLI tools for validate, status, init. Fixed push command to work with CipherStash Proxy.

## 0.1.0

### Minor Changes

- 60ce44a: Initial release of the `stash-forge` CLI utility.
