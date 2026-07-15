# @cipherstash/wizard

## 0.5.0-rc.1

### Patch Changes

- d8e0c1d: Align the wizard's analytics with the `stash` CLI's telemetry privacy contract.
  The wizard now honors `DO_NOT_TRACK`, `STASH_TELEMETRY_DISABLED`, and CI
  auto-detection; uses a random per-session identifier instead of one derived
  from username@hostname; disables IP→geo resolution; and reports error events as
  fixed labels / error class names instead of raw messages (which could embed
  schema names or connection details). Analytics remain dormant unless a PostHog
  key is configured at build time.

## 0.5.0-rc.0

### Minor Changes

- 0b9b192: Rename `stash db install` to `stash eql install`. The command scaffolds
  `stash.config.ts` and installs the EQL extensions, so it now lives under a
  dedicated `eql` command group. `stash db install` keeps working as a
  deprecated alias that prints a warning pointing at the new name. All help
  text, hints, generated migration headers, and wizard steps now reference
  `stash eql install`.

### Patch Changes

- 9c673bb: Stop the agent guard from blocking `.env.example`.

  `SENSITIVE_FILE_PATTERNS` matched `/\.env($|\.)/`, which tests true against
  `.env.example`. Because the guard covers `Edit` and `Write` as well as `Read`,
  the wizard's agent was blocked from creating or editing the very file the
  CipherStash doctrine tells it to write ("New env keys go in `.env.example` with
  placeholders"). Committed env templates carry placeholder key names, not values.

  `.env.example`, `.env.sample` and `.env.template` are now readable and writable.
  Everything else is unchanged: `.env`, `.env.local`, `.env.production`, and
  value-bearing files that merely start with a template name
  (`.env.example.local`, `.env.example.bak`) stay blocked, as do `auth.json`,
  `secretkey.json` and credential files. Bash access to any env file — including
  the templates — remains blocked; `Read`/`Write` is the sanctioned path.

## 0.4.0

### Minor Changes

- 64fdeb2: Rename `stash db install`, `stash db upgrade`, and `stash db status` to
  `stash eql install`, `stash eql upgrade`, and `stash eql status`. These
  commands manage the EQL extension itself, so they now live under a dedicated
  `eql` command group. The old `db` spellings keep working as deprecated
  aliases that print a warning pointing at the new names. All help text,
  hints, generated migration headers, and wizard steps now reference the
  `eql` commands.

### Patch Changes

- a5f5422: Bump `@cipherstash/auth` (and its per-platform native bindings) from `0.40.0` to `0.41.0`, and migrate to its new `Result`-returning API.

  **What changed in `@cipherstash/auth` `0.41`.** Every fallible auth operation now returns a `@byteslice/result` `Result<T, AuthFailure>` (`{ data }` on success, `{ failure }` on error) instead of throwing. This covers strategy construction (`AccessKeyStrategy.create`, `OidcFederationStrategy.create`, `AutoStrategy.detect`, `DeviceSessionStrategy.fromProfile`), `getToken()`, and the device-code flow (`beginDeviceCodeFlow`, `pollForToken`, `openInBrowser`, `bindClientDevice`). Consumers now write `if (result.failure) …` and read `result.data` rather than `try/catch`. The `AuthError` type was renamed to **`AuthFailure`** — a discriminated union keyed by `type` (`"NOT_AUTHENTICATED"`, `"WORKSPACE_MISMATCH"`, …), replacing the old `error.code` string.

  **`@cipherstash/stack` (breaking type surface).**

  - **`AuthError` is renamed to `AuthFailure`** in the public re-exports from `@cipherstash/stack`. `AuthErrorCode` and `TokenResult` are unchanged. Anyone importing `AuthError` from `@cipherstash/stack` must switch to `AuthFailure`.
  - The WASM-inline access-key path (`resolveStrategy`, used by `@cipherstash/stack/wasm-inline`'s `Encryption()`) now unwraps the `Result` from `AccessKeyStrategy.create`. A construction failure (e.g. an invalid CRN or access key) throws a descriptive `[encryption]` error naming the `AuthFailure.type` instead of surfacing the raw auth error.
  - Bump `@cipherstash/protect-ffi` from `0.27.0` to `0.28.0`. auth `0.41`'s `getToken()` returns the token inside a `Result` envelope; protect-ffi `0.28` unwraps it (`.data.token`) inside its WASM `newClient`, whereas `0.27` read `.token` off the envelope and got `undefined` — which failed the WASM encrypt/decrypt round-trip with `token field is not a string`. `0.28` is the floor for the WASM path under auth `0.41`.

  **`stash` (CLI) and `@cipherstash/wizard`.** Internal auth call sites (`stash auth login`, device binding, `init` auth check, and the wizard's token acquisition / prerequisite check) were updated to unwrap `Result` and branch on `failure.type`. Behaviour is preserved — auth failures still surface the same way to end users; no CLI/wizard API changed.

- 17f4745: Add `@anthropic-ai/sdk` `^0.106.0` as a direct dependency so the
  auto-installed peer of `@anthropic-ai/claude-agent-sdk` resolves to a release
  patched against GHSA-p7fg-763f-g4gf, instead of the vulnerable 0.81.0 the
  peer range alone would select. The wizard never imports the SDK directly —
  this is a peer-resolution pin only; no behaviour change.

## 0.3.0

### Minor Changes

- bb9764d: `stash db push` is no longer included by default in `stash plan` / `stash impl` agent prompts or the wizard's post-agent step. SDK users (Drizzle, Supabase, plain PostgreSQL) no longer see `stash db push` baked into their rollout/cutover walkthroughs — the encryption config lives in app code, so the database doesn't need a copy.

  Pass `--proxy` to `stash init` (or answer the new interactive prompt) if you query encrypted data via [CipherStash Proxy](https://github.com/cipherstash/proxy). The choice is persisted to `.cipherstash/context.json` as `usesProxy` and is honoured by `stash plan`, `stash impl`, and the wizard's post-agent step. Existing `.cipherstash/context.json` files without the field default to SDK-only.

  Known gap: `stash encrypt cutover` currently requires a pending EQL config registered via `stash db push`, so SDK-only users running the migrate-existing-column flow will hit a "No pending EQL configuration" error from cutover. Workaround: run `stash db push` once before `stash encrypt cutover`. Decoupling cutover from EQL config for SDK-only users is tracked as a follow-up to [#447](https://github.com/cipherstash/stack/issues/447).

## 0.2.0

### Minor Changes

- 1a97d40: Add plan-mode support to the wizard so `stash plan` can hand off to the CipherStash Agent. The wizard now accepts `--mode <plan|implement>` (default `implement` for back-compat). In plan mode it skips the column-selection TUI, forwards `mode: 'plan'` to the gateway (which returns a planning prompt whose deliverable is `.cipherstash/plan.md`), and skips the post-agent install/push/migrate and call-site-scan steps. Implement mode is unchanged.

  `stash plan`'s handoff picker now offers all four targets (Claude Code, Codex, AGENTS.md, CipherStash Agent) — the wizard is no longer gated out of plan mode. `stash impl`'s picker is unchanged.

## 0.1.3

### Patch Changes

- a8dbb65: Render every user-facing CLI string and execute every shell-out under the detected package manager (`npx` / `bunx` / `pnpm dlx` / `yarn dlx`), completing the work started in #379. Affected surfaces: `@cipherstash/cli` top-level + `auth` + `env` help, `db install` Drizzle migration steps, `db migrate` not-implemented warning, the Supabase migration SQL header, the Supabase status fallback exec, the `@cipherstash/protect` `stash` Stricli help (set/get/list/delete), the `@cipherstash/wizard` usage line and agent command allowlist, and the `@cipherstash/drizzle` `generate-eql-migration` help + drizzle-kit invocation. A new `pnpm run lint:runners` lint runs in CI and fails on any reintroduction of a hardcoded runner literal.

## 0.1.2

### Patch Changes

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

## 0.1.1

### Patch Changes

- f34fe9d: Show and execute commands using the detected package manager's runner (`npx` / `bunx` / `pnpm dlx` / `yarn dlx`) instead of always emitting `npx`. A user who runs `bunx @cipherstash/cli init` now sees a "Next Steps" panel that suggests `bunx @cipherstash/cli db install` and `bunx @cipherstash/wizard`, and the wizard's post-agent step both displays and shells out to `bunx @cipherstash/cli db push` (was: `Failed: npx @cipherstash/cli db push`). Wizard prerequisite messages and AI-agent error hints (e.g. on a 401, `Run: bunx @cipherstash/cli auth login`) follow the same rule. Detection sources are unchanged: `npm_config_user_agent` first, then lockfile, then `npx` fallback.

## 0.1.0

### Minor Changes

- 5d3eb13: Initial release of `@cipherstash/wizard` — AI-powered encryption setup for CipherStash, extracted from `@cipherstash/cli`.

  Run it once per project, after `stash init`:

  ```bash
  npx @cipherstash/wizard
  pnpm dlx @cipherstash/wizard
  yarn dlx @cipherstash/wizard
  bunx @cipherstash/wizard
  ```

  The wizard reads your codebase, asks which columns to encrypt, hands a surgical prompt to the Claude Agent SDK against the CipherStash-hosted LLM gateway, and runs deterministic post-agent steps (package install, `db install`, `db push`, framework migrations). Same behavior as the previous `stash wizard` command — just shipped as its own package so it doesn't bloat the cli's dependency tree.
