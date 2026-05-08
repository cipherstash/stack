# @cipherstash/wizard

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
