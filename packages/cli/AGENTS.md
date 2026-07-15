# `stash` — agent notes

## Two test suites

This package has **two** Vitest configs. Run the right one for the change.

| Command | Config | Scope | Needs build? |
| --- | --- | --- | --- |
| `pnpm --filter stash test` | `vitest.config.ts` | Unit tests under `src/__tests__/**` and `src/**/__tests__/**` | No |
| `pnpm --filter stash test:e2e` | `vitest.integration.config.ts` | E2E tests under `tests/e2e/**.e2e.test.ts` driving the built `dist/bin/stash.js` through a real pty (`node-pty`) | **Yes** — run `pnpm --filter stash build` first, or use the turbo `test:e2e` task which depends on `build`. |

The unit config explicitly excludes `tests/e2e/**` so the default `pnpm test`
stays fast and self-contained.

## When to add or update an E2E test

Update `tests/e2e/**` whenever you:

- Add or rename a top-level command, subcommand, or flag (smoke tests assert
  on help text, command names, and unknown-command behavior).
- Change the user-facing string for an exit message that an existing E2E
  asserts on (e.g. cancellation text, "Unknown auth command", the
  `db migrate` stub warning). Strings that tests assert on live in
  `src/messages.ts` — update the constant there and both prod and tests
  pick it up. *Don't* hard-code the new wording in a test.
- Touch `src/bin/stash.ts` argv parsing, exit codes, or top-level error
  handling.
- Add a new clack prompt that changes the *first* prompt rendered for a
  command currently covered by E2E (the cancel test waits for a specific
  prompt label).

You do **not** need to add an E2E test for every new flag or branch — keep
E2E coverage to the highest-value flows. Unit tests still own the bulk of
behaviour coverage.

## How the harness works

`tests/helpers/pty.ts` exports `render(args, opts?)` which spawns
`dist/bin/stash.js` inside a real pseudo-terminal and returns:

- `output` — cumulative ANSI-stripped stdout.
- `raw` — same, with ANSI escapes preserved (handy when debugging).
- `waitFor(text|regex, timeoutMs?)` — polls until the match appears.
- `key(name)` — sends keystrokes (`Enter`, `Up`, `Down`, `CtrlC`, etc.).
- `write(string)` — raw stdin write.
- `exit` — promise resolving to `{ exitCode, signal? }`.
- `kill(signal?)` — terminate the pty.

A real pty is required because `@clack/prompts` switches stdin to raw mode
and renders differently when stdout isn't a TTY; piped-stdin mocks don't
exercise the same code paths.

## Gotchas

- **Build before E2E.** `dist/bin/stash.js` is the artifact under test. The
  turbo `test:e2e` task already depends on `build`, but if you invoke the
  script directly you must build first.
- **macOS spawn-helper exec bit.** pnpm strips the executable bit when
  unpacking node-pty's prebuilds. The helper auto-fixes this at module load
  via `ensureSpawnHelperExecutable`. If you see `posix_spawnp failed` after
  reinstalling `node_modules`, the chmod logic should handle it on next
  test run; if not, manually `chmod +x` the helper under
  `node_modules/.pnpm/node-pty@*/node_modules/node-pty/prebuilds/<plat>/spawn-helper`.
- **Don't broaden the cancel test target.** `auth login` was chosen because
  the region picker runs before any network I/O. Don't move the cancel
  assertion to a command that hits the auth server or DB before the first
  prompt — flaky.
- **Region resolution is CI-aware.** `resolveRegion` (in
  `src/commands/auth/region.ts`) mirrors the `DATABASE_URL` resolver: it only
  renders the interactive picker when `stdin.isTTY` **and** `CI` is unset, and
  otherwise honours `--region` / `STASH_REGION` or exits with an actionable
  error (JSON in `--json` mode). Because the pty harness defaults `CI=true`,
  the interactive-cancel test passes `env: { CI: '' }` to force the picker to
  render. The pure helpers (`normalizeRegion`, `regionSlugs`) and the resolver
  policy have unit coverage in `src/commands/auth/__tests__/region.test.ts` —
  the module imports no native code, so it runs under the fast unit config.
- **Use `src/messages.ts` for assertion-stable strings.** The module is a
  single typed `as const` object grouping copy by area (`cli`, `auth`,
  `db`). Prod call sites import the same constants the tests do, so a copy
  tweak only needs to land in one place. Add to `messages.ts` only when a
  test actually asserts on the string — premature extraction is worse
  than copy-paste here. For literals tests don't touch (e.g. command
  names like `init`, `eql install`), keep them inline.
- **Telemetry.** The CLI has anonymous, opt-out usage analytics in
  `src/telemetry/` (posthog-node, loaded lazily only when an event is
  actually sent). It ships dormant — a real project key is embedded only by
  the release build (`STASH_POSTHOG_KEY` repo variable → tsup define) — and
  is force-disabled in every pty e2e child via `STASH_TELEMETRY_DISABLED=1`
  in `tests/helpers/pty.ts`. Two contracts to preserve when touching it:
  (1) event VALUES are closed vocabularies — `classifyCommand` /
  `classifyErrorType` in `src/telemetry/classify-command.ts` must wrap
  anything argv- or error-derived before emit; (2) never intercept
  `process.exit` with a thrown signal — @clack/core exits from keypress
  handlers and several commands have broad catches, so interception breaks
  cancel flows (tried and reverted; see `src/cli/exit.ts`). Commands that
  terminate via deep `process.exit()` are simply not tracked; cooperative
  exits use `throw new CliExit(code)` from verified-unwindable sites only.

## Plan and rationale

Background, alternative approaches considered, and the phase-2 messages
module are in `docs/plans/cli-pty-integration-tests.md`.
