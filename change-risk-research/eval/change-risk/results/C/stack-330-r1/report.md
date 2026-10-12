## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `b1b5157c32..07f5c4c1ec`

Adds a `stash auth login` command (device-code flow + device binding via the new native dependency @cipherstash/auth 0.34.2), makes authentication the mandatory first step of `stash init`, removes the CS_* credential guidance from init's next steps and from the README (which now says no env vars are needed for local development), and pins/downgrades several runtime dependencies of the published @cipherstash/stack package (evlog 1.11.0 -> 1.9.0, @byteslice/result 0.2.2 -> 0.2.0). No encryption, payload or SQL paths change. The main risks are in the published CLI: it now statically loads an unseen native package at startup and none of the CLI is built or exercised by CI; `stash init` can no longer complete without interactive network auth; and the new documentation contradicts code that still requires CS_* env vars (`stash secrets`, LockContext). Library runtime risk is limited to the dependency downgrades, which CI tests ran against.

### Failure scenarios

**FS-1 · Published stash CLI fails at startup for every command because @cipherstash/auth does not load** (high impact, plausible)

- Trigger: A user installs the released package and runs any `stash` command, on a platform or packaging where @cipherstash/auth's default export or native binary does not resolve as the bundled ESM bin expects.
- Mechanism: stash.ts statically imports commands/auth/index.js (stash.ts:7), which imports login.ts, which does `import auth from '@cipherstash/auth'` and destructures beginDeviceCodeFlow/bindClientDevice at module load (login.ts:2-3). A load or interop error is thrown before main() runs, so it is not caught by main().catch. The bin is a separate tsup build (tsup.config.ts:26-41) that CI does not build or run: `pnpm run test` runs vitest with turbo dependsOn ^build only, and no test file covers src/bin.
- Consequence: Every stash command, including `stash secrets` and `--help`, crashes for affected users of that published version; recovery requires a new npm release.
- Affects: stash CLI (packages/stack/src/bin, published as dist/bin/stash.js), stash secrets CLI commands
- Evidence: `packages/stack/src/bin/stash.ts:7-9`; `packages/stack/src/bin/commands/auth/login.ts:1-65`; `packages/stack/tsup.config.ts:26-41`; `turbo.json:16-20`; signal `tests`
- Existing verification: CI 'Run Tests' passed, but it runs vitest for packages and does not build or execute the stash bin. [ran_passed]
- Missing verification: Build the package and run `node dist/bin/stash.js --help` and `stash auth --help` from a packed tarball on the supported platforms (linux gnu/musl, darwin, windows).; Confirm @cipherstash/auth 0.34.2 exposes a CommonJS module.exports (default import) with beginDeviceCodeFlow and bindClientDevice.
- Mitigation: Lazy-load @cipherstash/auth inside the auth command/step (dynamic import) so other commands do not depend on it, and add a CLI smoke test of the built bin to CI.

**FS-2 · stash init cannot complete without interactive network login and device binding** (medium impact, plausible)

- Trigger: A user runs `stash init` offline, behind a proxy, in a non-interactive shell, in an unlisted region, or without wanting a device bound (e.g. already holding CS_* machine credentials), or the device code expires / binding fails.
- Mechanism: authenticateStep is unconditionally first in STEPS (init/index.ts:16-22) and calls selectRegion, login and bindDevice (authenticate.ts:7-11). login() has no error handling around beginDeviceCodeFlow/pollForToken (login.ts:31-52), so failures propagate to main() as 'Fatal error'; bindDevice calls process.exit(1) on failure (login.ts:54-65). Neither is a CancelledError, so init aborts before any scaffolding. There is no flag to skip or detect an existing token.
- Consequence: Onboarding command that previously worked offline is blocked for these users; re-running init re-authenticates and re-binds the device each time. Loud and recoverable, but affects the documented first step of the quick start.
- Affects: stash CLI (packages/stack/src/bin, published as dist/bin/stash.js), CipherStash auth / device-binding service
- Evidence: `packages/stack/src/bin/commands/init/index.ts:16-52`; `packages/stack/src/bin/commands/init/steps/authenticate.ts:4-13`; `packages/stack/src/bin/commands/auth/login.ts:1-65`
- Missing verification: No tests for the init flow or authenticate step (no test file maps to src/bin).; Manual check of init behaviour when auth fails or when already authenticated.
- Mitigation: Skip the step when a valid token or CS_* credentials already exist, add a `--skip-auth` flag, and convert auth failures into a clear message with a retry or continue option.

**FS-3 · New docs and init next steps say no env vars are needed, but stash secrets and LockContext still require CS_* credentials** (medium impact, observed in the code)

- Trigger: A new user follows the updated README / init next steps (auth login only, no CS_* vars, no cipherstash.toml) and runs `stash secrets ...` or constructs a LockContext; possibly also Encryption() if protect-ffi 0.21.0 does not read ~/.cipherstash/auth.json.
- Mechanism: README now states 'No environment variables or credentials are needed for local development ... the SDK and CLI will use the token saved to ~/.cipherstash/auth.json' (README.md:497, 451) and init next steps drop the CS_* instructions (base.ts:14). At head, secrets getConfig still exits with 'Missing required environment variables' when CS_WORKSPACE_CRN/CS_CLIENT_ID/CS_CLIENT_KEY are unset (helpers.ts:33-57), and LockContext calls loadWorkSpaceId which throws without CS_WORKSPACE_CRN or cipherstash.toml (identity/index.ts:62, utils/config/index.ts:66-70). Encryption delegates credential fallback to protect-ffi newClient (encryption/index.ts:79-90), which this change does not touch; whether it reads auth.json is unknown.
- Consequence: Documented local-development path fails with credential errors for the secrets CLI and identity-bound encryption, and the guidance on how to fix it (CS_* vars, TOML) has been removed from the README and init output.
- Affects: stash secrets CLI commands, packages/stack README / onboarding docs, LockContext (identity) and Encryption client credential loading
- Evidence: `packages/stack/README.md:495-510`; `packages/stack/src/bin/commands/init/providers/base.ts:13-14`; `packages/stack/src/bin/commands/secrets/helpers.ts:33-57`; `packages/stack/src/utils/config/index.ts:59-70`; `packages/stack/src/encryption/index.ts:79-90`
- Missing verification: End-to-end check that Encryption() initialises with only ~/.cipherstash/auth.json present and no CS_* vars.; Check of `stash secrets` and LockContext under the same conditions.
- Mitigation: Either make secrets/identity read the auth token, or scope the README claim to what works (e.g. Encryption only) and keep the CS_* guidance for secrets and lock contexts.

**FS-4 · Downgraded and exact-pinned runtime dependencies change library behaviour for consumers** (low impact, speculative)

- Trigger: Consumers install the new @cipherstash/stack release and the library logger or Result helpers rely on behaviour present only in evlog 1.11 / @byteslice/result 0.2.2.
- Mechanism: package.json pins evlog 1.9.0 and @byteslice/result 0.2.0 (package.json:209-212); the lockfile moves stack from evlog 1.11.0 and @byteslice/result 0.2.2 to the older versions. The logger uses evlog initLogger/createRequestLogger (utils/logger/index.ts:1). Exact pins also prevent deduplication with consumers' own versions.
- Consequence: Possible logging differences or duplicate installs for consumers; no data or encryption effect identified.
- Affects: @cipherstash/stack library runtime (logger, Result handling)
- Evidence: `packages/stack/package.json:208-215`; `pnpm-lock.yaml`; `packages/stack/src/utils/logger/index.ts:1`
- Existing verification: CI 'Run Tests' (pnpm install + vitest for packages) passed on head with the downgraded versions. [ran_passed]
- Missing verification: Reason for the downgrade is not stated in the PR.
- Mitigation: Confirm the downgrade is intentional (e.g. evlog 1.11 peer deps on next/react) and note it in the changeset.

### Recommended controls

- Add a CI smoke test that builds packages/stack, packs it, installs it, and runs `stash --help`, `stash auth --help` and `stash secrets --help` on linux gnu and musl (and ideally darwin/windows). (test; FS-1, VG-1)
- Load @cipherstash/auth lazily inside the auth command/step so unrelated commands do not depend on it. (other; FS-1)
- Make the init auth step skippable (flag, or detect existing token / CS_* vars) and handle login errors with a clear message. (other; FS-2)
- Reconcile README and init next steps with what actually reads auth.json; keep CS_* guidance for `stash secrets` and LockContext until they support the token. (documentation; FS-3, VG-2)
- Reviewer to confirm the intent of the evlog and @byteslice/result downgrades and exact pins. (review_focus; FS-4)

### What this assessment could not see

- node_modules are not installed, so @cipherstash/auth 0.34.2 (exports, module format, where it stores the token, what bindClientDevice does) and protect-ffi 0.21.0 credential loading could not be inspected. FS-1 and the Encryption part of FS-3 rest on unverified behaviour of these packages.
- I did not build the package or run the CLI or tests; CI results are conclusions only, without logs. Cannot say whether the bundled bin loads correctly.
- PR description is empty; intent of the dependency downgrades and the mandatory auth step is not stated. CODEOWNERS and deployment context unavailable. Scenarios FS-2 and FS-4 may reflect deliberate decisions.
- The service-side effects of device binding to the default keyset (e.g. repeated binds, which keyset/workspace is used) are not visible. Any key-management consequence of binding is unassessed.

_Inputs unavailable: codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
