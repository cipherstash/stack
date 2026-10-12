## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** low · `b1b5157c32..07f5c4c1ec`

Adds a `stash auth login` command (region select, OAuth device-code flow and device-to-keyset binding through the new native dependency @cipherstash/auth 0.34.2) and makes the same flow the first, mandatory step of `stash init`. It also rewrites the shipped README and the init 'next steps' to say local development needs no CS_* environment variables, pins three existing runtime dependencies to exact versions (evlog 1.11.0 to 1.9.0 and @byteslice/result 0.2.2 to 0.2.0 in the lockfile), and is released as a minor bump. Library encryption paths, payloads and exports are not touched. The material risks are in the CLI and its guidance. `stash init` can no longer complete without network access, an interactive region prompt, a browser confirmation and a successful device binding. There is no skip or 'already authenticated' check, and a failure aborts before any scaffolding. The new guidance that no env vars are needed contradicts code that is unchanged at head: `stash secrets` still exits unless CS_WORKSPACE_CRN, CS_CLIENT_ID and CS_CLIENT_KEY are set, and LockContext still requires CS_WORKSPACE_CRN or cipherstash.toml. No test covers any CLI code, and no CI results were provided. Failures are loud onboarding failures with no data or encryption effect, so the impact is medium.

### Failure scenarios

**FS-1 · `stash init` cannot complete without interactive, networked device login and a successful keyset bind** (medium impact, plausible)

- Trigger: A user runs `npx stash init` offline, behind a proxy, in a non-interactive or CI shell, in a region not in the hard-coded list, lets the device code expire, or the bind call fails (e.g. the account has no default keyset). Re-running init also forces a new login and bind every time.
- Mechanism: STEPS now starts with authenticateStep (init/index.ts:16-22). It always calls selectRegion, login and bindDevice (steps/authenticate.ts:7-11) and does not check for an existing token. Rejections from beginDeviceCodeFlow or pollForToken are not caught in login() (auth/login.ts:30-51) or in initCommand, which only handles CancelledError (init/index.ts:46-52). They reach main()'s catch and exit 1 (stash.ts:93-97). A failed bindClientDevice calls process.exit(1) (auth/login.ts:57-64).
- Consequence: Init exits before connection selection, schema generation and forge install. At base, init worked with no account or network. Users get no scaffolding and no fallback path. Onboarding is blocked for any user who cannot complete the device flow or bind.
- Affects: stash CLI: init command, @cipherstash/stack published npm package (README, dependency set)
- Evidence: `packages/stack/src/bin/commands/init/steps/authenticate.ts:4-13`; `packages/stack/src/bin/commands/init/index.ts:16-52`; `packages/stack/src/bin/commands/auth/login.ts:30-51`; `packages/stack/src/bin/commands/auth/login.ts:53-65`; `packages/stack/src/bin/commands/auth/login.ts:4-28`; `packages/stack/src/bin/stash.ts:76-97`
- Existing verification: No unit or integration test covers src/bin (collector name mapping, plus a listing of packages/stack/__tests__). [unknown]
- Missing verification: A test of initCommand with the auth step mocked to reject (expired code, bind failure) asserting the user-facing outcome; A manual run of `stash init` against the real service in each listed region, plus a re-run when already authenticated
- Mitigation: Skip the auth step when a valid token already exists. Add a `--skip-auth` flag or let the step fail soft and continue scaffolding with a warning. Catch device-flow errors with a clear message.

**FS-2 · New guidance says no env vars are needed for local development, but `stash secrets` and LockContext still require them** (medium impact, observed in the code)

- Trigger: A user follows the updated README or init next-steps: they run `stash auth login`, set no CS_* variables and no cipherstash.toml, then use `stash secrets ...` or `LockContext`.
- Mechanism: The README now says no environment variables or credential files are needed and that the CLI uses ~/.cipherstash/auth.json (README.md:451, 495-497). Init next-steps dropped the instruction to set CS_* (providers/base.ts:13-14 head vs base). At head, secrets/helpers.ts getConfig still exits 1 when CS_WORKSPACE_CRN, CS_CLIENT_ID or CS_CLIENT_KEY is missing (helpers.ts:33-51). LockContext calls loadWorkSpaceId(), which throws without CS_WORKSPACE_CRN or cipherstash.toml (identity/index.ts:62, utils/config/index.ts:59-71). This change removed the TOML documentation.
- Consequence: Shipped docs and CLI output tell users something the code does not support. The secrets CLI and identity-aware encryption fail on first use with 'missing environment variables' or 'workspace CRN' errors. No data effect, but onboarding guidance is wrong in a published README.
- Affects: stash CLI: secrets commands, @cipherstash/stack identity (LockContext), @cipherstash/stack published npm package (README, dependency set)
- Evidence: `packages/stack/README.md:495-510`; `packages/stack/README.md:443-451`; `packages/stack/src/bin/commands/secrets/helpers.ts:33-51`; `packages/stack/src/utils/config/index.ts:59-71`; `packages/stack/src/bin/commands/init/providers/base.ts:13-17` (base); `packages/stack/README.md`
- Missing verification: An end-to-end run of the documented local-dev path (auth login, then secrets set, then LockContext) with no CS_* variables set
- Mitigation: Make the secrets CLI and loadWorkSpaceId fall back to the device token or profile, or scope the README claim to what actually works and keep the CS_* and cipherstash.toml instructions for the secrets CLI and identity.

**FS-3 · Encryption() may fail after following the new 'no credentials' quick start if protect-ffi 0.21.0 does not read the device token** (medium impact, plausible)

- Trigger: A user completes `stash init` (device login) and calls `Encryption({ schemas })` with no CS_* variables set, as the README now says is enough.
- Mechanism: Encryption.init passes only the explicit config to protect-ffi newClient and relies on its internal env fallback (encryption/index.ts:79-90). This change does not bump protect-ffi (still 0.21.0). The repository contains nothing showing that newClient reads ~/.cipherstash/auth.json, and the package contents were not available to check.
- Consequence: If newClient does not support the token, every new user following the quick start gets a ClientInitError when creating the client. The README examples would fail at the first step of the documented path.
- Affects: @cipherstash/stack Encryption client initialisation, @cipherstash/stack published npm package (README, dependency set)
- Evidence: `packages/stack/README.md:495-510`; `packages/stack/src/encryption/index.ts:79-90` (inferred); `packages/stack/package.json:208-215`
- Missing verification: Confirm that protect-ffi 0.21.0 newClient resolves credentials from the @cipherstash/auth token store; A smoke test: device login, then Encryption() with an empty env
- Mitigation: Verify the protect-ffi credential chain before publishing. If it does not support the token, bump protect-ffi or keep the CS_* instructions for SDK use.

**FS-4 · Library consumers silently get older evlog and @byteslice/result versions with exact pins** (low impact, speculative)

- Trigger: A consumer installs the new @cipherstash/stack minor release.
- Mechanism: The dependency ranges become exact pins (package.json:208-215). The lockfile resolution moves evlog 1.11.0 to 1.9.0 and @byteslice/result 0.2.2 to 0.2.0. The logger only imports initLogger and createRequestLogger (utils/logger/index.ts:1). evlog was introduced at 1.9.0 in commit ac17968, which lowers the chance of a missing API.
- Consequence: Probably benign. At worst, logging behaviour differs from the version CI previously resolved, and consumers get duplicate copies of these packages. The repository's tests at head will now run against 1.9.0.
- Affects: @cipherstash/stack published npm package (README, dependency set)
- Evidence: `packages/stack/package.json:208-215`; signal `dependencies`; `git -C repo show ac17968 -- pnpm-lock.yaml | grep -A2 evlog`
- Existing verification: Library tests in packages/stack/__tests__ exercise code paths that use the logger and Result helpers; not run here. [exists_not_run]
- Missing verification: A CI run of the packages/stack test suite against the new lockfile
- Mitigation: Confirm whether the pins and downgrade are intentional. If not, restore the caret ranges.

### Recommended controls

- Review init/steps/authenticate.ts and auth/login.ts error handling. Decide whether init should hard-require auth, add a skip or 'already logged in' path, and catch device-flow and bind errors. (review_focus; FS-1)
- Reconcile the README 'Local Development' and `stash auth` sections and the init next-steps with what the secrets CLI, LockContext and Encryption() actually accept. Keep or restore the CS_* and cipherstash.toml guidance where it is still required. (documentation; FS-2, FS-3)
- Before publishing, do a manual smoke run on a clean machine: `stash auth login`, `stash init`, Encryption() and `stash secrets list` with no CS_* variables set. (compatibility_check; FS-1, FS-2, FS-3, VG-2)
- Add unit tests for the init step runner and auth command with @cipherstash/auth mocked, covering rejection paths. Run the packages/stack suite in CI against the new lockfile. (test; VG-1, FS-4)

### What this assessment could not see

- @cipherstash/auth and @cipherstash/protect-ffi are not installed in the checkout and no network access was allowed. Their APIs (beginDeviceCodeFlow, pollForToken, bindClientDevice, newClient credential resolution) and the default-import interop of `import auth from '@cipherstash/auth'` in the ESM bin bundle could not be verified. FS-3 remains plausible rather than confirmed. A load-time failure of the auth import would affect every stash command and was not assessed.
- No CI results, PR description, CODEOWNERS or deployment context were available. No build or test was run. Verification confidence is low by default. Nothing is claimed as passing.
- The collector's name-based mapping links providers/supabase.ts to a library supabase test. That test covers the Supabase SDK integration, not the CLI provider. Not counted as coverage of the CLI change.
- The CLI already loaded the protect-ffi native module at startup through the secrets command import chain. Adding a second native module (same platform set) was judged not to widen platform exposure materially, but this was not tested. No scenario was raised for eager native loading.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
