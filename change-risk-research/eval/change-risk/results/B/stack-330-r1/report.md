## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** low · `b1b5157c32..07f5c4c1ec`

Adds a `stash auth login` command (device-code flow + device bind via the new native dependency @cipherstash/auth 0.34.2) and makes authentication a mandatory first step of `stash init`. The init next-steps and README no longer tell users to set CS_* credentials and claim the SDK and CLI use the saved token in ~/.cipherstash/auth.json for local development, but `stash secrets`, the Secrets class and LockContext at head still read only CS_* env vars / cipherstash.toml (the TOML docs were also removed). The change also pins runtime dependencies to exact versions that downgrade @byteslice/result (0.2.2 -> 0.2.0) and evlog (1.11.0 -> 1.9.0) for the published library. Nothing touches the encryption path, payload format or key handling directly. No tests cover the CLI, and no CI results were provided. Impact is medium: onboarding and CLI failures that users notice, not data or security failures. A reviewer should check the documented credential contract, how eagerly the native module loads, the non-interactive init path, and the dependency downgrades.

### Failure scenarios

**FS-1 · Docs and init promise credential-free local dev, but secrets CLI/API and LockContext still require CS_* env vars** (medium impact, observed in the code)

- Trigger: A new user follows the updated README or the init next-steps: runs `stash init` or `stash auth login`, sets no CS_* vars and no cipherstash.toml, then runs `stash secrets ...`, constructs `Secrets`, or uses LockContext.
- Mechanism: The next-steps lists drop the CS_* setup instruction (base.ts:14, supabase.ts:18), and the README says the SDK and CLI use ~/.cipherstash/auth.json (README.md:451, 497). `stash secrets` getConfig still exits when CS_WORKSPACE_CRN/CS_CLIENT_ID/CS_CLIENT_KEY are missing (helpers.ts:33-61). Secrets throws without CS_* values (secrets/index.ts:179-188). loadWorkSpaceId, used by LockContext, throws without CS_WORKSPACE_CRN or cipherstash.toml (config/index.ts:59-92, identity/index.ts:62). The README section that documented cipherstash.toml was deleted even though the code still reads it. The shipped stash-encryption skill still documents CS_* vars.
- Consequence: Users get 'Missing required environment variables' or 'You have not defined a workspace CRN' errors right after an onboarding flow that told them no credentials are needed, and the docs no longer say where to put them. Agent skills copied into customer repos give guidance that conflicts with the README. The failures are loud; no data or security effect.
- Affects: stash CLI (packages/stack/src/bin), stash secrets CLI command, Secrets class and LockContext (library API), Shipped agent skill skills/stash-encryption/SKILL.md, Encryption client (newClient from protect-ffi 0.21.0)
- Evidence: `packages/stack/src/bin/commands/init/providers/base.ts:14`; `packages/stack/src/bin/commands/init/providers/supabase.ts:18`; `packages/stack/README.md:451`; `packages/stack/README.md:497`; `packages/stack/src/bin/commands/secrets/helpers.ts:33-61`; `packages/stack/src/secrets/index.ts:179-188`; `packages/stack/src/utils/config/index.ts:59-92`; `skills/stash-encryption/SKILL.md:36-59`
- Missing verification: An end-to-end check that `stash auth login` followed by `stash secrets list` (and Encryption()/LockContext) works with no CS_* vars set.; Confirmation of whether protect-ffi 0.21.0 newClient reads ~/.cipherstash/auth.json.
- Mitigation: Make the docs match the code: state which surfaces support the auth.json token (only the encryption client, if protect-ffi supports it) and keep CS_*/cipherstash.toml instructions for secrets and LockContext. Alternatively, add auth.json support to those paths before claiming it. Update skills/stash-encryption/SKILL.md in the same release.

**FS-2 · Native @cipherstash/auth loaded eagerly breaks every stash command on platforms without a prebuilt binary** (medium impact, plausible)

- Trigger: A user runs any `stash` command (including `stash secrets` or `stash --help`) on a platform with no @cipherstash/auth binary in 0.34.2, e.g. linux-arm64-musl (Alpine on ARM) or win32-arm64, or where optional dependencies were skipped at install.
- Mechanism: stash.ts:7 statically imports commands/auth/index.js, which imports login.ts. login.ts:2-3 does `import auth from '@cipherstash/auth'` at module top level, so the package is resolved before main() runs. The lockfile lists only six platform binaries (pnpm-lock.yaml:467-497). The CLI bundle keeps dependencies external (tsup.config.ts:26-41). If the package's loader throws when no binary matches, which is typical of napi packages but not verified here, the error happens at import time, before the main().catch handler can catch it.
- Consequence: `stash secrets` and `stash init` stop working on those platforms, even for users who never use auth. Before this change, those commands did not need this module. The failure is loud; a fix needs a new release.
- Affects: stash CLI (packages/stack/src/bin), stash secrets CLI command, @cipherstash/stack npm package (dependency set)
- Evidence: `pnpm-lock.yaml:467-497`; `packages/stack/src/bin/stash.ts:7-9`; `packages/stack/src/bin/commands/auth/login.ts:1-3` (inferred)
- Missing verification: A smoke test of `stash --help` / `stash secrets` on a platform without a matching binary, or inspection of @cipherstash/auth's loader behaviour.; A CLI smoke test in CI on each supported OS.
- Mitigation: Lazy-load @cipherstash/auth (dynamic import inside login/bindDevice) so only `auth` and `init` depend on it, and show a clear message when the platform is unsupported.

**FS-3 · Mandatory interactive device-code auth makes `stash init` unusable non-interactively or offline** (medium impact, plausible)

- Trigger: `stash init` runs in CI, in a container without a browser, from a coding agent, or by a user who already has CS_* machine credentials or no network access to the auth service.
- Mechanism: authenticateStep is now first in STEPS (init/index.ts:16-22) and always calls selectRegion, login and bindDevice (authenticate.ts:7-12). There is no flag to skip it and no check for an existing token or env credentials. login() waits on pollForToken with no timeout handling of its own (login.ts:32-51). bindDevice() calls process.exit(1) on any error (login.ts:53-65). Any failure therefore aborts init before the connection, schema and forge steps run.
- Consequence: Workflows that used to scaffold a project with `stash init` now hang at a prompt or exit before generating anything. Users with working machine credentials are forced through a browser login and a device bind to the default Keyset that they may not want.
- Affects: stash CLI (packages/stack/src/bin)
- Evidence: `packages/stack/src/bin/commands/init/index.ts:16-22`; `packages/stack/src/bin/commands/init/steps/authenticate.ts:7-12`; `packages/stack/src/bin/commands/auth/login.ts:32-51`; `packages/stack/src/bin/commands/auth/login.ts:53-65`
- Missing verification: Tests for init with auth skipped, failing or already done.; A check of pollForToken behaviour on expiry or denial (it lives inside @cipherstash/auth and could not be read).
- Mitigation: Add a `--skip-auth` flag, or skip the step when a valid token or CS_* credentials already exist. Treat a bind failure as a warning in init, or throw an error that the init loop handles, instead of calling process.exit.

**FS-4 · Exact-pin downgrades of @byteslice/result and evlog change library runtime for all consumers** (medium impact, speculative)

- Trigger: A consumer installs the new @cipherstash/stack minor version. Their encryption operations now run against @byteslice/result 0.2.0 and evlog 1.9.0 instead of the 0.2.2 and 1.11.0 that the base lockfile resolved.
- Mechanism: package.json:209-213 pins exact versions, and the lockfile moves @byteslice/result to 0.2.0 and evlog to 1.9.0 (pnpm-lock.yaml:406, 1489). withResult wraps every encryption operation's result (e.g. encryption/index.ts:22), and the logger uses initLogger/createRequestLogger plus sampling rates from evlog (utils/logger/index.ts:1-33). Whether 0.2.0 → 0.2.2 or 1.9.0 → 1.11.0 contains behaviour this code relies on is unknown. Exact pins also stop consumers' package managers from deduplicating these packages.
- Consequence: If behaviour differs, the result/failure objects that callers branch on, or the log-level filtering, could change silently for library users. This part of the PR is unrelated to the CLI feature. No evidence of an actual difference was found.
- Affects: @cipherstash/stack npm package (dependency set)
- Evidence: `pnpm-lock.yaml:406-410`; `pnpm-lock.yaml:1489`; `packages/stack/src/utils/logger/index.ts:1-33`
- Existing verification: The packages/stack test suite exercises encryption operations through withResult. Its results at head were not seen. [exists_not_run]
- Missing verification: A CI run of the packages/stack test suite against the new lockfile.; A review of the @byteslice/result 0.2.0..0.2.2 and evlog 1.9.0..1.11.0 changelogs.
- Mitigation: Pin at the previously resolved versions (0.2.2, 1.11.0) or keep caret ranges, unless the downgrade is intentional, and say why in the changeset.

### Recommended controls

- Reconcile the README, init next-steps and skills/stash-encryption/SKILL.md with what actually reads auth.json. Restore the CS_* / cipherstash.toml guidance for secrets and LockContext. (documentation; FS-1)
- Add a CLI smoke test: with no CS_* vars, `stash --help` and `stash secrets list` behave as documented, and `stash init` can be driven or skipped past auth. (test; FS-1, FS-2, FS-3, VG-1)
- Review whether @cipherstash/auth should be imported lazily, and what happens on an unsupported platform. (review_focus; FS-2)
- Confirm that downgrading @byteslice/result and evlog is intentional. Run the packages/stack suite in CI against the new lockfile before publishing. (review_focus; FS-4, VG-2)
- Provide a non-interactive path for `stash init` (skip-auth flag, or reuse of existing credentials), and avoid process.exit inside the init step. (other; FS-3)

### What this assessment could not see

- No node_modules were available, so @cipherstash/auth 0.34.2 (default export shape, platform loader, where and with what file permissions it writes ~/.cipherstash/auth.json, pollForToken timeout behaviour) and protect-ffi 0.21.0 credential resolution could not be read. FS-2 stays a plausible failure, and the protect-ffi part of FS-1 is unknown. Token-at-rest security could not be assessed.
- No CI results and no tests run. No PR description beyond the title. Verification confidence is low. Intent behind the dependency pin/downgrade (FS-4) is unknown.
- pnpm-lock.yaml was only reviewed for the hunks touching packages/stack and evlog/@byteslice/@cipherstash/auth. Moving the @rollup optionalDependencies blocks in other importers looks like reordering only. Minor lockfile effects in other packages may have been missed.
- A pre-existing mismatch was noticed and left out of the scenarios because this change did not cause it: secrets/helpers.ts reads CS_ACCESS_KEY, while the Secrets class and docs use CS_CLIENT_ACCESS_KEY. Not attributed to this change.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
