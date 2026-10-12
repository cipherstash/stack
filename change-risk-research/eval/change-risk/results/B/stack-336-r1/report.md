## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `abf3ddd895..8ebc77b5ef`

Renames @cipherstash/stack-forge to @cipherstash/cli (1.0.0-rc.0), moves the `stash` CLI (auth, init, secrets) out of @cipherstash/stack into it, adds an AI 'wizard' that runs the Claude Agent SDK against the user's project through a CipherStash gateway, and moves the root dependency overrides. Four mechanisms matter for release: (1) the CLI binary is now built with skipNodeModulesBundle, so its static imports of @cipherstash/stack (only a devDependency) are left external and the published binary may fail to start where that package cannot be resolved; (2) the wizard lists every tool in allowedTools, which in the Agent SDK auto-approves them, so the canUseTool gate that blocks .env reads and non-allowlisted Bash may never run, sending local secrets to the gateway; (3) pnpm overrides moved to a top-level `overrides` field that pnpm does not read, and the lockfile has lost its overrides block and now resolves esbuild 0.18/0.19; (4) @cipherstash/stack loses its `stash` bin with no changeset or deprecation path. Nothing could be built or run, and the relevant tests do not exercise the packaged binary or the real SDK permission flow. Impact high; verification low.

### Failure scenarios

**FS-1 · Published `stash` binary fails to start because @cipherstash/stack is external but only a devDependency** (high impact, plausible)

- Trigger: A user runs `npx @cipherstash/cli <any command>` (the documented entry point) where @cipherstash/stack is not resolvable from the CLI's install location, e.g. the npx cache or a pnpm project that has not hoisted it.
- Mechanism: tsup bin build now sets skipNodeModulesBundle: true (packages/cli/tsup.config.ts:40), so bare imports are left external. bin/stash.ts statically imports commands/index.js, which statically imports db/push.ts (value import `toEqlCastAs` from '@cipherstash/stack/schema') and secrets/helpers.ts (value import `Secrets` from '@cipherstash/stack/secrets'). @cipherstash/stack is listed only in devDependencies (packages/cli/package.json:54), so npm does not install it for consumers. At base, tsup's default bundled devDependencies into stash-forge.js, so the same import was inlined.
- Consequence: Every CLI command, including `--help`, `auth login` and `init`, exits with ERR_MODULE_NOT_FOUND before main() runs, because ESM resolves static imports at load. Where it does resolve, the CLI silently runs against whatever @cipherstash/stack version the project has, rather than the one it was built with.
- Affects: @cipherstash/cli (published package, bin `stash`), @cipherstash/stack (published package)
- Evidence: `packages/cli/tsup.config.ts:27-41`; `packages/stack-forge/tsup.config.ts:39-40` (base) (inferred); `packages/cli/src/commands/db/push.ts:3`; `packages/cli/src/commands/secrets/helpers.ts:4`; `packages/cli/package.json:53-54`
- Existing verification: config.test.ts and installer.test.ts exercise source modules through vitest, not the built bin or a packed tarball. [exists_not_run]
- Missing verification: Build the package, `npm pack`, install the tarball into an empty directory and run `npx stash --help` and `stash db push --dry-run`.; Inspect dist/bin/stash.js for bare imports of @cipherstash/stack.
- Mitigation: Move @cipherstash/stack to dependencies (or peerDependencies with a clear install step), or add it to noExternal for the bin build; add a packed-tarball smoke test to CI before publishing.

**FS-2 · Wizard's canUseTool gate is bypassed by allowedTools, letting the agent read .env secrets and send them to the gateway** (high impact, plausible)

- Trigger: The wizard runs and the agent (steered by the gateway-supplied prompt or by text in the project) reads .env, ~/.cipherstash/auth.json or other credential files, or runs a Bash command outside the allowlist.
- Mechanism: sdkOptions lists Read, Write, Edit, Glob, Grep and Bash in allowedTools with permissionMode 'acceptEdits' (interface.ts:311-315). In the Claude Agent SDK, tools in allowedTools are auto-approved before the canUseTool callback is consulted, and a sandboxed Bash is auto-allowed by default, so wizardCanUseTool (sensitive-path blocking, Bash allowlist, operator scan) may never be called (interface.ts:320-331). The sandbox only constrains Bash writes, not the Read tool. The integration test that exercises canUseTool deliberately omits allowedTools, so it does not cover this configuration. The post-tool scanners in hooks.ts (scanPostToolUseRead/Write) are exported and unit-tested but not wired into the agent.
- Consequence: Contents of .env (DATABASE_URL with password, CS_CLIENT_KEY / CS_CLIENT_ACCESS_KEY) or CipherStash auth tokens enter the model context and leave the machine via the gateway; non-allowlisted shell commands run in the user's project. For an encryption product this is plaintext-secret exposure to a third party.
- Affects: Wizard agent permission layer (packages/cli/src/commands/wizard/agent), CipherStash wizard gateway (wizard.getstash.sh), Customer databases and projects running the wizard / db commands
- Evidence: `packages/cli/src/commands/wizard/agent/interface.ts:309-338`; `packages/cli/src/commands/wizard/agent/interface.ts:103-160`; `packages/cli/src/commands/wizard/__tests__/agent-sdk.test.ts:224-303`
- Existing verification: interface.test.ts unit-tests wizardCanUseTool as a pure function (blocks .env, operators, non-allowlisted commands). [exists_not_run]; agent-sdk.test.ts 'canUseTool blocks disallowed commands' is skipped unless WIZARD_INTEGRATION=1, runs without allowedTools, and asserts only expect(true).toBe(true). [exists_not_run]
- Missing verification: An SDK-level test using the exact sdkOptions from interface.ts that asserts canUseTool is invoked and a Read of .env is denied.; Confirmation of the pinned @anthropic-ai/claude-agent-sdk ^0.2.87 permission-evaluation order.
- Mitigation: Remove the tools from allowedTools (keep them in `tools`) so every call reaches canUseTool, or enforce the same rules in a PreToolUse hook; set permissionMode 'default'; wire the post-tool scanners as hooks or delete the claim; do not pass the full process.env to the agent.

**FS-3 · Dependency security overrides silently stop applying after moving to a top-level `overrides` field** (medium impact, observed in the code)

- Trigger: Any `pnpm install` in the repo or in CI/release with pnpm 10.14.0 (packageManager).
- Mechanism: Overrides moved from `pnpm.overrides` (base package.json:49) to a top-level `overrides` key (head package.json:77), which is npm's field; pnpm reads `pnpm.overrides` or `overrides` in pnpm-workspace.yaml, and the head pnpm-workspace.yaml has none. The regenerated lockfile confirms it: its `overrides:` block is removed, pg resolves 8.13.1 instead of the forced ^8.16.3, and esbuild 0.18.20 and 0.19.12 now resolve (pnpm-lock.yaml:3471, 4275) despite the `esbuild@<=0.24.2: >=0.25.0` rule.
- Consequence: Previously patched transitive versions (esbuild, and potentially vite, next, rollup, lodash, qs and others on future installs) are no longer forced, so the repo's dev, build and example toolchain regains known-vulnerable versions while the manifest still appears to pin them. Published library tarballs are not directly affected, since overrides never apply to consumers.
- Affects: Monorepo dependency resolution (root package.json, pnpm-lock.yaml) and CI/release install
- Evidence: `package.json:64-98`; `pnpm-lock.yaml`; `pnpm-lock.yaml:3469-3471`
- Existing verification: osv-scanner workflow exists and may flag the new versions; no result was available. [unknown]
- Missing verification: A diff of resolved versions for every previously overridden package between the base and head lockfiles.; OSV scanner result on the head lockfile.
- Mitigation: Restore the block under `pnpm.overrides` or move it to `overrides:` in pnpm-workspace.yaml, re-run `pnpm install`, and confirm the lockfile's overrides block returns.

**FS-4 · Removing the `stash` bin from @cipherstash/stack breaks existing users with no changeset or migration path** (medium impact, plausible)

- Trigger: The next release of @cipherstash/stack (version bump driven by any later changeset), or users upgrading stack-forge to the renamed package.
- Mechanism: packages/stack/package.json removes `bin.stash` and its postbuild; the bin source is deleted. No .changeset entry is added, so the removal ships under whatever bump the next unrelated changeset chooses, possibly a patch or minor. @cipherstash/stack-forge is renamed in place with no deprecation release; @cipherstash/cli 1.0.0-rc.0 is not covered by a changeset but would be published by `changeset publish`, which publishes unpublished versions.
- Consequence: `npx stash init|auth|secrets` and CI scripts that use it fail after a routine @cipherstash/stack upgrade. The failure is loud but surprising and unannounced. A prerelease version may publish to the default dist-tag depending on publish tooling.
- Affects: @cipherstash/stack (published package), Existing users of `npx stash` from @cipherstash/stack and of @cipherstash/stack-forge / `stash-forge`, Release pipeline (changesets publish)
- Evidence: `packages/stack/package.json:30-32` (base); `packages/stack/tsup.config.ts`; `.changeset/config.json`; `.github/workflows/release.yml:37-46`
- Missing verification: A changeset marking a major (or documented breaking) bump for @cipherstash/stack and an initial release for @cipherstash/cli.; A check of which dist-tag `changeset publish` uses for 1.0.0-rc.0.
- Mitigation: Add changesets; keep a deprecated `stash` shim in @cipherstash/stack for one release that tells users to run `npx @cipherstash/cli`; publish a final @cipherstash/stack-forge with an npm deprecate message; publish the rc under a `next` tag or in changesets pre mode.

**FS-5 · Wizard reports encryption is set up even when setup, push or migration failed or the user aborted** (medium impact, observed in the code)

- Trigger: Any post-agent step fails (no DATABASE_URL, the FS-1 module error in nested `npx @cipherstash/cli db push`, or a migration error), or the user types 'done' or cancels at an agent question.
- Mechanism: Typing 'done' or cancelling sets success = true (interface.ts:433-435). runPostAgentSteps then runs each command through runStep, which catches every execSync error and only logs a warning (post-agent.ts:97-115). run.ts then unconditionally prints 'Encryption is set up! Your data is now protected by CipherStash.' (run.ts:160).
- Consequence: Users may believe sensitive columns are encrypted when the encrypt config was never pushed, the migration did not run, or the agent's code changes were partial. Plaintext keeps being written while the tool reports protection.
- Affects: Customer databases and projects running the wizard / db commands, Wizard agent permission layer (packages/cli/src/commands/wizard/agent)
- Evidence: `packages/cli/src/commands/wizard/lib/post-agent.ts:92-115`; `packages/cli/src/commands/wizard/run.ts:150-161`
- Missing verification: A test of run() where a post-agent step fails, asserting a non-success outro and non-zero exit.
- Mitigation: Have runStep return a status; print the success outro only when every required step succeeded; treat 'done' or cancel as an aborted run that skips push and migrations.

### Recommended controls

- Add a CI job that runs tsup, `npm pack`s packages/cli, installs the tarball in a clean temp project with no @cipherstash/stack, and runs `stash --help`, `stash db validate` and `stash secrets --help`. (test; FS-1, VG-1)
- Security review of wizard/agent/interface.ts: drop tools from allowedTools so they reach canUseTool, enforce the rules in PreToolUse hooks, restrict the env passed to the agent, and wire or remove the post-tool scanners. (review_focus; FS-2, VG-2)
- Restore overrides under `pnpm.overrides` (or pnpm-workspace.yaml), reinstall, and diff resolved versions of every overridden package against the base lockfile. (other; FS-3, VG-3)
- Add changesets (breaking for @cipherstash/stack, initial for @cipherstash/cli), publish the rc under a non-latest dist-tag, and deprecate @cipherstash/stack-forge with a pointer to the new package. (documentation; FS-4)
- Make post-agent failures and 'done'/cancel paths produce a failure outro, and cover them with a unit test. (test; FS-5, VG-4)

### What this assessment could not see

- No node_modules and no network: the CLI could not be built, packed or tested, and tsup's skipNodeModulesBundle externals behaviour was taken from its documented semantics rather than observed output. FS-1 stays plausible_failure; tsup's tsconfig `paths` handling (the '@/...' alias) was assumed to keep aliases bundled.
- Claude Agent SDK permission ordering (allowedTools before canUseTool; sandboxed Bash auto-allow) was taken from SDK documentation knowledge, not verified against the pinned ^0.2.87 source. FS-2 depends on this; if the SDK consults canUseTool for allowedTools entries, FS-2's mechanism is weaker, though the post-tool scanners are still unwired.
- The wizard's system prompt is fetched at runtime from the gateway and was unavailable, so what the agent is told to edit (schema column-type changes, migrations) could not be assessed. Data-migration risk from agent-edited Drizzle/Prisma schemas followed by auto-run migrations is not assessed.
- The 1575-line lockfile diff was checked only for the overrides block and previously-overridden packages; the new transitive tree of @anthropic-ai/claude-agent-sdk and posthog-node was not reviewed. Example app changes (examples/basic), README rewrites and the rewritten skills/stash-cli/SKILL.md were skimmed, not checked line by line against the commands. Drift between shipped skill guidance and actual CLI behaviour could be missed.
- No CI results, PR description, CODEOWNERS or npm registry state (published versions, dist-tags) were available. Release-time behaviour of changesets for 1.0.0-rc.0 and whether any tests pass at head are unknown.

_Inputs unavailable: pr_description, ci_results, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
