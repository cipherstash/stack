## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** low · `9c2fc652a8..a258a817bc`

Lockfile-only change (pnpm-lock.yaml). Despite the title naming only proxy-addr 2.0.7->2.0.8, the lockfile also moves hono 4.13.7->4.13.13, jose 6.2.9->6.2.12 (for @modelcontextprotocol/sdk only), express-rate-limit 8.6.2->8.7.1, ip-address 10.7.2->10.7.3, negotiator 1.0.0->1.1.0 (now depends on content-type 2.1.0, already in the lockfile), shell-quote 1.10.0->1.12.0 (optional, via gel) and acorn 8.18.0->8.19.0 (optional, via terser). All are patch/minor upgrades in the transitive tree of @modelcontextprotocol/sdk (pulled in by @anthropic-ai/claude-agent-sdk in the @cipherstash/wizard package) or optional build tooling. No package.json specifier changes. The wizard build uses skipNodeModulesBundle, so these resolutions are not bundled into the published tarball; npm consumers resolve their own versions. Effect is confined to the monorepo's install, dev, test and build environment. Impact low; the main reviewer note is that the PR scope is wider than its title.

### Failure scenarios

**FS-1 · Unannounced transitive upgrades in the agent-SDK/MCP stack break wizard dev or test runs** (low impact, speculative)

- Trigger: A behavioural change in hono, jose, express-rate-limit or negotiator between the old and new patch/minor versions that the MCP SDK relies on.
- Mechanism: The lockfile changes eight resolutions while the title names one, so reviewers may not examine the others. They all sit under @modelcontextprotocol/sdk@1.29.0 used by the wizard's agent SDK. The only tests that exercise the real SDK are skipped unless WIZARD_INTEGRATION=1.
- Consequence: Wizard local/CI runs that use the agent SDK fail or behave differently. Published packages are not affected because the lockfile is not shipped and the wizard bundle excludes node_modules. Recovery is reverting the lockfile.
- Affects: pnpm-lock.yaml (workspace dependency resolution), @cipherstash/wizard (languages/typescript/packages/wizard)
- Evidence: `pnpm-lock.yaml:4265-4282`; `pnpm-lock.yaml:5568-5570`; `languages/typescript/packages/wizard/tsup.config.ts:4-18`; `languages/typescript/packages/wizard/src/__tests__/agent-sdk.test.ts:20-26`
- Existing verification: agent-sdk.test.ts exercises the real Claude Agent SDK, but is skipped by default (describe.skipIf(!RUN_INTEGRATION)). [exists_not_run]
- Missing verification: CI results for install, build and wizard tests at head.; Integrity/provenance check of the new tarballs (cannot be done offline).
- Mitigation: Confirm the extra bumps are intended (typical of a Dependabot rebase onto a refreshed lockfile) and that CI passes `pnpm install --frozen-lockfile`, build and tests; revert the lockfile if anything regresses.

### Recommended controls

- Reviewer should acknowledge that the lockfile changes hono, jose, express-rate-limit, ip-address, negotiator, shell-quote and acorn in addition to proxy-addr, and check that CI install/build/test is green before merging. (review_focus; FS-1, VG-1)

### What this assessment could not see

- No network access: upstream changelogs, advisories and tarball integrity hashes for the new versions could not be checked. Whether any upgrade changes behaviour or fixes/introduces a vulnerability is unknown; assessment relies on semver ranges and dependency placement.
- No CI results and no PR body. Cannot state that install, build or tests pass at head, or why the scope exceeds the title.
- Did not trace which other workspace packages (beyond the wizard) might reach express/hono at runtime; only importers whose resolution strings reference @modelcontextprotocol/sdk were found (wizard). Small chance of an additional dev-time consumer; does not change the low impact since no shipped artefact embeds the lockfile.

_Inputs unavailable: ci_results, architecture_docs, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
