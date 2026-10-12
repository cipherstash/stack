## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** low · `013e3ff31f..aca5cc8ebe`

Dependency-only change: the `security` catalog pin for `next` moves from 15.5.23 to 15.5.24 and the workspace override floor is raised from `next@<15.5.18 -> ~15.5.18` to `next@<15.5.24 -> ~15.5.24` (comment cites GHSA-2xp9-vwfh-vxw4 / CVE-2026-75604). The lockfile is regenerated to match: next, @next/env and the eight @next/swc-* binaries move to 15.5.24, and the dependents @clerk/nextjs and evlog are re-keyed. In this repository `next` is only a devDependency of @cipherstash/nextjs (whose published peer range `^14 || ^15` is unchanged, and tsup externalises it) and an optional peer of evlog, a runtime dependency of @cipherstash/stack. The lockfile and overrides are not published, so customers' installed next version and the shipped dist output do not change. The realistic failure is a local/CI one: a patch-level behaviour or type change in next/server or next/headers breaking @cipherstash/nextjs typecheck or tests. Impact is low. CI wiring that would catch that exists (frozen-lockfile install, nextjs typecheck, turbo test) but no CI results were provided. A side note for reviewers: this bump does not fix the CVE for customers, who pick their own next version.

### Failure scenarios

**FS-1 · Patch-level change in next 15.5.24 breaks @cipherstash/nextjs typecheck or tests** (low impact, plausible)

- Trigger: next 15.5.24 (a security patch release) changes types or runtime behaviour of NextResponse, NextRequest or cookies() used by packages/nextjs.
- Mechanism: packages/nextjs is compiled, typechecked and tested against the catalog-pinned next. Security fixes in middleware or request handling can tighten behaviour that the middleware helpers or their tests rely on.
- Consequence: CI fails for the nextjs package or, if tests are not run, a local dev/test mismatch. Published dist is unaffected because next is external and the peer range is unchanged; customers run whichever next they install.
- Affects: @cipherstash/nextjs (packages/nextjs), CI tests workflow (frozen-lockfile install, nextjs typecheck, turbo test)
- Evidence: `packages/nextjs/src/index.ts:2-4`; `packages/nextjs/__tests__/nextjs.test.ts:17`; `packages/nextjs/tsup.config.ts:3-8` (inferred); `.github/workflows/tests.yml:220-221`
- Existing verification: CI typecheck of @cipherstash/nextjs against the installed next. [exists_not_run]; packages/nextjs/__tests__/nextjs.test.ts exercises getCtsToken/resetCtsToken/protectMiddleware using next/server, reached through the root `turbo test --filter './packages/**'`. [exists_not_run]
- Missing verification: No CI result for the head commit was available to confirm install, typecheck and tests pass with next 15.5.24.
- Mitigation: Confirm the tests workflow (frozen-lockfile install, nextjs typecheck, pnpm run test) passes on the head commit before merging. Reverting is a one-commit lockfile/workspace revert.

### Recommended controls

- Require a green tests workflow on the head commit (frozen-lockfile install, `turbo run typecheck --filter @cipherstash/nextjs`, `pnpm run test`). (test; FS-1, VG-1)
- Do not treat this as fixing CVE-2026-75604 for customers: @cipherstash/nextjs still accepts `next ^14 || ^15`. If customer guidance is wanted, it belongs in release notes or the peer range, which is a separate decision. (documentation; )

### What this assessment could not see

- No CI results were available, and no install/build/test command was run (no network). Verification confidence is low; whether the lockfile installs and the nextjs package passes against 15.5.24 is unconfirmed.
- The next 15.5.23 -> 15.5.24 upstream changelog and the cited advisory could not be read (no network). Upstream behaviour changes in the patch release are unknown; FS-1 rests on the general mechanism, not a known change.
- Whether next 15.5.24 satisfies the workspace `minimumReleaseAge` (7 days) and whether lockfile integrity hashes match the registry could not be checked offline. A supply-chain or cooldown issue with the new version would not be detected by this assessment.

_Inputs unavailable: ci_results, architecture_docs, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
