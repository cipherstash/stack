## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** high · `013e3ff31f..aca5cc8ebe`

Security patch bump of next 15.5.23 -> 15.5.24 (with @next/env and @next/swc-*) in the `security` catalog, and the `next` override raised from `next@<15.5.18: ~15.5.18` to `next@<15.5.24: ~15.5.24`. Only pnpm-workspace.yaml and pnpm-lock.yaml change. In this repo `next` is a devDependency of @cipherstash/nextjs (whose published peer range `^14 || ^15` is unchanged and which tsup externalises as a peer) and an optional peer of evlog (a runtime dependency of @cipherstash/stack); workspace overrides and the lockfile are not published, so no shipped artefact's contents or declared ranges change. The realistic failure is a patch-level behaviour change in next/server or next/headers breaking @cipherstash/nextjs's build/tests, which would be loud and was covered by CI: the Node 22/24 test jobs (which run `turbo test` over packages/**) and ci-required passed on the head commit. No material release risk found.

### Failure scenarios

**FS-1 · next 15.5.24 patch changes next/server or next/headers behaviour used by @cipherstash/nextjs** (low impact, speculative)

- Trigger: The upstream security fix in next 15.5.24 alters NextResponse, NextRequest or cookies() semantics that packages/nextjs relies on.
- Mechanism: packages/nextjs imports NextResponse/NextRequest from next/server and cookies from next/headers (src/index.ts, src/clerk/index.ts); its dev/test resolution moves to 15.5.24. tsup externalises next (peer dependency), so the published dist is not changed by the bump itself.
- Consequence: Local/CI build or test failures for @cipherstash/nextjs; customers are unaffected because they bring their own next within `^14 || ^15`.
- Affects: @cipherstash/nextjs (packages/nextjs)
- Evidence: `packages/nextjs/src/index.ts:2-4`; `packages/nextjs/tsup.config.ts:1-8` (inferred); `packages/nextjs/package.json:41-51`
- Existing verification: Run Tests (Node 22) and Run Tests (Node 24) execute `pnpm run test` (turbo test over packages/**, which includes packages/nextjs's vitest suite) and passed on head. [ran_passed]; PR author reports pnpm build, typecheck and test (25 tests) pass in packages/nextjs. [unknown]
- Missing verification: No CI job seen here explicitly builds/typechecks packages/nextjs outside turbo test; the build result relies on the PR author's report.
- Mitigation: None needed beyond normal review; the bump is a patch release on the same minor and is easily reverted.

### Recommended controls

- Confirm the lockfile diff only moves next/@next/* (and the dependent snapshot keys) and that no other package changed, matching the PR claim. (review_focus; FS-1)

### What this assessment could not see

- No network: the next 15.5.24 changelog, advisory GHSA-2xp9-vwfh-vxw4 and npm integrity hashes could not be checked. Whether 15.5.24 fully fixes the advisory and contains no other behaviour change is taken from the PR description and the passing osv-scanner check, not verified upstream.
- Did not run pnpm install/build/test locally (no network to fetch packages). Verification relies on CI results in ci.json and the PR author's report.
- 10 CI jobs were skipped by change detection (Postgres/EQL/Rust suites). Not relevant to a JS dev-dependency bump, but they provide no evidence for this change.
- Pre-existing, not caused by this change: @cipherstash/nextjs is only tested against the single pinned next 15.x, while its published peer range admits ^14. Next 14 compatibility is unverified both before and after this change.

_Inputs unavailable: codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
