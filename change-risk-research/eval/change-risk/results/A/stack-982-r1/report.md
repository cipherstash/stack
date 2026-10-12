## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `013e3ff31f..aca5cc8ebe`

Patch-level security bump of next from 15.5.23 to 15.5.24 in the workspace 'security' catalog, with the workspace override raised from next@<15.5.18 -> ~15.5.18 to next@<15.5.24 -> ~15.5.24 (GHSA-2xp9-vwfh-vxw4 / CVE-2026-75604 per the commit). The lockfile is regenerated consistently (no 15.5.23 references remain). next is only a devDependency of @cipherstash/nextjs (whose published peer range ^14 || ^15 is unchanged and which is not bundled) and an optional peer of evlog, a runtime dependency of @cipherstash/stack. Catalogs and overrides do not ship to consumers, so no published contract changes; the effect is confined to the next version this repo builds and tests against. The only scenario is a patch-level change in next/server or next/headers breaking @cipherstash/nextjs build/tests, which would be loud in CI. CI results were not available.

### Failure scenarios

**FS-1 · Patch-level next change breaks @cipherstash/nextjs build or tests** (low impact, speculative)

- Trigger: next 15.5.24 alters behaviour or types of next/server (NextResponse, NextRequest) or next/headers (cookies) used by @cipherstash/nextjs.
- Mechanism: packages/nextjs/src imports NextResponse/NextRequest from next/server and cookies from next/headers; its devDependency now resolves to 15.5.24. Security patches can tighten middleware/header handling.
- Consequence: Typecheck, build or vitest failures for @cipherstash/nextjs in CI (loud). Published artefacts are not affected because next is an external peer whose range is unchanged; customers choose their own next version.
- Affects: @cipherstash/nextjs (packages/nextjs), CI install (pnpm install --frozen-lockfile)
- Evidence: `packages/nextjs/src/index.ts:2-4`; `packages/nextjs/tsup.config.ts:1-8` (inferred); `packages/nextjs/__tests__/nextjs.test.ts:17-38`
- Existing verification: packages/nextjs/__tests__/nextjs.test.ts exercises getCtsToken, resetCtsToken and protectMiddleware using the real NextResponse from next/server (next/headers is mocked). [exists_not_run]
- Missing verification: CI results for this commit (install, typecheck, build and test of @cipherstash/nextjs) were not available.
- Mitigation: Confirm CI passes for @cipherstash/nextjs (typecheck, build, test) before merging.

### Recommended controls

- Check the CI run for this commit: frozen-lockfile install succeeds and @cipherstash/nextjs typecheck/build/test pass. (test; FS-1, VG-1)

### What this assessment could not see

- No network access: the upstream next 15.5.24 changelog, the advisory contents and the lockfile integrity hashes could not be checked. Whether 15.5.24 fixes the advisory, and what else it changes, is taken from the commit message and not verified.
- The workspace enforces minimumReleaseAge: 10080 (7 days) and next is not in minimumReleaseAgeExclude. The publish date of next 15.5.24 is unknown offline. Cannot tell whether a non-frozen re-resolution soon after release would reject or demote 15.5.24; a frozen-lockfile install is expected to use the locked version, but this was not observed.
- No CI results, CODEOWNERS or PR description were provided. Verification confidence rests on the existence of tests, not their results.
- That tsup leaves next external in @cipherstash/nextjs's dist is inferred from tsup's default handling of peer dependencies; the built output was not inspected. If next were bundled, the published dist would embed the new next code; considered unlikely.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
