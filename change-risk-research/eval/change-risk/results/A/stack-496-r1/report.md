## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `b9c4fe5598..c39e895ca9`

Adds a new ESM-only `@cipherstash/stack/wasm-inline` subpath (minimal encrypt/decrypt client over protect-ffi's WASM build) plus a Deno CI smoke test and a Supabase example. The release risk is mostly not in the new subpath but in what moves with it for every existing consumer: protect-ffi is bumped 0.23.0 -> 0.24.0 under the main Node entry (with a new node/default conditional-exports split, per the author's tsconfig comment), the main build now bundles zod and @byteslice/result, @cipherstash/auth moves 0.36 -> 0.38 for the shipped CLI and wizard, and the stack version is bumped by hand to 0.18.0 even though the repo releases via changesets and a pending minor changeset exists, with no changeset for this change. The WASM client also drops the Node entry's null short-circuit, so a null plaintext is encrypted rather than passed through. No CI results were available and protect-ffi/auth changelogs could not be read, so compatibility of 0.24 payloads with the EQL 2.3.1 bundle is unknown.

### Failure scenarios

**FS-1 · protect-ffi 0.24 changes main-entry behaviour or payloads without the EQL/CLI lockstep bump** (high impact, plausible)

- Trigger: A stack consumer upgrades to the release carrying this change, or bundles the main entry with a bundler whose conditions omit `node`.
- Mechanism: packages/stack/package.json:217 moves protect-ffi to 0.24.0. The workflow comment (tests.yml:21-25) says the EQL image is pinned to match the payload format of protect-ffi 0.23.x and must be bumped in lockstep; it is not, and the CLI still installs eql-2.3.1. The author's tsconfig comment says 0.24 resolves `default` to the WASM bundle with a different newClient signature, so a consumer bundle resolving without the `node` condition would call the NAPI-style newClient({...}) (encryption/index.ts:81) against the WASM API. The dependency's own changelog was not available.
- Consequence: If 0.24 changed payload or search-term shape, newly written ciphertexts or query terms may not match what EQL 2.3.1 in customer databases or older clients expect (wrong query results). With a non-node bundle, client initialisation fails for that deployment.
- Affects: @cipherstash/stack main (Node) entry, In-repo stack consumers (migrate, prisma-next, bench), Customer data encrypted by stack / EQL 2.3.1 SQL bundle, packages/cli (stash CLI)
- Evidence: `packages/stack/package.json:216-217`; `packages/stack/tsconfig.json:18-24`; `.github/workflows/tests.yml:18-25`; `packages/cli/src/installer/index.ts:7`; `packages/stack/src/encryption/index.ts:23-81`
- Existing verification: Stack/drizzle integration tests run in the run-tests job against postgres-eql 2.3.1 with real credentials. [exists_not_run]
- Missing verification: Review of protect-ffi 0.24.0 release notes for payload, search-term and API changes.; Round-trip and query test of data written by 0.23.0 read by 0.24.0 (and vice versa).; A check that the built main entry resolves to NAPI under common bundlers (Next.js server, Vite SSR, esbuild).
- Mitigation: Confirm 0.24 is payload-compatible with EQL 2.3.1 or bump EQL/CLI bundle together; add a changeset describing the protect-ffi bump; document the node-condition requirement for the main entry.

**FS-2 · Manual 0.18.0 bump collides with changesets; example's ^0.18.0 never resolves** (medium impact, plausible)

- Trigger: The changesets release action runs after merge.
- Mechanism: package.json:3 is set to 0.18.0 by hand while CHANGELOG still tops out at 0.17.0 and .changeset/restore-null-guards-in-encryption-ops.md requests a stack minor bump. changeset version bumps from the current 0.18.0 to 0.19.0, so 0.18.0 is never published, and for a 0.x range `^0.18.0` excludes 0.19.0. No changeset describes the new subpath or the protect-ffi/auth bumps.
- Consequence: Published version skips 0.18.0; the Supabase example import `npm:@cipherstash/stack@^0.18.0/wasm-inline` fails to resolve; the release notes omit a dependency bump that affects every consumer.
- Affects: Changesets release workflow, examples/supabase-worker, @cipherstash/stack main (Node) entry
- Evidence: `packages/stack/package.json:3`; `.changeset/restore-null-guards-in-encryption-ops.md:1-7`; `packages/stack/CHANGELOG.md:1-7`; `.github/workflows/release.yml:53-54`; `examples/supabase-worker/supabase/functions/cipherstash-roundtrip/index.ts:21`
- Missing verification: A dry run of `changeset version` / `changeset status` on this head.
- Mitigation: Revert the manual version to 0.17.0 and add a changeset for stack (and cli/wizard for the auth bump); update the example range to the version actually released.

**FS-3 · WASM client encrypts null instead of passing it through** (medium impact, plausible)

- Trigger: An edge/Deno caller encrypts a nullable column value that is null.
- Mechanism: WasmPlaintext includes null (wasm-inline.ts:108-114) and encrypt (wasm-inline.ts:205-218) forwards it to protect-ffi unguarded, whereas the Node EncryptOperation returns null (encrypt.ts:63). The pending changeset states protect-ffi turns null into a real SteVec ciphertext.
- Consequence: A null value is stored as a non-NULL ciphertext; IS NULL queries and code expecting null diverge between data written by edge and Node clients.
- Affects: @cipherstash/stack/wasm-inline, Customer data encrypted by stack / EQL 2.3.1 SQL bundle
- Evidence: `packages/stack/src/wasm-inline.ts:108-218`; `packages/stack/src/encryption/operations/encrypt.ts:63`; `.changeset/restore-null-guards-in-encryption-ops.md:1-7`
- Existing verification: Deno round-trip test encrypts only a non-null string. [exists_not_run]
- Missing verification: Test of encrypt(null)/decrypt(null) on the WASM entry matching Node entry semantics.
- Mitigation: Add the same null short-circuit to WasmEncryptionClient.encrypt/decrypt, or remove null from WasmPlaintext.

**FS-4 · auth 0.38 bump breaks CLI login or wizard credential detection** (medium impact, plausible)

- Trigger: A customer runs `stash auth login`/init or the wizard on a release built with auth 0.38.
- Mechanism: The CLI destructures beginDeviceCodeFlow/bindClientDevice from the auth default export (login.ts:1-4) and the wizard calls AutoStrategy.detect(); auth moves two minor versions and changes how native bindings are packaged (optional peers, compensated by new optionalDependencies). Wizard unit tests mock @cipherstash/auth, so API or binding-load changes are not exercised there. History shows the branch first kept cli/wizard on 0.36.0 and later reversed that.
- Consequence: CLI authentication or wizard prerequisites fail on some or all platforms; loud but customer-facing.
- Affects: packages/cli (stash CLI), packages/wizard
- Evidence: `pnpm-workspace.yaml:14-20`; `packages/cli/src/commands/auth/login.ts:1-4`; `packages/wizard/src/__tests__/prerequisites.test.ts:8`; signal `commits base..head`
- Existing verification: CLI and @cipherstash/e2e E2E jobs in tests.yml (coverage of real login unknown). [exists_not_run]
- Missing verification: Smoke test of CLI login/bind and wizard detect against auth 0.38 on each supported platform, installed via npm (not the workspace).
- Mitigation: Review auth 0.37/0.38 changelog; pack and install the CLI tarball on macOS/Linux/Windows before release.

### Recommended controls

- Read protect-ffi 0.24.0 notes; run cross-version (0.23 write / 0.24 read and query) tests against EQL 2.3.1, or bump EQL image and CLI bundle in lockstep. (compatibility_check; FS-1, VG-1)
- Revert manual version bump, add changesets for stack/cli/wizard, run `changeset status` before merge. (other; FS-2, VG-2)
- Add null-handling parity to the WASM client and a test for it. (test; FS-3, VG-3)
- Packed-tarball smoke test of CLI login and wizard on supported platforms with auth 0.38. (test; FS-4, VG-1)
- Check that bundling zod/@byteslice/result into all main entries does not change error identity (e.g. instanceof ZodError) or Result handling for downstream packages such as migrate and prisma-next. (review_focus; FS-1)

### What this assessment could not see

- Dependency sources were not installed; protect-ffi 0.24 conditional exports and payload behaviour are known only from the author's comments. FS-1 cannot be confirmed or ruled out; impact kept at high because of the mechanism, not lowered for lack of evidence.
- No CI results, PR description, CODEOWNERS or deployment information. All verification is exists_not_run; verification confidence is low.
- pnpm-lock.yaml diff was skimmed for auth/protect-ffi entries only; the removal of `libc:` fields was noted but not analysed. Repo-install effects of the lockfile regeneration (e.g. both musl and glibc binaries selected) are not assessed.
- Effect of bundling zod into each CJS/ESM entry (duplicate instances, size) was reasoned about, not tested. Kept as a review focus (RC-5), not a scenario.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
