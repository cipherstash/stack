## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `b9c4fe5598..c39e895ca9`

Adds a new ESM-only `@cipherstash/stack/wasm-inline` subpath (Encryption factory + encrypt/decrypt over WASM protect-ffi and auth AccessKeyStrategy), a Deno CI smoke test and a Supabase Edge example. The riskier part for existing users is not the new subpath but what ships alongside it: the Node entry's native dependency moves protect-ffi 0.23.0 -> 0.24.0 (whose new conditional exports also change which type declarations consumers resolve), `@cipherstash/auth` becomes a stack dependency and moves 0.36.0 -> 0.38.0 for the CLI and wizard, zod and @byteslice/result are now bundled into every stack entry, and stack's version is hand-bumped to 0.18.0 in a changesets repo. All 8 CI checks are green, including Node 22/24, Bun, E2E and the new Deno job, which is the main mitigation for the protect-ffi bump. The new WASM client also diverges from the Node client on null handling (no null short-circuit), which matters once edge and Node code share a table. No plaintext-exposure or wrong-key mechanism was found. Focused review is advised on the protect-ffi/auth bumps and on WASM/Node payload parity.

### Failure scenarios

**FS-1 · protect-ffi 0.24.0 native bump changes payloads or API for existing Node users without a matching EQL bump** (high impact, plausible)

- Trigger: An existing stack user upgrades and encrypts/queries against a database with the EQL 2.3.x SQL bundle, or decrypts payloads written by 0.23.0.
- Mechanism: Every main-entry operation now runs on protect-ffi 0.24.0 (package.json:217). The repository's own CI comment says postgres-eql 2.3.1 matches the protect-ffi 0.23.x payload format and must be bumped in lockstep (tests.yml:21-22). The image was not bumped. The PR asserts 0.24 is WASM-focused and not a format bump, but the protect-ffi changelog is not available to confirm it.
- Consequence: If 0.24 changed payload shape or search-term encoding, newly written values could fail to index or match in existing databases, or older payloads could fail to decrypt. That is a cross-version compatibility problem affecting data at rest, and npm publication cannot be undone.
- Affects: @cipherstash/stack main (Node) entry, Stack encryption operations calling protect-ffi newClient/encrypt/decrypt, EQL SQL bundle / postgres-eql image (data at rest)
- Evidence: `packages/stack/package.json:213-221`; `.github/workflows/tests.yml:21-25`; pr_description; ci_result
- Existing verification: Run Tests (Node 22/24), Run Tests (Bun) and Run E2E Tests jobs passed on head; the Node job runs against postgres-eql 2.3.1. [ran_passed]
- Missing verification: No test decrypts or queries a fixture payload written by protect-ffi 0.23.0 (read compatibility with data at rest).; No review of the protect-ffi 0.24.0 changelog or Node API diff is recorded.
- Mitigation: Confirm from the protect-ffi 0.24.0 release notes that the Node API and EQL payload/search-term format are unchanged. Add or run a fixture test that decrypts and queries 0.23-written ciphertexts, and update the stale tests.yml lockstep comment.

**FS-2 · WASM client encrypts null into a real ciphertext where the Node client returns null** (medium impact, plausible)

- Trigger: Edge or Deno code calls client.encrypt(null, ...) for a nullable column, which the WasmPlaintext type explicitly allows, on a table that Node code also reads or queries.
- Mechanism: WasmPlaintext includes null (wasm-inline.ts:108-112), and WasmEncryptionClient.encrypt passes plaintext straight to wasmEncrypt with no null guard (wasm-inline.ts:205-218). The Node operations short-circuit null (encrypt.ts:63, decrypt.ts:51). The pending changeset documents that protect-ffi otherwise turns null into a real SteVec ciphertext.
- Consequence: Rows written from the edge store an encrypted value instead of SQL NULL, so `IS NULL` filters and nullable-field semantics silently diverge between rows written by WASM and rows written by Node. The same app sees different data depending on runtime, and nothing errors.
- Affects: @cipherstash/stack/wasm-inline subpath, EQL SQL bundle / postgres-eql image (data at rest)
- Evidence: `packages/stack/src/wasm-inline.ts:108-260`; `packages/stack/src/encryption/operations/encrypt.ts:63`; `.changeset/restore-null-guards-in-encryption-ops.md:7`
- Existing verification: Deno round-trip test covers a non-null string only. [ran_passed]
- Missing verification: No test of encrypt(null)/decrypt(null) on the wasm-inline client.; No cross-runtime test that WASM-written payloads (including cast_as normalisation by stack's toEqlCastAs rather than protect-ffi's internal normaliser) are identical in shape to Node-written ones.
- Mitigation: Mirror the Node null short-circuit in WasmEncryptionClient.encrypt/decrypt, or remove null from WasmPlaintext. Add a parity test that compares WASM and Node payload metadata for each cast_as.

**FS-3 · Consumers' TypeScript resolves protect-ffi WASM types for stack's main-entry declarations** (medium impact, plausible)

- Trigger: A TypeScript app using moduleResolution 'bundler' (or other resolution without the `node` condition) upgrades to this stack release.
- Mechanism: stack's public types are derived from protect-ffi (types.ts:7-13, `Client = Awaited<ReturnType<typeof newClient>>` at line 29). Stack's own tsconfig needed customConditions ['node'] because under bundler resolution protect-ffi 0.24 otherwise resolves to WASM types with a different newClient signature (tsconfig.json:18-24). That setting fixes stack's build only; consumers resolve the emitted .d.ts with their own conditions.
- Consequence: Consumers may see compile errors or silently different types (Client, Encrypted, JsPlaintext) after a minor upgrade. The failure is mostly loud, at build time, and recoverable by pinning.
- Affects: @cipherstash/stack main (Node) entry, Downstream TypeScript consumers of @cipherstash/stack
- Evidence: `packages/stack/tsconfig.json:18-24`; `packages/stack/src/types.ts:7-38`
- Missing verification: No consumer fixture type-checks the packed stack against bundler resolution without customConditions.
- Mitigation: Add a type-check fixture that installs the packed tarball under moduleResolution 'bundler' and 'node16'. Alternatively, import Node types from an unconditional protect-ffi subpath or inline the needed types.

**FS-4 · CLI/wizard auth 0.36 -> 0.38 upgrade breaks login or token fetch** (medium impact, speculative)

- Trigger: A user runs `stash auth login`, `stash init` or the wizard after the CLI/wizard are next published with auth 0.38.0.
- Mechanism: The catalog moves @cipherstash/auth from 0.36.0 to 0.38.0 (pnpm-workspace.yaml), which cli and wizard consume via catalog:repo. They call the native default export (login.ts, fetch-prompt.ts `const { AutoStrategy } = auth`). These are 0.x minor bumps whose API changes are unknown here. The wizard unit test mocks @cipherstash/auth.
- Consequence: CLI login or wizard prompt fetching fails for users. The failure is loud, but onboarding is blocked until a patched release ships.
- Affects: stash CLI (packages/cli) and wizard
- Evidence: `pnpm-workspace.yaml:7-20`; `packages/cli/src/commands/auth/login.ts:1`; `packages/wizard/src/agent/fetch-prompt.ts:1-6`; `packages/wizard/src/__tests__/prerequisites.test.ts:8`
- Existing verification: Run Tests jobs (which include the CLI E2E step) passed; whether they exercise real auth login is not visible. [ran_passed]
- Missing verification: No evidence of a real-auth login exercise with 0.38.0 on each platform binary.; No changeset or CHANGELOG entry for cli/wizard records the dependency change.
- Mitigation: Review the auth 0.37/0.38 changelog for changes to the default export and AutoStrategy, smoke-test `stash auth login`, and add changesets for cli and wizard.

**FS-5 · Hand-edited 0.18.0 version conflicts with changesets release flow** (low impact, plausible)

- Trigger: The next release run of `changeset version`/`changeset publish` on main.
- Mechanism: packages/stack/package.json now says 0.18.0 while a pending minor changeset for stack already exists. Changesets would bump from 0.18.0 to 0.19.0, so 0.18.0 may never be published. The wasm-inline feature and protect-ffi bump have no changeset, so the CHANGELOG would not mention them.
- Consequence: Version skips and an incomplete changelog for a release that changes the native dependency. Customers cannot tell from release notes that protect-ffi changed. Low, recoverable impact.
- Affects: @cipherstash/stack main (Node) entry, Release pipeline (changesets)
- Evidence: `packages/stack/package.json:3`; `package.json:52`; `.changeset/restore-null-guards-in-encryption-ops.md:1-3`; signal `co_change.omitted_co_changes[1]`
- Missing verification: No dry-run of `changeset version` on this branch.
- Mitigation: Revert the manual version bump and add changesets for stack (wasm-inline + protect-ffi 0.24), cli and wizard.

### Recommended controls

- Before release, confirm from the protect-ffi 0.24.0 notes that the Node API and payload/search-term format are unchanged. Run a fixture test that decrypts and queries data written by 0.23.0 against EQL 2.3.1. (compatibility_check; FS-1, VG-1)
- Add a null short-circuit to the wasm-inline encrypt/decrypt (or drop null from WasmPlaintext) with a unit test. Add a WASM-vs-Node payload-shape parity test covering every cast_as. (test; FS-2, VG-2)
- Add a packed-tarball consumer type-check (bundler and node16 resolution, skipLibCheck off). (test; FS-3, VG-3)
- Review the auth 0.36->0.38 changes affecting the default export and AutoStrategy, and smoke-test `stash auth login`. (review_focus; FS-4, VG-4)
- Replace the manual version bump with changesets for stack, cli and wizard so the release notes record the native dependency change. (documentation; FS-5)

### What this assessment could not see

- The contents and changelogs of @cipherstash/protect-ffi 0.24.0 and @cipherstash/auth 0.38.0 were unavailable (no node_modules, no network). Whether FS-1 and FS-4 actually occur cannot be determined; the PR's assertion that the Node API is unchanged is an unverified claim.
- CI results are job-level conclusions only, with no logs. Cannot confirm which tests ran inside each job (e.g. that cjs-require.test.ts or wasm-inline-normalize.test.ts executed), or that the Deno test was not skipped. The secret-presence assertion step makes a skip unlikely.
- pnpm-lock.yaml changes were skimmed, not audited line by line. The lockfile also drops `libc: [glibc]` markers on unrelated @img/sharp entries, which suggests a different pnpm version regenerated it. Unrelated transitive resolution changes may be missed.
- Did not verify whether pnpm 10 runs the `prebuild` lifecycle script that replaces tsup's clean:true, or whether bundling zod/@byteslice/result into the main entries affects consumers that combine stack's exported zod schemas with their own zod instance. Possible stale dist artefacts in local publishes, or zod instance-mismatch issues, are not assessed. CI release builds from a fresh checkout.
- The PR description is partly stale relative to the code: it says raw re-exports exist (the code says they intentionally do not) and that auth is 0.37.0-alpha.8 (the catalog is 0.38.0). The PR description was treated as claims only.

_Inputs unavailable: architecture_docs, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
