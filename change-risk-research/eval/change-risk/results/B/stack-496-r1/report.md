## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `b9c4fe5598..c39e895ca9`

This change adds a new ESM-only `@cipherstash/stack/wasm-inline` subpath for Deno and edge runtimes, a Deno CI smoke test and a Supabase example. Most of the release risk is in what ships with it rather than in the new subpath. The main Node entry of @cipherstash/stack moves from protect-ffi 0.23.0 to 0.24.0. The previous protect-ffi bump (0.23) brought breaking payload changes and was paired with an EQL bump. This one comes with no changeset, no EQL lockstep change and no upstream changelog in the evidence. The package version is hand-edited to 0.18.0 while a minor changeset is still pending, so the release tooling may publish 0.19.0. That would leave the new example's `^0.18.0` import with nothing to resolve to. The new WASM client keeps the same names as the Node client (`Encryption`, `encrypt`, `decrypt`) but follows a different contract: it throws instead of returning a Result, and it has no null short-circuit. The CLI and wizard move to auth 0.38.0, which ships its native bindings differently. No CI results were available, so every test is exists_not_run.

### Failure scenarios

**FS-1 · protect-ffi 0.24 bump in the main Node entry ships without EQL lockstep or payload-compatibility evidence** (high impact, plausible)

- Trigger: A customer upgrades @cipherstash/stack to the release built from this change and keeps EQL eql-2.3.1 installed, or reads data written by 0.17.x.
- Mechanism: packages/stack/package.json:217 moves protect-ffi from 0.23.0 to 0.24.0 for all main-entry operations. The repo pins EQL in two places, each with a comment saying it must move in lockstep with protect-ffi (tests.yml:21-22, cli installer/index.ts:5-7). Neither changed. The previous bump (0.23) changed payload shape and SteVec encoding defaults and came with an EQL bump (CHANGELOG.md:7-17). Upstream 0.24 release notes were not available. This change was framed as a WASM feature, and it adds no changeset that would describe the bump.
- Consequence: If 0.24 changes payload or search-term encoding, newly written payloads or query terms may not match what the installed eql_v2 functions or older data expect. Encrypted searches can then silently return no or wrong rows, or reads of existing data can fail. The bump would also reach customers with no CHANGELOG entry.
- Affects: @cipherstash/stack (published npm package, main Node entries), EQL SQL bundle installed by the stash CLI and used in CI (eql-2.3.1), Customer data at rest and customer TypeScript builds using @cipherstash/stack
- Evidence: `packages/stack/package.json:216-217`; `.github/workflows/tests.yml:21-22`; `packages/cli/src/installer/index.ts:5-7`; `packages/stack/CHANGELOG.md:7-17`; `AGENTS.md:179-198`
- Existing verification: Stack vitest suite, including backward-compat.test.ts, encrypt-query*.test.ts and searchable-json-pg.test.ts, runs in CI against ghcr.io/cipherstash/postgres-eql:17-2.3.1 with live credentials. [exists_not_run]
- Missing verification: Upstream protect-ffi 0.23.0 -> 0.24.0 changelog reviewed for payload, search-term or config-version changes; A green CI run of the stack integration suite on this head against eql-2.3.1; A test that decrypts and queries payloads written by protect-ffi 0.23 using 0.24
- Mitigation: Review the protect-ffi 0.24 release notes. Either confirm that eql-2.3.1 is still the matching bundle and update the lockstep comments, or bump EQL in the CLI and CI together. Add a changeset that names the protect-ffi bump. Consider splitting the dependency bump out of the WASM feature PR.

**FS-2 · Hand-set 0.18.0 plus a pending minor changeset publishes an unexpected version and drops the CHANGELOG entry** (medium impact, plausible)

- Trigger: changesets/action runs `changeset version` on main after this merges.
- Mechanism: package.json:3 is set to 0.18.0 by hand. .changeset/restore-null-guards-in-encryption-ops.md still declares a minor bump for @cipherstash/stack, and CHANGELOG.md's latest entry is 0.17.0. Changesets bumps from the current version, which gives 0.19.0. No changeset is added for wasm-inline or the dependency bumps, although AGENTS.md:179-198 requires one. The Supabase example imports `npm:@cipherstash/stack@^0.18.0/wasm-inline`, and for a 0.x version that caret allows only 0.18.x.
- Consequence: 0.18.0 is never published and the release comes out as 0.19.0. The example and README instructions then fail to resolve the package, and neither the new subpath nor the protect-ffi and auth bumps appear in the CHANGELOG. Publishing cannot be undone, so fixing this needs a further release.
- Affects: Release pipeline (changesets/action -> pnpm run release), @cipherstash/stack (published npm package, main Node entries), examples/supabase-worker
- Evidence: `packages/stack/package.json:3`; `.changeset/restore-null-guards-in-encryption-ops.md:1-3`; `AGENTS.md:179-198`; `examples/supabase-worker/supabase/functions/cipherstash-roundtrip/index.ts:21`; `.github/workflows/release.yml:53-56`
- Missing verification: A dry run of `changeset version` on this head to see which version it produces
- Mitigation: Revert the hand edit to version, add a changeset covering wasm-inline and the dependency bumps, and set the example's specifier to whatever version changesets will produce.

**FS-3 · WASM client reuses the Node API names with a different contract: it throws instead of returning a Result, and encrypts null** (medium impact, plausible)

- Trigger: A developer ports Node code to the WASM entry, or a plain JS or Deno caller (no type check) passes null or reads `.data` and `.failure`.
- Mechanism: wasm-inline.ts:205-224: encrypt/decrypt return the raw protect-ffi value or throw. AGENTS.md:126 says the `{ data } | { failure }` result shape is a contract of the Node entry. WasmPlaintext explicitly accepts null (wasm-inline.ts:108-114) and encrypt has no null guard. The Node EncryptOperation returns null for a null plaintext (encrypt.ts:63-70), and the pending changeset describes null otherwise being encrypted into a real ciphertext.
- Consequence: For an untyped caller, `const { data } = await client.encrypt(v)` yields undefined, which can be written to the database as NULL instead of a ciphertext, a silent data loss. A nullable field is stored as an encrypted null rather than SQL NULL, so IS NULL semantics differ between rows written from the edge and rows written from Node.
- Affects: @cipherstash/stack/wasm-inline subpath, Customer data at rest and customer TypeScript builds using @cipherstash/stack
- Evidence: `packages/stack/src/wasm-inline.ts:205-224`; `packages/stack/src/wasm-inline.ts:108-114`; `packages/stack/src/encryption/operations/encrypt.ts:63-70`; `.changeset/restore-null-guards-in-encryption-ops.md:1-3`; `AGENTS.md:126-128`
- Existing verification: Deno round-trip test e2e/wasm/roundtrip.test.ts covers only a non-null string happy path, run with --no-check. [exists_not_run]
- Missing verification: A test of null input on the WASM entry; Documentation or naming that tells users the WASM client does not return Results
- Mitigation: Add a null short-circuit that matches the Node entry, and either return Result objects or document the divergent contract prominently in the subpath's README or type docs.

**FS-4 · Consumers using moduleResolution 'bundler' get protect-ffi's WASM typings behind stack's public types** (medium impact, plausible)

- Trigger: A customer project type-checks with moduleResolution bundler (for example the Next.js default) without a `node` custom condition, and upgrades stack.
- Mechanism: Stack's own tsconfig needed customConditions ['node'] to avoid resolving protect-ffi 0.24's WASM types (tsconfig.json:18-24). The published types re-export protect-ffi types (types.ts:7-13, 29, 38), and the d.ts files keep those imports external. A consumer resolver without the `node` condition will resolve them to the WASM declarations.
- Consequence: Type errors or silently different `Encrypted`/`Client` types in customer builds after a minor upgrade. This is loud at compile time and does not corrupt data.
- Affects: @cipherstash/stack (published npm package, main Node entries), Customer data at rest and customer TypeScript builds using @cipherstash/stack
- Evidence: `packages/stack/tsconfig.json:18-24`; `packages/stack/src/types.ts:7-38`
- Existing verification: packages/stack/__tests__/types.test-d.ts type tests run inside the stack tsconfig, which sets the node condition, so they do not exercise a consumer setup. [exists_not_run]
- Missing verification: Type-check of a fixture consumer with moduleResolution bundler and with node16 against the built dist
- Mitigation: Add a consumer type-check fixture (or attw-style check) for both resolution modes, or document the need for `customConditions: ['node']`.

**FS-5 · CLI and wizard login depend on a new auth 0.38 native-binding layout** (medium impact, speculative)

- Trigger: A customer installs or upgrades stash or @cipherstash/wizard and runs `stash auth login`, `stash init` or the wizard on a platform or package manager where the optional platform binary is not installed.
- Mechanism: auth 0.38 moved its platform bindings to optional peerDependencies (pnpm-lock). The CLI and wizard now list six platform packages as optionalDependencies through the catalog (pnpm-workspace.yaml:14-20). Platforms that are not listed, such as linux-arm64-musl and win32-arm64, have no binding. The auth API changes from 0.36 to 0.38 are unknown, and the wizard's test mocks @cipherstash/auth entirely.
- Consequence: The login and credential commands fail at module load on platforms where the binding is missing. The failure is loud and fixed by a patch release, but it blocks onboarding.
- Affects: stash CLI (packages/cli) and @cipherstash/wizard
- Evidence: `pnpm-workspace.yaml:14-20`; `packages/cli/src/commands/auth/login.ts:1`; `pnpm-lock.yaml`
- Existing verification: CLI pty E2E suite (`turbo run test:e2e --filter stash`) in CI on linux-x64 only. [exists_not_run]
- Missing verification: Install and smoke test of the packed CLI on darwin and on linux-musl; Review of the auth 0.36 -> 0.38 default-export API changes
- Mitigation: Smoke test `stash auth login --help` from a packed tarball on each supported platform, and add a changeset for the CLI and wizard.

### Recommended controls

- Confirm from the protect-ffi 0.24 release notes that payload and search-term output are unchanged for eql-2.3.1. Otherwise bump EQL in the CLI installer and the CI image together. Require a green integration run on this head. (compatibility_check; FS-1, VG-1, VG-2)
- Revert the hand-edited version, add changesets for stack (wasm-inline and protect-ffi 0.24), the CLI and the wizard (auth 0.38), and align the example's version specifier. (documentation; FS-2, FS-1)
- Add a null short-circuit and a test for it on the WASM entry. Decide whether to return Result objects or document the different contract. (test; FS-3, VG-3)
- Add a consumer type-check fixture for moduleResolution bundler and node16 against the built dist. (test; FS-4, VG-4)
- Smoke test the packed CLI and wizard login on macOS and on linux-musl before publishing. (review_focus; FS-5)

### What this assessment could not see

- Upstream package contents (protect-ffi 0.24.0, auth 0.38.0) and their changelogs were not available offline. Whether FS-1 actually occurs, and the API compatibility in FS-5, could not be determined. Impact is stated as what would happen if they occur.
- No build or tests were run: no node_modules, no network, no credentials. All verification is exists_not_run. The generated dist/wasm-inline.d.ts and bundle contents (for example whether the .d.ts still imports Node protect-ffi types) were not inspected.
- pnpm-lock.yaml was skimmed. Besides the auth and protect-ffi entries, it drops libc fields from many platform packages, which suggests it was regenerated by a different pnpm version. Linux installs may fetch both the gnu and musl variants. Not assessed further.
- No PR description or deployment context was available. Commit messages were treated as untrusted. The intended release plan (for example whether 0.18.0 is meant to be published manually) is unknown.
- The workflow change was read. The new job exposes the same CS_* secrets as the existing jobs on pull_request; on fork PRs the new assertion step fails loudly. Not treated as a material scenario.

_Inputs unavailable: pr_description, ci_results, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
