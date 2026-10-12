## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `17c9fadd51..c034508d74`

Build-config fix: @cipherstash/stack's wasm-inline type declarations now come from the main tsup config's DTS pass (dts: false on the wasm-inline config), so ./wasm-inline, ./eql/v3, ./v3 and ./adapter-kit share one declaration of EncryptedV3Column. A wasm-inline-authored table can now be passed to the native Encryption, encryptedSupabase and the other adapters, and the reverse, without a compile error. Runtime JS is unchanged. The wasm-inline.js bundle and each CJS entry still carry their own runtime copy of the class. That is now only a hazard for code that uses instanceof, and the first-party code at head does not (it probes structurally and fails closed). Two dist-types gates pin the new type identity. Both run in the CI job 'Run Tests (Node 22/24)', which passed. A text guard over shipped skills was deleted, and four shipped skills were rewritten to recommend cross-entry schema sharing. The main residual risks: (1) the skills ship in the stash tarball and say 'upgrade' without naming a version, so a customer on an older @cipherstash/stack follows a now-recommended pattern and gets a compile error; (2) the type system now asserts an identity the runtime does not have, so any future instanceof check on these classes would silently fail; (3) Deno edge consumers' type resolution of the re-chunked .d.ts is not exercised by any gate. All failures are compile-time or need a future regression. Impact is medium at most.

### Failure scenarios

**FS-1 · Shipped skills recommend cross-entry schemas to customers whose installed @cipherstash/stack predates the fix** (low impact, plausible)

- Trigger: A customer has the new stash skills (the stash tarball is versioned separately) but an existing project still has an older @cipherstash/stack installed. Their coding agent follows the new stash-edge fence and authors schemas from @cipherstash/stack/wasm-inline for encryptedSupabase or native Encryption.
- Mechanism: The skills now present cross-entry pairing as the normal path (stash-edge SKILL.md:441-446). The fallback only says 'on older versions'/'upgrade' and gives no version number (stash-edge SKILL.md:405-424, 448; stash-encryption SKILL.md:528). The deleted guard test was the only check over shipped snippets. Agents reading 'it works at runtime' plus a TS2322 error may reach for a cast.
- Consequence: tsc fails in the customer project with TS2322 'separate declarations of a private property columnName'. That is a loud, recoverable build failure. A worse outcome is an agent silencing it with as any/as never, which the old skills explicitly warned against. The new text still discourages that.
- Affects: Shipped agent skills (stash tarball), @cipherstash/stack build (tsup.config.ts) and published dist/*.d.ts
- Evidence: `skills/stash-edge/SKILL.md:405-448`; `skills/stash-encryption/SKILL.md:525-528`; `scripts/__tests__/skills-supabase-edge-schema-entry.test.mjs:126-159` (base); `packages/cli/src/commands/init/lib/write-context.ts:122` (inferred)
- Existing verification: dist-types gates prove the new pairing compiles against this head's build only, not against older installed versions [ran_passed]
- Missing verification: No check ties the skills' claims to a minimum @cipherstash/stack version; Nothing typechecks skill snippets
- Mitigation: Name the first @cipherstash/stack version carrying the fix in the four skills, for example 'requires @cipherstash/stack >= <next patch>'. Optionally keep the eql/v3-authoring example first for the Supabase adapter path.

**FS-2 · Types now assert one EncryptedV3Column while runtime has several copies, so a future instanceof check silently misclassifies wasm-authored tables** (medium impact, speculative)

- Trigger: Future first-party or customer code adds `x instanceof EncryptedV3Column` (or a module-local brand) on a path that receives schemas. A wasm-inline-authored table now passes the compiler, which it did not before.
- Mechanism: tsup still emits separate runtime class copies (wasm-inline.js is a separate esbuild run, and CJS entries do not split) per tsup.config.ts:70-83 and the adapter-kit.ts:31-40 comment. The compile error used to stop TS users from passing wasm-authored tables across entries. That error is gone. The historical consequence of a failed identity check in the Supabase adapter was an empty v3Columns map and plaintext filter operands in PostgREST URLs.
- Consequence: If such a check were added, filter operands could silently be treated as plaintext or columns skipped. No such check exists at head: column-map.ts probes structurally, fails closed (column-map.ts:189) and has tests using wasm-authored table mocks.
- Affects: @cipherstash/stack-supabase (schemas option, ColumnMap), Drizzle / Prisma Next adapters and native Encryption, @cipherstash/stack build (tsup.config.ts) and published dist/*.d.ts
- Evidence: `packages/stack/src/adapter-kit.ts:31-40`; `packages/stack-supabase/src/column-map.ts:68`; `packages/stack-supabase/src/column-map.ts:189`; `Grep 'instanceof [A-Z]\w*(Column|Table|Field)\b' over packages/ (excluding __tests__)`; `packages/stack-supabase/__tests__/helpers/supabase-mock.ts:216-230`
- Existing verification: supabase-schema-builder.test.ts structural-recognition and fail-closed tests using wasmAuthoredV3Table object-literal mocks [exists_not_run]; Run Tests (Node 22/24) job, which includes the stack-supabase unit tests, concluded success [ran_passed]
- Missing verification: No lint or test forbids instanceof on EncryptedV3Column across packages; the rule is a code comment only; No dist-level runtime test passes a real wasm-inline.js-built table to the native client or adapter
- Mitigation: Add a lint (Biome/GritQL or a grep test) that rejects instanceof EncryptedV3Column / EncryptedV3Table in packages/*/src. Optionally add a runtime test over a built dist that pairs a wasm-inline table with encryptedSupabase.

**FS-3 · Re-chunked wasm-inline declarations fail to resolve or degrade to any for edge type-checkers** (low impact, speculative)

- Trigger: An edge consumer (Deno check, Workers with a bundler tsconfig) resolves dist/wasm-inline.d.ts, which now imports shared chunk files from the main DTS pass instead of being self-contained.
- Mechanism: tsup.config.ts:52 adds src/wasm-inline.ts to the main config's dts entry list, so rollup-plugin-dts splits shared declarations into chunks. Chunks shared with Node-only entries could carry imports the edge consumer cannot resolve. The built output was not inspected.
- Consequence: A compile error or silently any-typed exports for edge TS users. Runtime is unaffected.
- Affects: @cipherstash/stack build (tsup.config.ts) and published dist/*.d.ts, Edge TypeScript consumers (Deno, Workers, Bun, Supabase Edge) of @cipherstash/stack/wasm-inline
- Evidence: `packages/stack/tsup.config.ts:52`; `.github/workflows/tests.yml:254-255`; `e2e/wasm/deno.json:8-9`
- Existing verification: test:types:dist compiles wasm-inline imports under moduleResolution bundler and node16 against the built dist [ran_passed]
- Missing verification: Deno type-check of the wasm-inline entry (e2e/wasm runs deno test --no-check)
- Mitigation: Inspect the packed dist/wasm-inline.d.ts and its chunk imports, or run `deno check` on a minimal wasm-inline schema before release.

### Recommended controls

- State the minimum @cipherstash/stack version in the four rewritten skills. (documentation; FS-1, VG-1)
- Add a lint or grep test forbidding instanceof EncryptedV3Column/EncryptedV3Table in package src. (test; FS-2, VG-2)
- Before publish, pack @cipherstash/stack and inspect dist/wasm-inline.d.ts imports; optionally run deno check over a wasm-inline schema module. (compatibility_check; FS-3, VG-3)
- Reviewer should confirm that the tsup dts entry list stays derived from mainEntry plus wasm-inline, and that no future config re-enables dts on the wasm-inline config. (review_focus; FS-3)

### What this assessment could not see

- No build or test was run locally (no node_modules, no network), so the emitted declarations were not inspected. FS-3 remains speculative. The type-identity claim relies on CI job success.
- ci.json gives job-level conclusions only. Attributing the dist-types gate to 'Run Tests (Node 22/24)' comes from reading tests.yml at head, not from step logs. ran_passed for the dist-types gate is inferred from the job conclusion.
- The PR claims the gates were watched failing on main's config. This could not be reproduced. The gates' sensitivity is taken from the PR description, not verified.
- Drizzle and Prisma Next schema typings and their runtime handling of tables were checked only by grepping for instanceof. AC-6 is 'likely' rather than confirmed.
- Skills diffs were read in full. The supabase test edits (message pinning) were skimmed. Minor test-strength changes were not assessed in depth.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
