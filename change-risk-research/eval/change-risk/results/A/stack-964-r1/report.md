## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `17c9fadd51..c034508d74`

Build-config change to the published @cipherstash/stack package: the type declarations for the ESM-only `./wasm-inline` entry are now emitted by the main dual-format tsup config, so they share the column-class declaration chunk with `./eql/v3`, `./v3` and `./adapter-kit`. The JS bundle for wasm-inline is unchanged. The result is that tables authored from either entry now typecheck against the other entry and against adapter `schemas` types. Shipped agent skills (copied into customer repos by `stash`) are rewritten to recommend sharing one schema module across entries, and a text guard that enforced the old rule is deleted and replaced by new dist-level type gates that run in CI. There is no runtime code change apart from an error-message string. I found no `instanceof` checks on stack classes in any package source, so the runtime cross-entry use the docs now encourage still goes through the existing structural checks. The main risk is the published `dist/wasm-inline.d.ts` shape, a type-level contract. The new gates cover it and CI runs them, but I did not see a result. Smaller risks are doc and version skew in shipped skills and a contradictory pending changeset. Impact is medium and verification is medium. A focused review of the emitted declarations is recommended.

### Failure scenarios

**FS-1 · Published dist/wasm-inline.d.ts is incomplete or wrong after moving DTS emission into the dual-format config** (medium impact, plausible)

- Trigger: Release build of @cipherstash/stack with the new tsup config. The DTS rollup over 11 entries re-partitions shared chunks, and the wasm-inline entry's declarations (WasmEncryptionClient, Encryption overloads, Wasm* types, re-exports of `@/eql/v3`, external `@cipherstash/protect-ffi/wasm-inline` and `@cipherstash/auth/wasm-inline` types) are now emitted alongside the native entries.
- Mechanism: Before, `dist/wasm-inline.d.ts` came from a separate self-contained DTS pass (base tsup.config.ts). Now it is emitted by the main config (`dts: { entry: [...mainEntry, 'src/wasm-inline.ts'] }`, tsup.config.ts:52) and imports shared chunks. Any difference in how that pass resolves or names the wasm-inline exports, such as a declaration landing in a chunk the `.d.ts` does not re-export, or chunk-name changes, alters the type surface that edge consumers resolve through `exports['./wasm-inline'].import.types`. The JS stays on the old pass (`dts: false`, :78), so types and JS now come from two different builds.
- Consequence: Edge and Deno/Workers/Supabase consumers on TypeScript get compile errors or missing or `any`-widened types after upgrading. A widened schema type would weaken typed `encryptQuery`/domain checks without a runtime signal. Fixing it needs a new npm release.
- Affects: @cipherstash/stack build (tsup.config.ts) and published dist declarations, @cipherstash/stack `./wasm-inline` export (types condition)
- Evidence: `packages/stack/tsup.config.ts:29-52`; `packages/stack/tsup.config.ts:70-82`; `packages/stack/package.json:175-180`; `packages/stack/dist-types/wasm-inline-type-identity.ts:75-114`; `packages/stack/dist-types/node16/wasm-inline.mts:89-99`; `.github/workflows/tests.yml:254-255`
- Existing verification: dist-types/wasm-inline-type-identity.ts and dist-types/node16/wasm-inline.mts typecheck the emitted declarations, including cross-entry assignability in both directions and pre-existing schema/config shape probes, via `test:types:dist` in tests.yml. [exists_not_run]
- Missing verification: No CI result was supplied for `test:types:dist` at head.; No comparison of the exported symbol list of dist/wasm-inline.d.ts at base vs head (e.g. `pnpm pack` and a diff of the public declaration surface).
- Mitigation: Before publishing, build at base and head and diff the exported names and types of `dist/wasm-inline.d.ts`, or run an API-extractor-style report, and confirm the `test:types:dist` step is green on this commit.

**FS-2 · Shipped skills recommend cross-entry schemas to customers whose installed @cipherstash/stack predates the fix** (low impact, plausible)

- Trigger: A customer upgrades `stash` (which carries skills/ and copies them into the repo) but keeps an older `@cipherstash/stack`, which the optional peer range `>=1.0.0-rc.0` allows. Their coding agent then follows the new example that authors `schemas` from `@cipherstash/stack/wasm-inline` for `encryptedSupabase`.
- Mechanism: skills/stash-edge/SKILL.md:384-450 and the other three skills now present wasm-inline authoring as correct. The fallback note refers only to 'older versions' and 'a version predating that fix' and names no version, so neither an agent nor a human can check applicability.
- Consequence: `tsc` fails with the private-member error on older stacks, and the agent may reach for `as any`, which the skills themselves warn against. The failure is loud and compile-time. Runtime behaviour is unaffected because adapters probe columns structurally.
- Affects: Shipped agent skills in the `stash` package (copied into customer repos), @cipherstash/stack-supabase `schemas` typing (V3Schemas)
- Evidence: `packages/cli/package.json:69-71`; `skills/stash-edge/SKILL.md:384-450`; `packages/stack-supabase/src/column-map.ts:68`; `git -C repo grep -n -E "instanceof [A-Z][A-Za-z0-9_]*" c034508d -- 'packages/*/src' | grep -v -E 'instanceof (Error|Date|Uint8Array|Array|Map|Set|RegExp|Promise|TypeError|Buffer|Object|ArrayBuffer|BigInt|Function|URL|Response|Request)'`
- Missing verification: No check ties the skill text to a minimum @cipherstash/stack version.
- Mitigation: Name the first @cipherstash/stack version containing the fix in the 'older versions' notes once it is known, or raise the stash peer floor.

**FS-3 · Pending changeset contradicts the new guidance in the same release's changelog** (low impact, observed in the code)

- Trigger: The next release consumes both `.changeset/supabase-docs-wasm-inline-entry.md` and `.changeset/wasm-inline-type-identity.md`.
- Mechanism: supabase-docs-wasm-inline-entry.md:49-58 states that wasm-inline-authored schemas do not compile with `encryptedSupabase`, that schemas must come from `eql/v3`, and that a guard (`skills-supabase-edge-schema-entry.test.mjs`) enforces this. This change deletes that guard and reverses the rule, but leaves that changeset unedited.
- Consequence: Published CHANGELOGs for stash and @cipherstash/stack-supabase carry two contradictory statements and reference a test that no longer exists, which confuses readers. This is documentation only.
- Affects: Release notes generated from pending changesets
- Evidence: `.changeset/supabase-docs-wasm-inline-entry.md:49-58`; `.changeset/wasm-inline-type-identity.md:1-18`; `scripts/__tests__/skills-supabase-edge-schema-entry.test.mjs:1-40` (base)
- Mitigation: Amend the earlier pending changeset, or note in the new one that it supersedes that guidance.

### Recommended controls

- Build @cipherstash/stack at base and head and diff `dist/wasm-inline.d.ts` (plus the chunks it references) for exported names and types, or run `pnpm pack` and inspect the tarball, before publishing. (compatibility_check; FS-1, VG-2)
- Confirm the 'Typecheck (stack — emitted declarations, not source)' CI step ran and passed on this head commit. (review_focus; FS-1, VG-1)
- State the minimum @cipherstash/stack version in the skills' 'older versions' notes, and amend or supersede `.changeset/supabase-docs-wasm-inline-entry.md` so release notes do not contradict each other. (documentation; FS-2, FS-3)

### What this assessment could not see

- I could not run the build or `test:types:dist`; there is no node_modules or dist in the checkout and no network access, and no CI results were supplied. Whether the emitted declarations are correct is inferred from the config and the gate source, not observed.
- Runtime safety of the newly encouraged cross-entry usage was checked only by grepping `packages/*/src` for `instanceof` / constructor-identity checks (none found) and reading `isV3ColumnLike`. Customer-side or example code was not examined. An identity check in code outside packages/*/src would not have been found.
- Skill markdown changes were read, not executed. Snippets in skills are not compiled by any gate I found. Snippet correctness is assumed from the type gates, not checked directly.
- Release workflow and the deployment/publishing context were not reviewed beyond the changeset files. I cannot say which pending changesets ship together or when.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
