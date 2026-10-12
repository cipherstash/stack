## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `17c9fadd51..c034508d74`

The change moves the TypeScript declaration emit for the `@cipherstash/stack/wasm-inline` entry out of its own tsup DTS pass and into the main dual-format config, so the wasm-inline declarations share the column-class declaration chunk with `./eql/v3` and `./adapter-kit`. That turns cross-entry schema authoring (a wasm-inline-authored table passed to `encryptedSupabase`, Drizzle, Prisma Next or the native `Encryption`, and vice versa) from a compile error into valid TypeScript. JS emission is unchanged: both configs keep their JS entry lists, so runtime behaviour, encryption and payloads are not touched, and the runtime paths that consume schemas already probe structurally. The rest is a new dist-level type gate (run in CI via test:types:dist), tightened test assertions, comment edits, a CI-only hard failure for an unbuilt logger gate, deletion of a docs guard that asserted the old compile error, and rewritten customer-shipped skills that now recommend sharing one schema module across entries. The material risks are a mis-shaped published `dist/wasm-inline.d.ts` (irreversible once published, but gated) and shipped guidance that overstates where cross-entry sharing works (version skew, CommonJS projects). Both are loud (compile or load errors), not silent. Verdict: focused review of the emitted declaration surface and the skill wording.

### Failure scenarios

**FS-1 · Published dist/wasm-inline.d.ts differs from the previous surface for edge consumers** (medium impact, plausible)

- Trigger: The main config's dual-format DTS rollup emits wasm-inline declarations that differ from the old standalone pass (for example a wasm-only type moved to or renamed inside a shared chunk, a declaration resolved differently under the main config, or chunk references that do not resolve in the tarball).
- Mechanism: Before, `dist/wasm-inline.d.ts` was a self-contained rollup from its own pass. Now it comes from the main config's pass (tsup.config.ts:52) alongside ten other entries and references shared declaration chunks, while the wasm config emits JS only (tsup.config.ts:78). Any difference in exported names or shapes reaches every Workers/Deno/Bun/Supabase Edge TypeScript consumer of `./wasm-inline`.
- Consequence: Type errors or missing exports for edge TypeScript users after upgrading a patch release. Runtime is unaffected. A published release cannot be withdrawn, so a fix needs a new release.
- Affects: @cipherstash/stack build (tsup.config.ts) and published dist/*.d.ts, @cipherstash/stack/wasm-inline export (types)
- Evidence: `packages/stack/tsup.config.ts:52`; `packages/stack/tsup.config.ts:70-83`; `packages/stack/package.json:175-180`; `packages/stack/dist-types/wasm-inline-type-identity.ts:75-114`; `packages/stack/dist-types/node16/wasm-inline.mts:89-99`; `.github/workflows/tests.yml:254-255`
- Existing verification: dist-types/wasm-inline-type-identity.ts and node16/wasm-inline.mts compile against built dist, covering cross-entry assignability plus the pre-existing wasmSchemaShapes and wasmConfigShapes probes. CI runs them via test:types:dist. [exists_not_run]
- Missing verification: A diff of the export list of dist/wasm-inline.d.ts at base vs head (e.g. via api-extractor or by listing exported names).; An `npm pack` check that every declaration chunk referenced by wasm-inline.d.ts is in the tarball (the gates resolve dist/ in-tree, not the packed tarball).
- Mitigation: Before release, build at base and head and compare the exported symbols of dist/wasm-inline.d.ts. Install the packed tarball into a scratch ESM project and typecheck a wasm-inline import.

**FS-2 · Shipped skills promise cross-entry schema sharing where it still fails (version skew, CommonJS projects)** (low impact, plausible)

- Trigger: A customer's coding agent follows the updated skill while the installed @cipherstash/stack predates this fix (skills ship in the separately installed `stash` tarball), or while their Node server compiles or runs as CommonJS.
- Mechanism: The skills now say one schema.ts can serve a Node server and an Edge Function in both directions. `./wasm-inline` has only an `import` branch, so a CommonJS server cannot load a schema module that imports it. Under node16 resolution, CommonJS resolves `./eql/v3` and `./v3` to the separately emitted `.d.cts` declarations, which do not share identity with the ESM `.d.ts` set. On older stack versions the old TS2322 still occurs. The text-level guard that policed these snippets was deleted, and nothing type-checks the skills.
- Consequence: A customer's build fails with ERR_REQUIRE_ESM or TS2322 after following first-party guidance. An agent may 'fix' it with `as any`, which the skills themselves warn against. Loud, not silent: no wrong data or plaintext path, because runtime detection is structural.
- Affects: Shipped agent skills (stash npm tarball, copied into customer repos by stash init), @cipherstash/stack/wasm-inline export (types)
- Evidence: `packages/stack/package.json:175-180`; `skills/stash-edge/SKILL.md:384-405`; `skills/stash-supabase/SKILL.md:376-388`; `skills/stash-encryption/SKILL.md:526`; `scripts/__tests__/skills-supabase-edge-schema-entry.test.mjs:31-34` (base); `AGENTS.md`; `packages/stack/dist-types/node16/tsconfig.json:7-11` (inferred)
- Existing verification: The new gates check ESM-mode cross-entry identity only. No .cts probe covers wasm-inline (the entry is ESM-only). [exists_not_run]
- Missing verification: Nothing checks skill snippets against the declared minimum @cipherstash/stack version.; No statement in the skills that the shared-module pattern needs an ESM project.
- Mitigation: In the skill text, name the minimum @cipherstash/stack version that carries the fix and state that sharing requires the consuming project to be ESM. Keep the upgrade/fallback notes already added.

### Recommended controls

- Build at base and head and diff the exported names and signatures of dist/wasm-inline.d.ts. Confirm test:types:dist passes in CI on this head. (compatibility_check; FS-1, VG-1, VG-2)
- Pack @cipherstash/stack and typecheck a scratch ESM consumer that imports encryptedTable/types from ./wasm-inline and passes the table to ./v3 Encryption, so chunk references are verified in the tarball. (test; FS-1, VG-2)
- In stash-edge, stash-supabase, stash-encryption and stash-managed-platforms, state the minimum @cipherstash/stack version for cross-entry schemas and that the shared module and its consumers must be ESM. (documentation; FS-2, VG-3)
- A reviewer should read tsup.config.ts (main dts.entry and wasm config dts:false) together with the emitted dist layout, and confirm no other DTS pass still emits a column-class copy. (review_focus; FS-1)

### What this assessment could not see

- Could not build or run anything: no node_modules and no network. Statements about the emitted .d.ts layout come from the config and the change's own comments, not from built output. FS-1 cannot be confirmed or ruled out, and verification confidence is capped at medium.
- No CI results, PR body or CODEOWNERS were available. The assessment does not know whether the new gates passed on this head or who should review.
- The skill-doc changes were read in full for stash-edge, stash-encryption and stash-managed-platforms. The stash-supabase diff was read for the added sections, and its later hunk (around the v2 rejection example) was only skimmed. A wording issue in the skimmed hunk could be missed. It is docs only.
- Whether importing @cipherstash/stack/wasm-inline in a Node process has import-time costs or side effects (WASM blob decode) was not established. That matters if Node servers start importing schema modules authored from it. A possible startup or memory cost for the recommended shared-module pattern is unassessed.

_Inputs unavailable: ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
