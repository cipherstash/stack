## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `9bf2a56778..3e040fad4d`

Three fixes, shipped as patch bumps of @cipherstash/stack-supabase and @cipherstash/stack. (1) The Supabase v3 builder now rejects a free-text needle that is empty or shorter than the ngram token_length (3 codepoints). The check sits in the term resolver that every encrypted filter term goes through (matches, like/ilike, not, or, raw cs). This closes a real fail-open: a short needle blooms to nothing, so the filter matched every row and the caller decrypted the whole table. That also applied to update/delete filtered by such a needle. The fix is fail-closed. Its release risk is that existing callers who pass short or empty search terms now get an error instead of rows, in a patch release. (2) withLockContext on the Supabase builder now accepts a plain { identityClaim } as well as a LockContext. This is a type-only widening: the value is passed unchanged to encryption operations that already accept LockContextInput and resolve it with resolveLockContext. (3) EncryptionErrorTypes is now `as const`, which narrows EncryptionError['type'] from string to a union of literals. This is compile-time only, but it can stop some TypeScript consumers compiling after the upgrade. A tsconfig paths entry affects type tests only; no src file imports that specifier. No tests were run and no CI results were available. Impact is medium. A focused review should look at the user-visible behaviour change and the patch-level type narrowing. The v2 Supabase like/ilike paths stay unguarded; that was already true at base and is not caused by this change.

### Failure scenarios

**FS-1 · Short or empty search terms that used to return rows now return status 500 after a patch upgrade** (medium impact, plausible)

- Trigger: An application on encryptedSupabaseV3 passes an empty or 1-2 character term to matches(), like('%ab%'), ilike, or(), or not(col,'matches',...). Typical sources are search-as-you-type or an empty search box treated as 'show all'.
- Mechanism: assertTermQueryable now calls matchNeedleError for every freeTextSearch term (query-builder-v3.ts:504-512). like/ilike strip the surrounding % and delegate to matches (844-875). or() maps matches/contains to freeTextSearch (908-916). The thrown Error is caught in execute() and returned as status 500, or rethrown under throwOnError (query-builder.ts:428-458).
- Consequence: Search or listing features in consumer apps that used to return results (in fact the whole table) now fail with an error after a patch-level upgrade, or throw under throwOnError. The failure is loud and fail-closed, and no data is exposed or corrupted. Callers must add their own length check. Negated not(col,'matches','ab') used to return no rows and now errors.
- Affects: @cipherstash/stack-supabase v3 query builder (encryptedSupabaseV3), Applications using encryptedSupabaseV3 free-text search
- Evidence: `packages/stack-supabase/src/query-builder-v3.ts:498-512`; `packages/stack-supabase/src/query-builder-v3.ts:549-562`; `packages/stack-supabase/src/query-builder-v3.ts:844-875`; `packages/stack-supabase/src/query-builder-v3.ts:908-916`; `packages/stack/src/schema/match-defaults.ts:131-146`; `packages/stack-supabase/src/query-builder.ts:402-458`; `.changeset/v3-supabase-needle-lockcontext-errors.md:1-21`
- Existing verification: supabase-v3-builder.test.ts asserts matches('email','ab') returns status 500 with the guard message [exists_not_run]; match-needle-guard.test.ts covers matchNeedleError for empty, short, astral and NFD needles and non-string values [exists_not_run]
- Missing verification: No Supabase test for like('%ab%') / ilike, or() string and structured conditions, not(col,'matches',...), raw filter(col,'cs',...), or an empty-string needle; No test or note on the throwOnError path for the new rejection; No test results seen; tests were not run (no node_modules, no CI)
- Mitigation: State clearly in the release notes that empty and short free-text terms now error, and consider a minor bump rather than patch. Document the threshold so callers can skip the filter for short terms (matchNeedleError is exported from adapter-kit). Add the missing path tests listed above.

**FS-2 · `as const` on EncryptionErrorTypes breaks compilation for some TypeScript consumers in a patch release** (medium impact, plausible)

- Trigger: A consumer's TypeScript code compares error.type with a string outside the five literals, assigns a string-typed value to the type field of an EncryptionError-shaped object (for example in mocks or wrappers), or assigns to an EncryptionErrorTypes member.
- Mechanism: EncryptionError.type is typed as the value type of EncryptionErrorTypes (errors/index.ts:38). With `as const` (line 13) that type is now a union of literals instead of string, so the code above raises TS2367 (no overlap), TS2322 (string not assignable) or TS2540 (read-only).
- Consequence: After upgrading the patch version, affected consumer builds fail type-checking. Runtime behaviour does not change, and the fix on the consumer side is mechanical.
- Affects: @cipherstash/stack/errors public types (EncryptionErrorTypes, EncryptionError, StackError), TypeScript consumers of @cipherstash/stack error types
- Evidence: `packages/stack/src/errors/index.ts:7-13`; `packages/stack/src/errors/index.ts:37-72`; `packages/stack/__tests__/error-discriminated-union.test-d.ts:1-52`; `.changeset/v3-supabase-needle-lockcontext-errors.md:1-21`
- Existing verification: error-discriminated-union.test-d.ts asserts the literal types and exhaustive narrowing (the intended positive case) [exists_not_run]
- Missing verification: No workspace-wide typecheck result showing that the other in-repo packages (stack-supabase, stack-drizzle, protect, migrate, prisma-next, cli) still compile with the narrowed type; No consideration of semver level for a type narrowing on a public export
- Mitigation: Run a full workspace typecheck/build before release. Call out the type narrowing in the changeset or bump minor. Optionally keep a widened alias for consumers that need string.

### Recommended controls

- Add stack-supabase v3 tests that short and empty needles are rejected through like('%ab%'), ilike, or('email.cs.ab') and structured or, not(col,'matches','ab'), and filter(col,'cs','ab'), and that a 3-codepoint needle still passes. (test; FS-1, VG-1)
- Make the changeset say explicitly that short or empty free-text terms now return an error (status 500 / throw), and that EncryptionError['type'] is now a literal union. Consider a minor bump for both packages. (documentation; FS-1, FS-2)
- Run pnpm build plus the test:types / tsc typecheck across every workspace package (and the examples) before publishing, to confirm the narrowing compiles everywhere in-repo. (compatibility_check; FS-2, VG-3)
- Review query-builder-v3.ts:498-512 to confirm the guard runs for every encrypted free-text spelling and that the 500/throwOnError surface is acceptable for this rejection. (review_focus; FS-1)
- Run the stack-supabase and stack unit and type suites (pnpm --filter @cipherstash/stack-supabase test; pnpm --filter @cipherstash/stack test:types) and attach the results. (test; VG-2)

### What this assessment could not see

- No tests, typecheck or build could be run: node_modules is absent and network access is not allowed. No CI results were supplied. Every verification is exists_not_run. Whether the in-repo packages still compile after the type narrowing is not established.
- Consumers outside this repository are unknown. Whether real applications send short or empty free-text terms is not established. FS-1 and FS-2 are rated plausible, not observed. Their likelihood is unknown.
- Pre-existing and not caused by this change: the v2 Supabase like/ilike paths and other v2 free-text spellings remain unguarded and still fail open (match-defaults.ts:123-129). Not counted as a scenario. Reviewers should not read this change as closing the fail-open for v2 users.
- The ngram tokenizer's handling of whitespace-only or punctuation-only 3+ codepoint needles was not checked. The guard counts codepoints only, the same as the Drizzle adapter. A residual fail-open for such needles, if one exists, would be shared with Drizzle and not introduced here. Unassessed.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
