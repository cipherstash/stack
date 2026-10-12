## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `7ba9119c7e..c447e26192`

Two behaviour changes in @cipherstash/stack ship together. (1) The low-level operations (encrypt, encryptQuery single and batch, decrypt, bulkEncrypt, bulkDecrypt) no longer short-circuit null: null values are now passed straight to protect-ffi instead of being preserved as null, and the null-tolerant result types are narrowed. Model operations still skip nulls. (2) The encrypt config sent to protect-ffi now uses cast_as 'text' instead of 'string' for every default or 'string' column, together with a protect-ffi bump 0.20.1 -> 0.20.2. The most material risks are runtime failures for existing callers that read or query nullable encrypted columns through the bulk, single or Supabase paths, and an unverified question about whether the cast_as change alters ciphertext or index terms for data already at rest. No test exercises either at runtime, and the tests that covered null handling were deleted. No CI results were available. The changeset marks this as minor; on a 0.3.0 package that means a 0.4.0 release, which caret ranges will not pull in automatically.

### Failure scenarios

**FS-1 · bulkDecrypt/decrypt of nullable encrypted columns now sends null to protect-ffi** (high impact, plausible)

- Trigger: An existing caller reads rows from a nullable encrypted column (database drivers return null, often typed as any or via a cast) and passes them to bulkDecrypt or decrypt, as was documented as supported at base ("null values are preserved").
- Mechanism: At base, createDecryptPayloads filtered `data !== null` and the result re-inserted `{ id, data: null }` (bulk-decrypt.ts:22,48 base); decrypt returned null early (decrypt.ts:47 base). At head createDecryptPayloads maps every entry to `ciphertext: data` (bulk-decrypt.ts:15-24) and passes it to decryptBulkFallible; decrypt calls ffiDecrypt directly. The same applies to encrypt/bulkEncrypt with null plaintext.
- Consequence: After upgrade, reads that previously succeeded either fail as a whole (if the FFI rejects the batch on deserialisation) or return per-item errors for null rows; user-facing reads of records with empty optional encrypted fields break. If protect-ffi instead accepts null (e.g. as a JSON value for a json-cast column), encrypt(null) would store an encrypted payload where SQL NULL was stored before; this could not be checked without the FFI source.
- Affects: @cipherstash/stack encryption operations (encrypt, decrypt, bulk, encryptQuery), protect-ffi native client (newClient / encrypt / query terms), TypeScript consumers of @cipherstash/stack
- Evidence: `packages/stack/src/encryption/operations/bulk-decrypt.ts:15-24`; `packages/stack/src/encryption/operations/bulk-decrypt.ts:20-24` (base); `packages/stack/src/encryption/operations/decrypt.ts:47-49` (base); `packages/stack/__tests__/bulk-protect.test.ts`
- Existing verification: Tests for null preservation in bulk-protect, json-protect, number-protect, encrypt-query and protect-ops were deleted rather than replaced with tests for the new behaviour. [unknown]; Model-level null handling tests remain in protect-ops.test.ts (integration, needs credentials). [exists_not_run]
- Missing verification: A test showing what bulkDecrypt/decrypt/encrypt/bulkEncrypt return for a null entry at runtime under protect-ffi 0.20.2 (failure result with a stable error type, not a throw or an encrypted null).; A test that one null in a bulkDecrypt batch does not fail the other entries.
- Mitigation: Either keep a runtime guard that returns a typed failure (or preserves null) for null inputs, or document the break in the changeset as breaking with a migration note and add tests pinning the new runtime behaviour.

**FS-2 · cast_as 'string' -> 'text' could change how values are encoded or indexed against data at rest** (high impact, plausible)

- Trigger: An existing application upgrades @cipherstash/stack and queries (equality/order/match) columns whose data was encrypted under the previous config (cast_as 'string', protect-ffi 0.20.1).
- Mechanism: build() now emits `cast_as: 'text'` where it emitted the stored castAsValue ('string') before (schema/index.ts:172,341 head vs 171,340 base); the zod default also moves to 'text'. The config is passed to protect-ffi newClient (encryption/index.ts:72-85). Whether protect-ffi 0.20.2 treats 'text' identically to how 0.20.1 treated 'string' (plaintext encoding, payload type metadata, index term derivation) is not visible from this repository. The EQL SQL bundle lists 'text' (not 'string') as the valid cast, which suggests 'text' is the canonical name and the change is an alignment, but this is not proof of equivalence.
- Consequence: If they differ, new query terms do not match stored index terms and searches silently return no or wrong rows, or newly written payloads differ in shape from older ones. If they are equivalent (the likely intent), there is no effect.
- Affects: @cipherstash/stack schema builders / encrypt config, protect-ffi native client (newClient / encrypt / query terms), Stored ciphertext and EQL index terms in customer databases
- Evidence: `packages/stack/src/schema/index.ts:170-174`; `packages/stack/src/schema/index.ts:26-27` (base); `packages/stack/src/encryption/index.ts:72-85`; `packages/schema/cipherstash-encrypt-2-1-8.sql:3604-3608`; `packages/stack/__tests__/schema-builders.test.ts:26-31`
- Existing verification: schema-builders.test.ts asserts the built config now contains cast_as 'text'; it does not exercise encryption or search across the change. [exists_not_run]
- Missing verification: A compatibility test: encrypt with the base config (cast_as 'string', protect-ffi 0.20.1), then search/decrypt with the head config (cast_as 'text', 0.20.2) and assert matches.; protect-ffi 0.20.2 changelog confirming 'text' and 'string' are aliases.
- Mitigation: Confirm with the protect-ffi owners that 'string' and 'text' map to the same column type, and add a cross-version encrypt/query fixture test before release.

**FS-3 · Supabase filters with a null value now reach encryptQuery and fail the query** (medium impact, plausible)

- Trigger: An application using the Supabase wrapper calls `.eq(col, null)`, `.in(col, [a, null])`, `.match({ col: null })`, `.not(...)` or an `.or()` string with a null value on an encrypted column.
- Mechanism: The query builder casts filter values `as JsPlaintext` without filtering nulls (query-builder.ts:460-485), skipping only `is` filters, and calls encryptQuery(terms) (query-builder.ts:590). At base BatchEncryptQueryOperation dropped null/undefined terms and returned null in their slot (batch-encrypt-query.ts:34 base); at head every term goes to buildQueryPayload and the FFI (batch-encrypt-query.ts:113,183).
- Consequence: The whole query fails with EncryptionFailedError where it previously sent a null term; for `.in` lists one null entry fails the full lookup. Loud, limited to this call pattern.
- Affects: Supabase query builder (packages/stack/src/supabase), @cipherstash/stack encryption operations (encrypt, decrypt, bulk, encryptQuery), protect-ffi native client (newClient / encrypt / query terms)
- Evidence: `packages/stack/src/supabase/query-builder.ts:460-485`; `packages/stack/src/encryption/operations/batch-encrypt-query.ts:32-38` (base)
- Missing verification: A Supabase builder test with a null filter value on an encrypted column.
- Mitigation: Filter or reject null filter values in the Supabase builder with a clear error (or route them to `is null`).

**FS-4 · Nullable-field type mapping changed without type tests** (medium impact, plausible)

- Trigger: A TypeScript consumer uses Decrypted<T> or EncryptedFromSchema<T,S> on models with optional or nullable encrypted fields, or imports the removed EncryptPayload type.
- Mechanism: EncryptedFields/OtherFields/DecryptedFields now use NonNullable<T[K]> and `null extends T[K]` (types.ts:128-139,168). Because Encrypted no longer includes null, a field typed `Encrypted | null` would have been excluded from encrypted keys without the NonNullable change; the new mapping is untested. types.test-d.ts, which history shows always changes with types.ts, was not updated and has no nullable cases.
- Consequence: Compile errors or incorrect inferred types for consumers on upgrade (e.g. a nullable encrypted field typed as Encrypted rather than plaintext after decrypt). Loud at build time, no runtime data effect.
- Affects: TypeScript consumers of @cipherstash/stack
- Evidence: `packages/stack/src/types.ts:32-35`; `packages/stack/src/types.ts:126-139`; signal `co_change.omitted_co_changes[1]`; `packages/stack/__tests__/types.test-d.ts:57-141`
- Existing verification: types.test-d.ts covers Decrypted/EncryptedFromSchema for non-nullable fields only. [exists_not_run]
- Missing verification: Type tests for optional and nullable encrypted fields through EncryptedFromSchema and Decrypted.
- Mitigation: Add type tests for nullable fields; mention the removed EncryptPayload export and the null contract change in the changeset.

### Recommended controls

- Run an encrypt-with-base / query-and-decrypt-with-head fixture test (or get written confirmation from protect-ffi that 'string' and 'text' are aliases in 0.20.1 and 0.20.2) before publishing. (compatibility_check; FS-2, VG-2)
- Add tests for null entries in encrypt, decrypt, bulkEncrypt, bulkDecrypt and batch encryptQuery asserting a typed failure (or chosen behaviour), and that one null does not fail the rest of a bulk decrypt. (test; FS-1, VG-1)
- Add a Supabase builder test for null filter values on encrypted columns, and handle them explicitly in the builder. (test; FS-3)
- Describe the release as breaking in the changeset: null no longer accepted by low-level/bulk operations, EncryptPayload removed, cast_as now 'text'. Include a migration note for reading nullable columns with bulkDecrypt. (documentation; FS-1, FS-4)
- Extend types.test-d.ts with nullable and optional encrypted fields. (test; FS-4, VG-4)
- Reviewer to check the index-by-position mapping in bulk-decrypt.ts/bulk-encrypt.ts/batch-encrypt-query.ts against protect-ffi output ordering and length now that no filtering occurs. (review_focus; FS-1)

### What this assessment could not see

- protect-ffi source and 0.20.2 release notes were not available, and node_modules is absent. Cannot determine whether null inputs throw, return per-item errors or are encrypted, nor whether cast_as 'text' and 'string' are equivalent. FS-1 and FS-2 consequences are conditional.
- No tests were run; integration tests need ZeroKMS credentials and no CI results were supplied. Verification confidence cannot exceed low/medium.
- Test-file diffs were read for intent (deleted null tests, updated cast_as expectations) but not line-by-line; the DynamoDB integration was only checked for cast_as usage (compares to 'json'). A DynamoDB-specific null path could have been missed.
- The PR body was unavailable; the change includes a merge from main (bd192bd) whose contents were not separated from the feature commits. Intent behind the cast_as change is inferred from the commit title 'default to text for encrypt config' and the SQL bundle.
- Minor: the JSDoc example for EncryptedTable.build still shows cast_as "string" (schema/index.ts:381) and EncryptedColumn still stores 'string' internally. Documentation drift only; not a release risk.

_Inputs unavailable: ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
