## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** low · `33ac5e5a07..35c482112c`

Major-version change to @cipherstash/protect: removes bulkEncrypt/bulkDecrypt and the EncryptedData type export, and adds model operations (encryptModel, decryptModel, bulkEncryptModels, bulkDecryptModels, each with a lock-context variant) that choose which object fields to encrypt by matching model keys against the csTable definition. The main risk is silent plaintext persistence: any field that should be encrypted but is not selected (key not matching the table definition, or a hyphenated key in the bulk paths, where the reconstruction truncates the key at the first '-') is passed through unchanged and the caller gets success. The only tests are round-trips, which cannot detect a pass-through because decryptModel also passes plaintext through. Lock-context tests stay commented out, and the workspace example apps still import the removed EncryptedData type, which CI does not build. Tests need live ZeroKMS credentials and were not run.

### Failure scenarios

**FS-1 · Model field not matched to the table definition is written as plaintext with a success result** (critical impact, plausible)

- Trigger: An application calls encryptModel/bulkEncryptModels with a model whose property name differs from the csTable key for that column. Examples: an ORM row with camelCase `emailAddress` against csTable key `email_address`, or a model built for a different table object.
- Mechanism: prepareFieldsForOperation and prepareBulkModelsForOperation select only entries whose key is in Object.keys(table.build().columns) (model-helpers.ts:148-152, 341-345). All non-payload fields, including the unmatched sensitive one, go into otherFields (extractOtherFields, :26-38) and are spread into the result (:232, :407-421). Nothing warns about or rejects a field that matches no column.
- Consequence: The caller receives { data } and inserts the row. The sensitive value lands in the database in plaintext. decryptModel later passes it through unchanged, so the application appears to work.
- Affects: @cipherstash/protect ProtectClient public API, packages/protect/src/ffi/model-helpers.ts, Customer databases storing values written via encryptModel
- Evidence: `packages/protect/src/ffi/model-helpers.ts:133-167`; `packages/protect/src/ffi/model-helpers.ts:202-233`; `packages/protect/__tests__/protect.test.ts:61-101`
- Existing verification: protect.test.ts round-trips encryptModel -> decryptModel and asserts the decrypted model equals the input. It never asserts that encryptedModel.data fields are EQL payloads, so a pass-through would also pass. [exists_not_run]
- Missing verification: Assert that each schema column in encryptModel output is an EQL payload (has c) and does not equal the plaintext; Test the behaviour when the model's keys do not match the table definition
- Mitigation: Assert on ciphertext shape in tests. Document clearly that matching is by csTable key. Consider a strict mode, or a warning when a model key looks like a schema column but is not matched.

**FS-2 · Bulk model reconstruction truncates hyphenated field names, leaving plaintext under the original key** (critical impact, plausible)

- Trigger: bulkEncryptModels (with or without lock context) is called with a table whose column key contains '-' (e.g. csTable('users', { 'first-name': csColumn('first-name') })).
- Mechanism: Items are keyed `${modelIndex}-${fieldKey}`. On reconstruction, `const [_, fieldKey] = key.split('-')` keeps only the second segment (model-helpers.ts:416-418, also :467 and :521). The ciphertext lands under `first`, while `first-name` still holds the plaintext copied in from otherFields.
- Consequence: Plaintext is persisted in the original column and a stray `first` property carries the ciphertext. The single-model path does not do this, so behaviour differs between single and bulk.
- Affects: packages/protect/src/ffi/model-helpers.ts, Customer databases storing values written via encryptModel
- Evidence: `packages/protect/src/ffi/model-helpers.ts:406-421`; `packages/protect/src/ffi/model-helpers.ts:202-233`
- Existing verification: Bulk tests use only the non-hyphenated keys email and address. [exists_not_run]
- Missing verification: A bulk test with a column key containing '-' (and ideally a test asserting that output fields are ciphertext)
- Mitigation: Map results back through keyMap ({modelIndex, fieldKey}) instead of re-parsing the string id, or split only on the first '-'.

**FS-3 · Lock-context model operations ship with no executed test of identity binding** (high impact, speculative)

- Trigger: A customer uses encryptModel/decryptModel/bulk*Models with .withLockContext(...).
- Mechanism: Four new lock-context code paths each build per-item lockContext and pass ctsToken to encryptBulk/decryptBulk (model-helpers.ts:276-315, 478-585). The lock-context tests are commented out at head, as they were at base.
- Consequence: A defect in context propagation, such as encrypting without the identity binding, would not be caught before release. The code read follows the base bulk pattern and no such defect was found.
- Affects: @cipherstash/protect ProtectClient public API, packages/protect/src/ffi/model-helpers.ts
- Evidence: `packages/protect/src/ffi/model-helpers.ts:276-315`; `packages/protect/__tests__/protect.test.ts:468-480`
- Existing verification: Lock-context model tests exist but are commented out. [unknown]
- Missing verification: Run the lock-context model tests (encrypt with context, check decrypt without context fails) before release
- Mitigation: Run the commented lock-context tests manually with a valid JWT before publishing the major version.

**FS-4 · Workspace example apps no longer type-check; CI does not build them** (medium impact, observed in the code)

- Trigger: Building or type-checking apps/drizzle or apps/nextjs-clerk at head.
- Mechanism: Both apps import `type EncryptedData` from '@cipherstash/protect' (workspace:*), but head no longer exports it (src/index.ts:41). The root build/test scripts filter './packages/*', so the apps are not compiled in CI.
- Consequence: Example apps that customers copy from break at compile time. Customers upgrading also lose bulkEncrypt/bulkDecrypt with no deprecation path. This is signalled by a major bump.
- Affects: apps/drizzle and apps/nextjs-clerk example apps, @cipherstash/protect ProtectClient public API
- Evidence: `apps/drizzle/src/select.ts:8`; `apps/nextjs-clerk/src/app/page.tsx:8`; `packages/protect/src/index.ts:40-44`; `package.json:25-36`
- Missing verification: Type-check workspace apps in CI or before release
- Mitigation: Update the apps to EncryptedPayload. Optionally keep a deprecated EncryptedData alias. Add migration notes to the changeset.

**FS-5 · decryptModel silently returns undecrypted values it does not recognise** (medium impact, plausible)

- Trigger: A model is passed to decryptModel whose encrypted column arrives as a JSON string (e.g. a driver returning jsonb as text) or as a k:'sv' payload.
- Mechanism: Field detection is shape-based (isEncryptedPayload: object with v, k, i; model-helpers.ts:43-52). Strings pass through as 'other' fields. The 'sv' payloads are sent with `.c` (undefined) and no k === 'ct' check (:186, :446), unlike single decrypt (decrypt.ts:49-53).
- Consequence: The application receives a raw ciphertext string typed as plaintext string and reports success; or gets an FFI error that is opaque.
- Affects: packages/protect/src/ffi/model-helpers.ts
- Evidence: `packages/protect/src/ffi/model-helpers.ts:43-52`; `packages/protect/src/ffi/operations/decrypt.ts:49-53`
- Existing verification: An 'invalid encrypted payloads' error-handling test exists; its inputs were not examined in detail. [exists_not_run]
- Missing verification: Test decryptModel with a stringified payload and an 'sv' payload
- Mitigation: Validate k === 'ct' in model decrypt. Document that encrypted columns must be parsed objects.

### Recommended controls

- Add assertions that encryptModel/bulkEncryptModels output for each schema column is an EQL payload not equal to the plaintext; add a hyphenated-key bulk case. (test; FS-1, FS-2, VG-1)
- Review model-helpers.ts reconstruction (key.split('-') at :413-418, :464-468, :517-522) and field selection (:148-152, :341-345); prefer mapping through keyMap. (review_focus; FS-1, FS-2)
- Run the lock-context model tests with a real JWT before publishing the major version. (test; FS-3, VG-2)
- Type-check apps/* against the new API and update the EncryptedData imports; add migration notes from bulkEncrypt/bulkDecrypt to the changeset. (compatibility_check; FS-4, VG-3)
- State in model-operations docs that fields are matched by csTable key and that unmatched fields are stored unchanged. (documentation; FS-1)

### What this assessment could not see

- Tests were not run (they need ZeroKMS credentials and network) and no CI results were provided. No verification status beyond exists_not_run; verification confidence is low.
- The protect-ffi native module's encryptBulk/decryptBulk semantics (result ordering, handling of the per-item lockContext) were not inspected. Assumes results come back in input order, as the base code also did.
- Docs and README rewrites (~900 lines) were skimmed only; the per-file operation classes were read for the encrypt-model, decrypt and lock-context paths and grepped for the rest. Doc inaccuracies or minor differences between operation classes may be missed.
- Pre-existing: single encrypt passes column.getName() to the FFI, while the encrypt config and model ops use the csTable object key. This was not introduced here. Not raised as a scenario; may interact with FS-1 when the key and column name differ.
- No PR description, deployment context, or external consumer list was available. The blast radius to external customers is unknown beyond the major-version signal.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
