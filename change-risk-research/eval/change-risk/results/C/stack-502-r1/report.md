## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `b9c4fe5598..6e7ae4e117`

Additive public-surface change to @cipherstash/stack (minor changeset). Re-exports the existing operation classes from the ./encryption and ./dynamodb subpath entries, adds EncryptedQuery and EncryptedFromSchema type exports to ./types, removes @internal tags from EncryptQueryOperation/BatchEncryptQueryOperation (and their WithLockContext variants), and adds type-only imports plus TSDoc wording fixes. No encryption, payload, lock-context or result-shape logic changes; the encryption/operations <-> encryption/index import cycle already existed at base. The release risk is about API contract, not runtime: runtime class constructors that take internal types become public API, and the ./encryption and ./dynamodb entries now export different classes under the same names. Both are low impact. CI on head passed, but no test checks the exported surface or the built .d.ts files.

### Failure scenarios

**FS-1 · Same-named but different operation classes exported from ./encryption and ./dynamodb** (low impact, plausible)

- Trigger: A consumer imports EncryptModelOperation, DecryptModelOperation, BulkEncryptModelsOperation or BulkDecryptModelsOperation from the wrong subpath, for example by IDE auto-import, to type the result of encryptedDynamoDB(...).encryptModel() or EncryptionClient.encryptModel().
- Mechanism: src/encryption/index.ts re-exports the classes from ./operations/* (Client-based constructors). src/dynamodb/index.ts re-exports different classes with the same names from dynamodb/operations/* (EncryptionClient-based constructors). The changeset lists both sets under the same names.
- Consequence: The consumer's code fails to type-check, or instanceof checks against the wrong class return false. This is loud and local; it does not affect encryption or data.
- Affects: @cipherstash/stack ./encryption entry (src/encryption/index.ts), @cipherstash/stack ./dynamodb entry (src/dynamodb/index.ts), Downstream TypeScript consumers of @cipherstash/stack
- Evidence: `packages/stack/src/encryption/index.ts:48-59`; `packages/stack/src/dynamodb/index.ts:103-108`; `packages/stack/src/dynamodb/operations/encrypt-model.ts:19-23`
- Missing verification: No test or doc distinguishes the two sets of same-named classes.
- Mitigation: Note the distinction in the TSDoc/changeset, or alias the DynamoDB exports (for example DynamoDBEncryptModelOperation) before the names ship and become hard to rename.

**FS-2 · Exported constructors and class identity become semver-bound public API** (low impact, plausible)

- Trigger: A later release changes an operation constructor (for example its internal FFI Client parameter or its argument order), or a consumer relies on `instanceof EncryptOperation` across package entry points.
- Mechanism: Previously the classes could be reached only as return types. Now they are runtime value exports, so their constructors (which take the internal `Client` type, e.g. encrypt-query.ts constructor) are public. tsup bundles each entry separately. For CJS output, tsup's default of no code splitting would give src/index.ts (which re-exports Encryption) and src/encryption/index.ts separate class copies, so instanceof could fail across entries. This last point comes from tsup defaults and was not verified against built output.
- Consequence: Internal refactors of the operation classes become breaking changes for anyone who constructs them directly, and instanceof checks may misbehave in CJS consumers. The failures are compile-time or logic errors in consumer code, not data or security effects.
- Affects: @cipherstash/stack ./encryption entry (src/encryption/index.ts), Published npm package build (tsup ESM/CJS + dts, per-entry bundles), Downstream TypeScript consumers of @cipherstash/stack
- Evidence: `packages/stack/src/encryption/index.ts:48-59`; `packages/stack/src/encryption/operations/encrypt-query.ts:17-26`; `packages/stack/tsup.config.ts:5-22`; `packages/stack/package.json:139-168`
- Missing verification: No API-surface or built-package (dist) test checks what each subpath exports or how the classes behave across entries.
- Mitigation: Document the classes as return types only (not for direct construction or instanceof). Optionally export them type-only (`export type { ... }`), which is enough for naming and TypeDoc links.

### Recommended controls

- Decide whether the classes should be value exports or type-only exports, and whether the DynamoDB classes need distinct names, before the minor release fixes the names. (review_focus; FS-1, FS-2)
- Run `pnpm --filter @cipherstash/stack build` and confirm that dist/encryption/index.d.ts, dist/dynamodb/index.d.ts and the CJS bundles expose the new exports. (test; VG-1)

### What this assessment could not see

- The package was not built and tests were not run locally (no network or credentials). CI results are summary-level only. The claims about the CJS class-copy behaviour and the dts output are inferred from tsup defaults and config, not observed.
- The companion cipherstash/docs PR and the TypeDoc build were unavailable. The PR's claim that the docs build has 0 warnings could not be verified. It affects only documentation.
- Biome lint config was read, but no lint run was seen. The type-only imports are referenced only in comments. Whether a lint step would flag them as unused is unknown. If it did, the failure would be loud and in CI only.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
