## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** low · `b9c4fe5598..6e7ae4e117`

Additive public-API change to the published @cipherstash/stack package. The /encryption entry now re-exports ten operation classes (already imported as values there), the /dynamodb entry re-exports its four DynamoDB operation classes (also already imported), and /types adds the type exports EncryptedQuery and EncryptedFromSchema. The @internal tags come off EncryptQueryOperation, BatchEncryptQueryOperation and their WithLockContext variants. The other edits are TSDoc text and type-only imports, which verbatimModuleSyntax erases. No runtime encryption, payload or lock-context path changes. tsconfig has no stripInternal, so removing @internal does not change emitted declarations. The risk is in the contract: these classes and their constructors become a semver-bound public surface. /encryption and /dynamodb now export different classes with the same names. The changeset says the WithLockContext variants stay internal, but their @internal tags were removed. Any build or declaration-bundling breakage would be loud and caught by a build. No build, type-check or test was run here, and no CI results were provided.

### Failure scenarios

**FS-1 · Same-named operation classes from /encryption and /dynamodb confuse consumers' type annotations** (low impact, plausible)

- Trigger: A consumer imports EncryptModelOperation (or another Bulk*/Decrypt* model operation) from the wrong subpath and annotates a value returned by the other API with it.
- Mechanism: The dynamodb classes are distinct declarations (extending DynamoDBOperation with private fields), not re-exports of the encryption classes. Private members make TypeScript class types nominal, so the two are not assignable to each other.
- Consequence: Consumers hit compile-time type errors and confusion in the generated API reference, where two different pages share a name. Nothing goes wrong at runtime, no data is affected, and the failure is loud.
- Affects: @cipherstash/stack/encryption entry (published), @cipherstash/stack/dynamodb entry (published)
- Evidence: `packages/stack/src/encryption/index.ts:48-59`; `packages/stack/src/dynamodb/index.ts:101-108`; `packages/stack/src/dynamodb/operations/encrypt-model.ts:12-17`; `packages/stack/src/encryption/operations/encrypt-model.ts:15`
- Existing verification: packages/stack/__tests__/types.test-d.ts exists for type-level checks; it is not known to cover the new exports. [exists_not_run]
- Missing verification: A type test that imports each newly exported class from its subpath and checks it matches the corresponding method's return type.
- Mitigation: Document the two families as distinct, or export the DynamoDB ones under DynamoDB-prefixed aliases before release; once published, renaming them is a breaking change.

**FS-2 · Operation constructors become a semver-bound contract** (low impact, plausible)

- Trigger: A later internal refactor changes an operation constructor signature or class hierarchy, for example how the FFI Client or lock context is passed.
- Mechanism: Classes are exported as values, so constructors and the `instanceof` identity become public. The changeset ships this as a minor release with no statement that construction is unsupported.
- Consequence: Future internal changes either need a major bump or silently break consumers who construct or subclass operations. Direct construction needs the private FFI Client, which limits real use.
- Affects: @cipherstash/stack/encryption entry (published), @cipherstash/stack/dynamodb entry (published)
- Evidence: `packages/stack/src/encryption/index.ts:48-59`; `packages/stack/src/encryption/index.ts:1-44`; `.changeset/export-operation-result-types.md:2`
- Missing verification: An API-surface check, for example api-extractor or an export snapshot, to make the newly public surface explicit and guarded.
- Mitigation: Export as `export type { ... }` if only naming the types is needed, or mark the constructors @internal or document them as not for direct construction.

**FS-3 · WithLockContext variants lose @internal despite the changeset saying they stay internal** (low impact, observed in the code)

- Trigger: Docs generation or IDE hints run against the published declarations.
- Mechanism: The diff deletes the @internal comments on EncryptQueryOperationWithLockContext and BatchEncryptQueryOperationWithLockContext. The changeset states the *WithLockContext variants remain internal. They are still not exported from any entry.
- Consequence: There is a documentation and contract inconsistency, and these two variants are now inconsistent with the other WithLockContext classes. The exported surface does not change.
- Affects: @cipherstash/stack/encryption entry (published)
- Evidence: `packages/stack/src/encryption/operations/batch-encrypt-query.ts:168-170`; `.changeset/export-operation-result-types.md:14`
- Mitigation: Restore @internal on the two WithLockContext classes, or correct the changeset wording.

### Recommended controls

- Run `pnpm build` for packages/stack in CI. Confirm that dist/encryption/index.{js,cjs,d.ts,d.cts} and dist/dynamodb/index.* export the new names and that the CJS require() of both entries still loads. (compatibility_check; VG-1)
- Decide deliberately whether the classes should be value exports (constructors public) or type-only exports, and whether the DynamoDB classes need distinct names. Both choices are hard to reverse after publish. (review_focus; FS-1, FS-2)
- Reconcile the @internal tags on the two WithLockContext query classes with the changeset text. (documentation; FS-3)
- Add a types.test-d.ts case that imports each newly exported class from its subpath and checks it against the corresponding method's return type. (test; VG-2, FS-1)

### What this assessment could not see

- There were no node_modules and no network access, so the package could not be built, type-checked or tested. The build and declaration outcome of the new re-exports is inferred from source and tsup config, not observed.
- No CI results or PR body were provided. Verification confidence is low. No claim is made that tests pass.
- Consumers outside this repository, such as customer code and the docs site build, could not be inspected. The effect on the generated API reference and on external users is assessed from the changeset intent only.

_Inputs unavailable: ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
