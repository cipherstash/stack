## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `b9c4fe5598..6e7ae4e117`

Additive public-API change to @cipherstash/stack (changeset: minor). It re-exports ten operation classes from the ./encryption entry and four from the ./dynamodb entry, removes @internal tags from EncryptQueryOperation/BatchEncryptQueryOperation and their WithLockContext variants, adds EncryptedQuery and EncryptedFromSchema to ./types, and fixes TSDoc (type-only imports used only for {@link}). No encryption, decryption, lock-context or payload logic changes; the re-exports are bindings already imported by those modules, so no new module-graph edges are introduced. The material consequence is contractual: class constructors (which take internal types such as the FFI Client) become part of the semver-covered public surface, and different classes named EncryptModelOperation, BulkEncryptModelsOperation etc. are now exported from two subpaths. Impact is low; normal review is sufficient. Nothing was built or run.

### Failure scenarios

**FS-1 · Operation class constructors become a semver-locked public contract** (low impact, plausible)

- Trigger: A later release refactors an operation constructor (e.g. EncryptOperation(client, plaintext, opts) or the DynamoDB EncryptModelOperation(encryptionClient, item, table, options)) in a minor/patch version after consumers start instantiating or subclassing the now-exported classes.
- Mechanism: The classes are exported as values, not `export type`, so their constructors (which take internal shapes such as the FFI `Client` type) are now reachable public API. Previously only the instances returned by EncryptionClient/encryptedDynamoDB methods were public. The changeset frames the change as type-naming only.
- Consequence: Consumer code that constructs or extends these classes breaks at compile time or runtime after an otherwise routine internal refactor; maintainers lose freedom to change constructor signatures without a major bump. No data or security consequence: constructing an operation directly still needs a client, and the wrapped FFI calls are unchanged.
- Affects: @cipherstash/stack ./encryption entry (src/encryption/index.ts), @cipherstash/stack ./dynamodb entry (src/dynamodb/index.ts), External consumers of @cipherstash/stack
- Evidence: `packages/stack/src/encryption/index.ts:45-59`; `packages/stack/src/encryption/operations/encrypt.ts:30-40`; `packages/stack/src/dynamodb/operations/encrypt-model.ts:19-29`; `.changeset/export-operation-result-types.md:1-15`
- Missing verification: No test or API-surface snapshot asserts which names each entry point exports or whether constructors are intended to be public.
- Mitigation: Either export the classes with `export type { ... }` (sufficient for naming return types and TSDoc links), or mark constructors @internal / document that only the returned instances are supported.

**FS-2 · Same class names exported from two subpaths refer to different classes** (low impact, plausible)

- Trigger: A consumer names the return type of encryptedDynamoDB(...).encryptModel() using EncryptModelOperation imported from @cipherstash/stack/encryption (or vice versa), e.g. via IDE auto-import.
- Mechanism: encryption/index.ts and dynamodb/index.ts both export EncryptModelOperation, DecryptModelOperation, BulkEncryptModelsOperation and BulkDecryptModelsOperation, but they are different classes with different constructors and result/error types.
- Consequence: TypeScript type errors or confusing type mismatches in consumer code; loud at compile time, no runtime data effect.
- Affects: @cipherstash/stack ./encryption entry (src/encryption/index.ts), @cipherstash/stack ./dynamodb entry (src/dynamodb/index.ts), External consumers of @cipherstash/stack
- Evidence: `packages/stack/src/encryption/index.ts:45-59`; `packages/stack/src/dynamodb/index.ts:101-108`; `packages/stack/src/dynamodb/operations/encrypt-model.ts:19-29`
- Missing verification: No type test covers naming the DynamoDB operation types.
- Mitigation: Document the distinction in TSDoc, or alias the DynamoDB exports (e.g. DynamoDBEncryptModelOperation).

### Recommended controls

- Decide deliberately whether the operation classes should be value exports (constructors public) or `export type` only, before publishing; publication is effectively irreversible. (review_focus; FS-1)
- Confirm CI build (tsup dts for all entries), typecheck and biome lint pass on head, and optionally add a type test that imports the new names from each subpath. (test; VG-1, FS-2)
- Note in TSDoc/changeset that the DynamoDB and encryption EncryptModelOperation et al. are distinct types. (documentation; FS-2)

### What this assessment could not see

- No CI results and no build/test run: dependencies are not installed and network access is not permitted. Cannot confirm the d.ts bundling, typecheck and lint succeed; verification confidence is medium on the strength of reading the code.
- encrypt-query.ts and batch-encrypt-query.ts import noClientError from '../index' while encryption/index.ts imports those modules: a pre-existing circular import at base. This change only re-exports already-imported bindings and adds no new edge. Treated as pre-existing and not attributed to this change.
- PR body, CODEOWNERS, architecture docs and deployment context were not inputs. Intent beyond the changeset text and ownership could not be checked.

_Inputs unavailable: ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
