## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `e4a814b026..6ad6c76e7d`

Mostly a type-level refactor of the @cipherstash/stack encryption client: the `as never` forwarding casts in createEncryptionClient are replaced by real signatures (PlaintextInput, EncryptQueryArgs, BulkEncryptPayloadInput), and FFI plaintext casts are centralised in an identity helper `toJsPlaintext`. Runtime behaviour of encrypt/encryptQuery/bulkEncrypt/model paths is unchanged on read: the native encryptQuery branches on args[1] exactly as it branched on `opts`, and no payload shape changes. Two contract changes ship: (1) `encrypt` on a `types.Json` column whose plaintext type admits null now returns `data: Encrypted | null`, which will stop some consumers' code compiling, released as a minor bump; (2) the stack-supabase per-term fallback now fails closed on a null envelope instead of sending the string "null" as a filter operand. No silent data, key or plaintext-exposure mechanism was found. Tests (type tests, forwarding unit tests, supabase fallback test, a JSON null-element integration test) were added but not run here and no CI was supplied.

### Failure scenarios

**FS-1 · Customer builds stop compiling after a minor upgrade when encrypting Json values typed JsonDocument** (medium impact, plausible)

- Trigger: A consumer upgrades @cipherstash/stack within its semver range and has code like `const r = await client.encrypt(doc, { table, column: t.metadata }); r.data.c` where `doc: JsonDocument` (or a variable whose type admits null).
- Mechanism: EncryptResult<P> adds `null` to the success type whenever P admits null (operations/encrypt.ts:41); EncryptionClient.encrypt now returns EncryptOperation<EncryptResult<P>> (client-v3.ts:196). The changeset declares this a `minor` bump and says such code must now null-check.
- Consequence: TypeScript compile errors in consumer projects (strictNullChecks) on a minor release; deploys blocked until code is updated. No runtime or data change: the value was already null at runtime, so the new type is more accurate.
- Affects: @cipherstash/stack encryption client (client-v3.ts, encryption/index.ts, operations/*), Customer TypeScript code calling encrypt on types.Json columns
- Evidence: `languages/typescript/packages/stack/src/encryption/client-v3.ts:196`; `languages/typescript/packages/stack/src/encryption/operations/encrypt.ts:41-63`; `.changeset/stack-encrypt-json-null-result.md:1-11`
- Existing verification: typed-client-v3.test-d.ts asserts Encrypted | null for literal null and JsonDocument-typed plaintexts and plain Encrypted for non-null values (including explicit <Table, Col> type args). [exists_not_run]
- Missing verification: No check that in-repo examples/docs snippets encrypting Json values still type-check (none found by grep, but docs code is not compiled).
- Mitigation: Call out the type change prominently in release notes (it is in the changeset); a reviewer should confirm the team accepts a type-only breaking change in a minor release rather than a major.

**FS-2 · Verbatim ...args forwarding changes native encryptQuery routing for an untyped or adapter caller** (medium impact, speculative)

- Trigger: A JS or `as never` caller (stack-drizzle, stack-prisma, plain JS) calls encryptQuery with an unusual argument list, e.g. (termsArray, undefined) or (array, null).
- Mechanism: Typed client now passes ...args through unchanged (client-v3.ts:529-533); native discriminates on `!args[1]` (index.ts:349-364), the same truthiness test previously applied to `opts`. On read, every argument shape routes as before; only the arity seen by the native method differs.
- Consequence: If routing differed, a scalar array plaintext could be treated as a batch (or vice versa), producing wrong query terms or a thrown error. No such divergence was found; listed so a reviewer can confirm equivalence.
- Affects: @cipherstash/stack encryption client (client-v3.ts, encryption/index.ts, operations/*), @cipherstash/stack-drizzle and @cipherstash/stack-prisma operators
- Evidence: `languages/typescript/packages/stack/src/encryption/client-v3.ts:529-533`; `languages/typescript/packages/stack/src/encryption/index.ts:337-367`; `languages/typescript/packages/stack/__tests__/typed-client-v3.test.ts:375-406`; `languages/typescript/packages/stack-drizzle/src/operators.ts:75-79`
- Existing verification: typed-client-v3.test.ts forwarding tests: scalar with opts, and batch forwarded with exactly one argument. [exists_not_run]
- Missing verification: No CI or local run of the stack, stack-drizzle and stack-prisma test suites was available.
- Mitigation: Run the stack, stack-drizzle and stack-prisma unit suites in CI before release.

### Recommended controls

- Confirm CI ran typecheck (including test-d) and unit tests for @cipherstash/stack, stack-supabase, stack-drizzle and stack-prisma on the head commit. (test; VG-1, FS-2)
- Release notes: state that encrypt on a types.Json column may now be typed Encrypted | null and show the null-check migration; reviewer to confirm minor (not major) is the intended semver signal. (documentation; FS-1)
- Reviewer to check the native encryptQuery args[1] discrimination (index.ts:337-367) against the old opts-based branches. (review_focus; FS-2)

### What this assessment could not see

- Test files (typed-client-v3.test-d.ts +251 lines in particular) were skimmed for coverage of the changed behaviour, not read line by line. Coverage claims rely on test names and a sample of assertions.
- No tests or typecheck were run (no node_modules, no network); no CI results. All verification is exists_not_run; compile-level breakage elsewhere in the monorepo cannot be ruled out.
- Consumers were found by git grep at head in languages/typescript/packages; examples/, docs code snippets and external customers were not compiled or exhaustively searched. AC-4 is likely, not confirmed.
- The range includes a merge of origin/main; the assessment covers the base..head diff as a whole. Attribution of individual hunks to commits was not checked.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
