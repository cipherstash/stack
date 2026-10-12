## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `e4a814b026..6ad6c76e7d`

Mostly a type-level refactor of the TypeScript @cipherstash/stack encryption client. It removes the `as never` forwarding casts in createEncryptionClient, gives the native client a strictly typed structural view, adds an internal PlaintextInput type (Plaintext | JsonDocument) and moves the FFI plaintext assertion into one toJsPlaintext helper. The change that matters publicly is that `encrypt` is now generic over the plaintext type, so its result is typed `Encrypted | null` when the argument can be null. In practice that means types.Json columns and calls that name `<Table, Col>` explicitly. Callers that dereference `result.data` will stop compiling, and this ships as a minor bump. The runtime encrypt, bulkEncrypt and encryptQuery paths look equivalent to base: null still short-circuits to null, and encryptQuery still routes on the second argument. The one runtime change is in stack-supabase: its per-term query fallback now throws on a null envelope instead of sending "null", which matches the bulk path. Nothing touches the payload format, keys or lock context. The encryptModel and bulkEncryptModels result types still rest on an unchecked assertion, which was already true at base.

### Failure scenarios

**FS-1 · Minor release breaks compilation for consumers that encrypt nullable-typed Json values** (medium impact, plausible)

- Trigger: A TypeScript consumer upgrades @cipherstash/stack to the minor release. Their code encrypts into a types.Json column with a plaintext typed JsonDocument (or calls encrypt<Table, Col> on a Json column) and then reads result.data.c, passes result.data to decrypt, or assigns it to an Encrypted-typed variable.
- Mechanism: EncryptionClient.encrypt now returns EncryptOperation<EncryptResult<P>> (client-v3.ts:192-196). EncryptResult<P> includes null whenever P does (encrypt.ts:41). JsonDocument admits null, and P defaults to the column's plaintext type. So code that compiled against `data: Encrypted` now sees `Encrypted | null` and fails strict null checks. The changeset classifies this as a minor bump.
- Consequence: Consumer builds fail after a routine minor upgrade and need a null check at each call site. There is no runtime or data effect, and the new type is more accurate because the runtime already returned null.
- Affects: @cipherstash/stack encryption client (client-v3.ts, index.ts, operations/*, types.ts), External TypeScript consumers of @cipherstash/stack/encryption and /v3 that call encrypt on types.Json columns
- Evidence: `languages/typescript/packages/stack/src/encryption/client-v3.ts:188-196`; `languages/typescript/packages/stack/src/encryption/operations/encrypt.ts:41`; `.changeset/stack-encrypt-json-null-result.md`
- Existing verification: typed-client-v3.test-d.ts asserts Encrypted | null for a literal null or JsonDocument, Encrypted for non-null and scalar values, and that explicit <Table, Col> calls still compile. [exists_not_run]
- Missing verification: CI typecheck results for every in-repo package that consumes @cipherstash/stack (cli, bench, stack-drizzle, stack-prisma, stack-supabase) were not seen.; dist-types declaration checks (node16 cts/mts) were not run against the new generic signature.
- Mitigation: Confirm the semver call (minor vs major) for a type-narrowing change. Call out the required null check prominently in release notes, and run the monorepo typecheck and dist-types checks before publishing.

**FS-2 · Supabase per-term fallback now throws where it used to send a "null" operand** (low impact, plausible)

- Trigger: A stack-supabase query runs with an encryption client that lacks bulkEncrypt, and a filter operand encrypts to null data.
- Mechanism: encryptGroupPerTerm now calls encryptionFailure when result.data === null (query-encrypt.ts:417-422, head). At base, it returned result.data directly (query-encrypt.ts:413, base).
- Consequence: The query fails loudly instead of sending the operand "null", which would have matched the wrong rows. The change fails closed, and a null operand is already rejected for JSON containment by assertJsonContainmentOperand. Reachability looks narrow because the typed client always provides bulkEncrypt.
- Affects: @cipherstash/stack-supabase query-encrypt
- Evidence: `languages/typescript/packages/stack-supabase/src/query-encrypt.ts:395-425`; `languages/typescript/packages/stack-supabase/src/query-encrypt.ts:395-413` (base)
- Existing verification: supabase-v3-builder.test.ts: 'rejects a null envelope on the per-term fallback rather than sending "null"'. [exists_not_run]
- Mitigation: None needed beyond the changeset note. This aligns the fallback with the bulk path.

### Recommended controls

- Run the monorepo typecheck (including the dist-types node16 checks and every package that consumes @cipherstash/stack) and the stack type and unit tests before release. (test; FS-1, VG-1)
- Have a reviewer decide whether a narrowing of encrypt's result type for Json columns belongs in a minor release, and check that the changelog tells users to null-check result.data. (review_focus; FS-1)
- Check that the native encryptQuery `...args` routing (index.ts:349-366) matches base for (value, opts), (terms) and ([], opts). (review_focus; VG-1)

### What this assessment could not see

- Tests were not run and no CI results were available. Verification confidence cannot exceed medium.
- Test diffs (about 430 added lines) were skimmed by test name only. Source hunks were read in full. The exact assertions in the tests are not confirmed.
- External consumer code was not available. The extent of FS-1 depends on how many consumers encrypt Json values typed as nullable. The breadth of FS-1 is unknown.
- The PR description, CODEOWNERS and architecture docs were not listed as inputs. The intended semver policy and ownership are not known.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
