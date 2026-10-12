## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** high · `c8b1325a7e..c379d44a1b`

Documentation and test-only change with no runtime behaviour change. It rewrites the JSDoc on EncryptionClient.decrypt / bulkDecrypt (native and wasm-inline entries), the table-less decryptModel overload and a runtime comment, to state that the raw decrypt paths do not reconstruct Date values and to correct the stated reason. It updates the shipped skills/stash-encryption/SKILL.md and the @cipherstash/stack README to match, adds runtime and type-level tests pinning the boundary, and fixes the stub casts in an existing unit test file. The only executable source lines touched are in tests; the delegations in client-v3.ts and the wasm decrypt bodies are unchanged. The shipped SKILL.md is bundled into the stash and @cipherstash/wizard tarballs, so wrong guidance there would reach customer repositories; the new statements I checked (bulkEncrypt is column-typed, bulkDecrypt/decrypt are bare delegations, bigint is native from the FFI, datePropertyPaths exists on the wasm entry) match the code at head. The changeset bumps stash and @cipherstash/stack as patches, and both are in a fixed group with @cipherstash/wizard, so the skill copy ships consistently. CI on the head commit passed all 15 checks, including the Node 22/24 test jobs that run the stack type tests. No material failure scenario found.

No material failure scenarios identified.

### Recommended controls

- Docs-level review of the new SKILL.md raw-path note: it is shipped to customer repositories and is not type-checked, so a reviewer should confirm the wording (e.g. 'stored ISO string' for types.Date, which stores a calendar date) reads correctly for agents. (review_focus; )

### What this assessment could not see

- Only check-run conclusions were supplied for CI; step logs were not, so I cannot confirm which individual tests (e.g. the new typed-client-v3 tests) ran within the Run Tests jobs, beyond the workflow showing a test:types step. Verification relies on job-level success plus the workflow definition.
- The PR description's claims about protect-ffi 0.30.0 (Identifier shared by every payload) and about other decrypt surfaces (DynamoDB, Supabase, prisma-next) were not independently verified; they only affect the accuracy of explanatory prose, not runtime. A factual error in the rationale text would be a docs-quality issue, not a release risk.
- I did not run any tests locally. No command_output evidence; CI results are the only execution evidence.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
