## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `b650a8c297..632bdf61b3`

Narrow bug fix in @cipherstash/stack's bulk model helpers. Per-field results are keyed by `${modelIndex}-${fieldKey}`; reconstruction previously used `split('-')`, so any field key containing a hyphen was truncated (`some-field` -> `some`) and the encrypted/decrypted value landed under the wrong key while the real field vanished. The change replaces four duplicated blocks (bulkEncryptModels, bulkDecryptModels and both lock-context variants) with one helper that splits at the first hyphen. Because the model index is always a non-negative integer with no hyphen, the first hyphen is always the separator, so the fix is correct for every id the code builds; for hyphen-free keys the output is identical to before. No payload shape, lock-context binding, or operation-result contract changes. A regression test was added for the two non-lock-context paths (not run here; no CI supplied). No material failure scenario introduced by this change was found. Note (pre-existing, not caused by this change): packages/protect/src/ffi/model-helpers.ts still carries the same naive split, and no changeset accompanies the fix.

No material failure scenarios identified.

### Recommended controls

- Confirm the stack package test suite (including bulk-model-hyphen-fields.test.ts and nested-models.test.ts) passes in CI; optionally add a lock-context and a nested hyphenated-path case. (test; VG-1)
- Add a changeset for @cipherstash/stack so the fix is released and noted in the changelog, and consider porting the same fix to packages/protect/src/ffi/model-helpers.ts (pre-existing, out of scope). (documentation; )

### What this assessment could not see

- No CI results, PR description or deployment context; tests could not be run because node_modules is absent in the checkout. Verification relies on reading the code and the added test; pass/fail of the test is unknown.
- Rows written previously by the buggy bulkEncryptModels with hyphenated columns may be missing those values at rest; this is pre-existing damage the fix does not repair and was not assessed. Data remediation for past writes is outside this assessment.
- The same naive split remains in packages/protect/src/ffi/model-helpers.ts (pre-existing, unchanged by this diff). @cipherstash/protect users with hyphenated fields remain affected; not counted as a risk of this change.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
