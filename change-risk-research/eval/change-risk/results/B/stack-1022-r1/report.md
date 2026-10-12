## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `3e8f6cb8ce..ab8ca589fa`

The title undersells the change. Besides making Context and ExtendContext copy byte-slice parts (a defensive fix against caller-buffer aliasing), it adds a new capability: Cipher.Term now takes variadic Options, so ExtendContext can scope a search probe to the same extended (e.g. per-tenant) context that EncryptRecords/DecryptRecords use. RecordOption changes from a func type to an interface, with a new Option sub-interface that only ExtendContext implements. All changes are in the Go stackencrypt package; the probe and record paths now share one extend() helper. The material risk is silent search misses: a probe whose extension differs from the write (given twice, different integer type, omitted, or produced by another language's client) returns no matches with no error. That does not expose plaintext or match across tenants, and new unit tests check that the probe and record contexts are byte-identical. The cross-tenant live test needs ZeroKMS credentials, and no test results were available. The public Go API change (Term signature, RecordOption kind) is loud (compile-time) and limited. Advisory: focused review of the probe-context equivalence and cross-language term compatibility.

### Failure scenarios

**FS-1 · Tenant-scoped probe silently matches nothing when its extension differs from the write** (medium impact, plausible)

- Trigger: An application adopts Term(..., ExtendContext(tenant)) but the probe's extension differs from the one rows were written under: the option is given twice (a helper adds it and so does the caller), the tenant is passed as int on one side and uint64 on the other, or the probe omits it.
- Mechanism: contextExtension.appendTo appends parts with no deduplication (record.go:124), and extend() applies every part in order (record.go:168). Term now runs the probe context through the same path (cipher.go:107). Context parts are typed, so the derived terms differ whenever the part list differs, and nothing reports the mismatch.
- Consequence: Equality/match/order queries return zero rows with no error. Data stays encrypted and cross-tenant matching does not occur, but search features appear broken or return incomplete results.
- Affects: languages/golang/stackencrypt (Context, record options, Cipher.Term), Downstream Go applications using stackencrypt search probes and ExtendContext
- Evidence: `languages/golang/stackencrypt/record.go:91-175`; `languages/golang/stackencrypt/cipher.go:99-111`; `languages/golang/stackencrypt/unit_test.go:305-450`
- Existing verification: TestSeveralExtensionsJoinInOrder shows two options join like one option, that order matters and that a duplicate extends twice, on both the record and probe sides. [exists_not_run]; TestTermExtensionMatchesRecordFieldContext checks that the probe context is deep-equal to the record field context under the same extension, and differs for another tenant or none. [exists_not_run]
- Missing verification: Nothing at runtime detects a probe whose extension does not match the stored rows. Only documentation (record.go:147-154) warns about double application.
- Mitigation: Keep the documented 'one option value held and passed to every call' guidance prominent (README does not yet mention ExtendContext or Term). Consider making the option idempotent or exposing a helper that returns the extended field Context, so callers can log or compare it.

**FS-2 · Extended Go probe does not match terms written by another language client under the same extension** (medium impact, speculative)

- Trigger: Rows are written by the Rust crate (encrypt_into_with_context) or another client with a tenant extension, then searched from Go with Term(..., ExtendContext(tenant)).
- Mechanism: The Go probe context is built as the nested-left list [[field, p1], p2] by Context.With (context.go:70) and sent to the guest's term call. Equivalence to Rust's extended field context is asserted in docs but tested only Go-record vs Go-probe (unit) and Go vs Go (live).
- Consequence: Cross-language tenant-scoped searches silently return no rows.
- Affects: languages/golang/stackencrypt (Context, record options, Cipher.Term), Stored terms written by other language clients (Rust encrypt_into_with_context)
- Evidence: `languages/golang/stackencrypt/doc.go:51-60`; `languages/golang/stackencrypt/live_test.go:224-250`
- Existing verification: TestLiveRecordsAndTerms checks a Go tenant probe equals a Go-written extended term, and differs from another tenant's and the unextended term (needs ZeroKMS credentials). [exists_not_run]
- Missing verification: A fixture or test comparing an extended Go probe against a term derived by the Rust crate under encrypt_into_with_context.
- Mitigation: Add a cross-language fixture (Rust-derived extended term in testdata) that the Go probe must equal.

**FS-3 · Downstream Go code stops compiling after the Term and RecordOption signature changes** (low impact, plausible)

- Trigger: A consumer declares an interface with the old `Term(ctx, any, Context, TermKind) (any, error)` signature (e.g. for mocking), takes a method value with that type, or treats RecordOption as a func type.
- Mechanism: Adding a variadic parameter changes Term's method type (cipher.go:99), so *Cipher no longer satisfies such interfaces. RecordOption is now an interface (record.go:91).
- Consequence: Build failure on upgrade. This is loud and caught at compile time, with no runtime or data effect.
- Affects: languages/golang/stackencrypt (Context, record options, Cipher.Term), Downstream Go applications using stackencrypt search probes and ExtendContext
- Evidence: `languages/golang/stackencrypt/cipher.go:99-111`; `languages/golang/stackencrypt/record.go:82-96` (base)
- Missing verification: Release notes or changelog entry noting the API change.
- Mitigation: Note the signature change in release notes.

### Recommended controls

- Confirm the tests-golang.yml go:test and live jobs pass on this change, including TestLiveRecordsAndTerms' tenant-probe assertions. (test; VG-1, FS-1)
- Add or run a fixture comparing an extended Go probe to a Rust-derived extended term. (compatibility_check; VG-2, FS-2)
- Review Cipher.Term (cipher.go:99-111) and extend()/contextExtension (record.go:117-175) to confirm the probe and record paths cannot diverge, and that the shadowed `context` parameter is used after extension. (review_focus; FS-1)
- Call out the Term signature and RecordOption kind change, and the tenant-probe usage, in release notes/README. (documentation; FS-3, FS-1)

### What this assessment could not see

- No PR description or CI results. The title describes only the byte-copy fix, not the Term/Option feature. Intent and test outcomes were inferred from code and test text.
- The guest (WASI/Rust) side of term derivation and the Rust crate's encrypt_into_with_context encoding were not read. Cross-language equivalence (FS-2) is unverified, so it is marked speculative.
- Downstream consumers outside this repository are unknown, and no module release/tag information was available. The breadth of FS-3 and FS-1 adoption cannot be estimated.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
