# Record read profile

`record-reads-v1` adds shared cases in `v1/reads.json` for stored record
shapes, authenticated type checks and context preflight. It fixes the resolver
to `NoTargets`. It is experimental and covers native Rust and Go WASI.

## Inputs and observations

Each case has separate `write` and `read` declarations, each naming the `kind`
and `null` policy of `value`. Outputs are ciphertext and equality. `rows` uses
the runtime profile's typed scalar representation. Runners first encrypt these
rows successfully, then apply the named `mutation` to its zero-based `row`.
This supplies real ciphertext, including for negative reads.

Without `context_field`, the context is `["conformance", "value"]`. With it,
`tenant` is a string passthrough supplying the row context; `value` is its
field identity. An optional `expected_context` constrains the stored context.
Omit it for an unrestricted read; when present it must be a nonempty plain
label string. Explicit JSON null is invalid, not another spelling of omission.

`expected` describes the native opener's stage, complete diagnostic code and
payload on refusal, typed ordered rows on success, and data-key retrieval
call count. Runners must reject unknown stages, mutations, capabilities,
profiles and input types. Cases have unique, nonempty IDs.

| Stage | Native observation | Retrieval calls |
|---|---|---|
| `shape` | `record::decrypt` refuses before returning a pending operation | 0 |
| `preflight` | The pending opener refuses before requesting keys | 0 |
| `authenticated` | Shape checking passes; opening the authenticated value finds a type mismatch | 1 |
| `success` | Opened rows match all expected values, types and ordering | 1 when ciphertext is present; 0 for the all-absent SQL-null case |

Counters are reset after fixture encryption. Reads must never generate data
keys. These counts observe native data-key calls, not index-key initialization
or Go's logical provider calls.

`check_error` independently describes `record::check_record`, which needs no
cipher. An absent `check_error` requires acceptance. The Go guest runs this
check before looking up its cipher state. Both an uninitialised guest and a
configured cipher execute each case (subject to the host context refusal
described below): guest preflight errors must have the specified
diagnostic in either; accepted shapes must reach `ErrState` without a cipher.
Consequently, a concealed type mismatch must pass preflight and fail only when
the active guest opens it.

The Go runner uses a test-only entry point to the existing `se_decrypt_record`
export. This permits shapes the host's `record.Sealed` type cannot express,
including a passthrough directly under `c`. It uses the binding's existing
tree codec, Cipher validation/context/extension, production decoding and
transport-buffer cleanup. Only the uninitialised checker deliberately bypasses
host plan checks to observe the guest boundary. Cases marked `adapter` also
run the normal `Cipher.Open` path; they retain their original stored shape.
This does not certify generated SDK mappings.

## Required behavior

- Missing required fields, missing ciphertext outputs, non-map rows or field
  outputs, and plaintext passthroughs under ciphertext are refused before keys.
- A malformed later row rejects the batch before retrieval.
- Reads project the fields and outputs the plan opens. Extra stored fields,
  extra outputs and missing equality outputs do not prevent reading ciphertext.
  Writes still reject unknown source fields, as the runtime profile requires.
- Reading int32 ciphertext as int64, uint64 or string fails after retrieval.
  Reads do not apply the query path's lossless numeric conversion.
- A sealed null cannot open through a required declaration. It can open through
  a SQL-null declaration, with retrieval because ciphertext is present.
- An absent SQL-null field opens as null without retrieval. A required or
  sealed-null read declaration refuses the same missing field.
- Context-field reads work without an expected label or with a matching label.
  A mismatch, including one in a later row, refuses the whole batch before keys.
- Missing context fields, missing passthrough payloads and non-string context
  values fail before retrieval.
- A static-context plan cannot also take a call context. Native `check_record`
  and the guest report `dynamic_record` with reason `refused`; the native pending
  opener reports `plan_two_context_sources`, naming the plan and the call.
  The corpus records both engine diagnostics explicitly. Go's configured
  `Cipher.Context(...).Open` refuses this combination earlier in `Cipher.plan`
  with `ErrEncoding`. The case also exercises that host refusal through both
  `Open` and the validated tree hook; it does not require its English wording
  or the absence of a diagnostic.

Context-mismatch diagnostic payloads expose only stored descriptor length and
part count, not its value. Go diagnostic numeric metadata is compared as JSON
numbers; plaintext comparisons retain actual host types.

## Mutation vocabulary

| Mutation | Change to the selected row |
|---|---|
| `none` | Preserve it |
| `drop_value` / `drop_c` / `drop_eq` | Remove the named field or output |
| `field_plain` / `c_plain` / `row_plain` | Replace that node with an int32 passthrough |
| `extra_field` / `extra_output` | Add an `extra` int32 passthrough at that level |
| `drop_tenant` | Remove the context field |
| `tenant_no_payload` | Replace its output map with an empty map |
| `tenant_number` | Replace its passthrough string with an int32 |

## Scope and consolidation

The existing native record tests retain repeated keys, invalid leaf framing,
other tree forms, context extensions and wider type/output combinations. Go's
tree encoder accepts maps with unique keys, so repeated-key transport cases
need a separate raw-byte profile rather than being silently skipped here.

The existing Go context-field suite retains generated SDK calls, query context
selection, extension behavior and stored-context tampering. The deterministic
provider's wrong-context refusal remains covered there and by the scalar
profile. This profile observes preflight context checks, not every context
composition or cryptographic tampering case.

No existing tests are removed. Python and TypeScript runners, EQL/JSON read
shapes, provider failures, version compatibility and runtime artifact exchange
remain follow-up work.

Opened row order follows the input batch. Within a row the engine emits fields
in declaration order. Both runners
construct declarations with the context field first, followed by recoverable
fields. Native expected frames use that order; Go's shared production decoder validates it
before converting objects to maps. `context_field_name` may override the default
`tenant` name when `context_field` is true; a `zone` case prevents lexical object
ordering from masquerading as declaration ordering.

Both runners require `context_field`, `adapter`, and `mutation.row` (including
explicit false/zero values), reject empty supplied `expected_context`, and reject
contradictory stage, check-error and retrieval-count expectations. The Rust runner
collects per-case failures so later cases still execute after an earlier failure.
