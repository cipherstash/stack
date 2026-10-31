# Record declaration grammar

Use this contract when a binding lowers an SDK declaration to the engine's record
plan. Send the complete plan to the engine checker before executing it.

For example, this declaration seals and equality-indexes an int64 field:

```json
{
  "value": {
    "context": ["users", "value"],
    "outputs": ["c", "eq"],
    "type": "int64"
  }
}
```

Run the executable cases with `mise run test:conformance`, after building the
deterministic test guest as described in [README.md](README.md).
`ciphertext-untyped`, `index-only`, and every `type-*-eq` case exercise these forms.

## Scope and authority

`record-declarations-v1` describes the engine at PR #1404's `b684a217e`, not future
SDK syntax. It is an experimental conformance profile, not a new production wire
version. The input is a Vitamin C **typed transport frame**. JSON below is a
readable projection; it cannot distinguish every integer width or carry bytes.

The executable authority is `stack_encrypt::dynamic::record::plan_with`, with the
selected target resolver. Native `record::plan` and the Go guest without EQL use
`NoTargets`. The corpus fixes that resolver explicitly as `none`. It checks
target syntax and unavailable-target refusals; it does not certify EQL targets.

The full contract has three parts: frame validity, the structural grammar below,
and the semantic constraints. A shape-only JSON Schema would not enforce the
context, index, null or resolver rules. SDK tooling must ask the engine instead
of implementing those rules again. Test runners convert fixture values and
observe results; they do not provide another semantic validator.

## Structural grammar

This is a typed grammar. `Object{...}` denotes a transport object, `List<T>` a
transport array, `?` an optional member, and `|` an alternative. Literal words
denote text values. Each object has exactly the listed keys, except `Plan`, whose
non-reserved keys are field names. Object key order is unrestricted.

```text
Plan = Object{
  "context_field"?: Text,
  (FieldName: FieldSpec)+
}
FieldName = Text except "context_field"

FieldSpec = Object{
  "context": FieldContext,
  ("outputs": NonEmptyList<Output> | "target": Target),
  "type"?: ValueKind,
  "null"?: "sealed" | "sql"
}

FieldContext = Label | [FieldContext, ContextScalar]
Label = NonEmptyList<PlainSegment>
ContextScalar = Text | Bytes | Int32 | Int64 | UInt32 | UInt64

UnitOutput = "c" | "passthrough" | "eq" | "ore" | "ope" | "ore_block"
Output = UnitOutput | Object{UnitOutput: Null}
       | "match" | Object{"match": Null | MatchOptions}
       | "json" | Object{"json": Null | JsonOptions}

MatchOptions = Object{
  "tokenizer"?: Tokenizer,
  "downcase"?: Bool,
  "short_words"?: Bool,
  "k"?: Integer,
  "m"?: Integer
}
Tokenizer = "standard" | Object{"standard": Null}
          | Object{"ngram": Integer}

Target = NonEmptyText | Object{
  "name": NonEmptyText,
  "options"?: JsonOptions
}
JsonOptions = Object{
  "sealed_root"?: Bool,
  "ordered"?: List<JsonPathText>
}

ValueKind = "bool"
          | "int8" | "int16" | "int32" | "int64" | "int128"
          | "uint8" | "uint16" | "uint32" | "uint64" | "uint128"
          | "float32" | "float64" | "decimal" | "date" | "timestamp"
          | "string" | "bytes" | "array" | "object" | "json"
```

`outputs` and `target` are exclusive and one must be present. Present optional
members must have the declared type: `"type": null` is not omission.
The explicit null alternatives for enum payloads are exceptions, pinned by the
`unit-output-null-*` and `match-default-*` cases. Unknown keys and output/type
names fail; no unknown option is ignored.

`Integer` here means an integer-valued transport tag accepted by the option's
integer reader, within its bounds. It does not mean a floating-point value that
happens to be integral. Width is not an option's identity. Context integer width,
in contrast, is part of context identity and must survive parsing unchanged.

Every object key must be unique, including keys nested inside options. The frame
must contain exactly one complete value within the codec's depth and size bounds.
Duplicate keys, truncation and trailing data fail before declaration semantics.
Do not change these codec rules in this specification.

## Context semantics

Try the `Label` alternative before decomposing an extension. A flat text list
is a label; `["users", "region", "value"]` has three segments. It is not the
extended context `[["users", "value"], "region"]`. Extensions nest to the left.
An extension is scalar, so `[["users", "value"], ["tenant"]]` is refused.
Bare `"users/value"` is not a field label.

A plain segment is nonempty and cannot contain `/`, parentheses, control
characters, or the invisible format characters listed by `Label::check_segment`
in `packages/stack-encrypt/src/descriptor.rs`. It cannot start with `b64:`, `-`,
or an ASCII digit. That shared label rule is referenced rather than reimplemented
by a binding. It applies to label segments, not SDK variable names.

Without `context_field`:

- Every field label has at least two segments.
- The last segment is the field's identity. All preceding segments form the
  plan label, which must agree across fields.
- All fields have the same ordered extension values, including their types.
- Sealed/indexed field identities cannot collide. The field's map key and its
  identity may differ; renaming a map key does not implicitly change its label.

With `context_field`:

- Its value names a declared field, whose sole output is `passthrough`.
- That field declares `string` or omits `type`; omission resolves to `string`.
- Every field label has exactly one segment: its identity.
- Extensions still agree across fields. No target field is admitted.
- At execution, each record supplies the named field's label value. Its validity
  and the opener's expected-context constraint are runtime requirements.

The grammar does not add call-time context roles or defaults. Context composition
is observed by `extended-context`, `flat-label-is-not-extension`, the
`typed-extension-*` cases, and the mixed-context refusals.

## Output and kind semantics

An output list is nonempty. Output keys are unique after reading their options:
two differently configured match indexes still collide on `match`.
`passthrough` is always the sole output. Ciphertext is explicit; an index-only
declaration does not implicitly acquire `c`.

Every field with a scalar index declares `type`. Ciphertext-only and passthrough
fields may omit it. Declaring a kind checks values during execution; it does not
select a different leaf encoding.

| Declared kind | `eq` | `match` | `ore`, `ope`, `ore_block` |
|---|---|---|---|
| bool | Refused | Refused | Refused |
| int8, uint8 | Admitted | Refused | Refused |
| Other integer widths | Admitted | Refused | Admitted |
| float32, float64, decimal, date, timestamp | Admitted | Refused | Admitted |
| string | Admitted | Admitted | Admitted |
| bytes | Admitted | Refused | Admitted |
| array, object, json | Refused | Refused | Refused |

The corpus explicitly tests all 21 kinds against all five scalar indexes.
`array` and `object` may still be sealed without indexes. A `json` field requires
a document target. A raw `json` output has a recognized syntax but is refused as
`json_index_pending`; it is not an alternative to a document target.

Match defaults are 3-grams, `downcase: true`, `short_words: false`, `k: 3`, and
`m: 256`. Every missing option takes its default. The bounds are:

- `3 <= k <= 16`.
- `m` is a power of two from 32 through 65536.
- N-gram length is nonzero and representable by the implementation's integer reader.
- `short_words: true` requires n-grams of length at least three.

Standard tokenization cannot enable short words. An invalid option fails when
the declaration is checked, before values or keys are needed.

## Null semantics

Omitting `null` keeps the field required. A typed field then refuses null values;
an untyped value's ability to represent null is not an implicit nullable column.
`null` is a storage policy, distinct from a null option payload or a missing key.

| Policy | Declaration requirements | Runtime meaning |
|---|---|---|
| `sql` | Any non-passthrough field | Missing/null source leaves no encrypted field output; the host stores SQL NULL |
| `sealed` | A fixed-width bool, number, decimal, date or timestamp; only equality indexes, if any | Missing/null source is sealed with type-appropriate padding; equality uses the field's null term |

Text, bytes and composite kinds cannot request sealed null. Passthrough cannot
request either policy. These cases check declaration admissibility only; runtime
padding, queries, missing values and round trips retain their existing tests.

## Targets and JSON options

Target syntax is parsed before resolver lookup. `options` takes JSON-index
options; a null options object or unknown option is an invalid target.
`sealed_root` defaults to true, and `ordered` to an empty set.
Paths are parsed by `JsonPath::parse`; ordered paths cannot select array positions.
Repeated equivalent paths collapse into the set.

Under this profile's `none` resolver, every otherwise valid target produces
`stack_encrypt::target_none` with its target name. A missing target capability
must never silently turn into a ciphertext-only field.

For a resolver that supplies EQL types, additional existing rules apply: the
target must be producible, its column label has exactly two segments, and the
plan has neither extensions nor a context field. An explicit kind matches the
target's plaintext kind; otherwise that kind is inferred. Only a document target
accepts JSON options. Sealed-null rules include the target's own indexes.
Those resolver-dependent outcomes and normalization need an EQL profile; this
corpus does not claim they have been verified across bindings.

## Normalization observations

The native runner observes the parsed plan directly. Its `normalized` fixture
field is a test report, not a canonical production serialization:

- `label` and `context_field` identify the resolved context source.
- `extension` lists typed scalar parts, preserving width and order.
- `fields` retains transport field order, label segments, resolved kind,
  null policy and output order.
- Unit output aliases become bare keys. Default match options become `"match"`.
  Non-default match options are explicit; `short_words` is emitted only when true.

No binding should sort production fields, flatten contexts, coerce context
integers, or infer omitted ciphertext outputs from these observations.
`frame-field-order` checks field order independently of the JSON projection.

The Go plan-check export returns success or a diagnostic, not a normalized plan.
Its runner therefore verifies acceptance and diagnostics. It does not claim an
independent observation of normalization or add a production export for testing.

## Diagnostics and corpus format

The corpus is `v1/declarations.json`. Its version, profile and resolver are
required. Case IDs are unique and stable. Every case contains exactly one input:

- `{"json": value}` converts JSON objects in lexical key order. Nonnegative
  integers become uint64, negative integers int64, and fractional values float64.
  Arrays preserve order. This is fixture conversion, not SDK policy.
- `{"frame_hex": text}` supplies exact transport bytes, including typed contexts,
  original field order and malformed frames that JSON cannot represent.

`accepted` is mandatory. Refused cases require `expected_error`, containing the
native engine diagnostic code and structured payload. Accepted cases may include
`normalized`. Runners reject unknown corpus keys and contradictory outcomes.

A malformed transport frame also has `boundary_error`. The native parser reports
`stack_encrypt::dynamic_plan` with `not_an_object`; the WASI frame check reports
`stack_guest_abi::malformed_input` before reaching that parser. Both runners verify
the frame really is malformed. Valid-frame declaration errors must agree exactly
on code and payload; Go also requires `ErrEncoding`. Error prose is not contractual.

Cases isolate a failure where practical. This profile does not define universal
error precedence for declarations containing several independent faults.
Neither runner initializes a cipher to check declarations. The Go checker has
no credentials and uses a refusing transport.

## Evidence and limits

The corpus covers 201 cases: 91 accepted and 110 refused, including the complete
scalar kind/index matrix. The native runner also checks selected normalization
observations. Existing codec tests own exhaustive frame validity, depth limits,
and integer-reader behavior. Existing EQL tests own resolver/catalog behavior.
Runtime operations and language-specific declarations remain separate layers.

See [coverage.md](coverage.md) for the consolidation policy. New Python and
TypeScript runners can adopt these inputs and expectations without copying the
engine's validation rules.
