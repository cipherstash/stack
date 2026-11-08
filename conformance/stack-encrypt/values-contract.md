# Record value-kind profile

`record-values-v1` describes the cases in `v1/values.json`: every kind the
engine names, at its boundaries, through the record path with no EQL
resolver. It is an experimental test contract for native Rust and Go WASI.
Python and TypeScript runners remain pending.

The earlier scalar, runtime and fixture profiles are representative. This
profile is the boundary matrix they left open: the narrow and 128-bit
integer edges (the 32- and 64-bit edges are the scalar and runtime
profiles'), 32-bit floats, the float specials, bytes, decimal scale and
mantissa limits, date and timestamp precision, sealed nulls for every
fixed-width kind the runtime profile does not already seal (it has
`int32`, `int64`, `uint64` and `float64`), SQL nulls, and the write
refusals between kinds.

The runners are `packages/stack-encrypt/tests/value_conformance.rs` and
`languages/golang/encrypt/value_conformance_test.go`.

## Cases

Each case declares one field, `value`, under context `["conformance", "value"]`,
with `kind`, a `null` policy (empty, `sql` or `sealed`) and an `outputs` list
that starts with `c`. Values use the scalar profile's `{type, text}` form,
extended to every kind:

| `type` | `text` |
|---|---|
| `bool` | `true` or `false` |
| `int8` … `int128`, `uint8` … `uint128` | canonical base-10 integer at exactly that width |
| `float32`, `float64` | the canonical spelling of a representable value (below), or `inf`, `-inf`; `-0` is negative zero |
| `string` | the literal text, control characters included |
| `bytes` | the bytes in lowercase hex, possibly empty |
| `date` | `YYYY-MM-DD`, proleptic Gregorian |
| `timestamp` | RFC 3339 in UTC, `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, at most nine fraction digits |
| `decimal` | fixed-point text keeping every trailing zero; the scale is the number of fraction digits |
| `null` | empty |

A float's canonical spelling is built from the shortest decimal digits
that parse back to the value at its width. Spelled positionally (Rust's
`{}`, Go's `strconv.FormatFloat(f, 'f', -1, bits)`: `34`, `-0`, `0.5`,
`9007199254740992`) and scientifically (Rust's `{:e}`, Go's
`strconv.FormatFloat(f, 'e', -1, bits)` with the exponent's `+` and leading
zeros removed: `1e3`, `3.4028235e38`, `5e-324`), the shorter of the two is
canonical, and the positional one on a tie (`100`, not `1e2`). Both
runners refuse any other text that parses to the value as a corpus error:
`1.00`, `1.0`, `1e0`, `1000`, `1e+3`, `1E3`, `+1`, `.5`, `-0.0`, `0.001`,
`Inf`, a rounded decimal. Rust's
`the_float_reader_accepts_only_the_canonical_spelling` and Go's
`TestConformanceFloatSpelling` hold both readers to the same accepted and
refused lists.

Runners construct real typed host values: Rust reads each integer at its
width and each logical type over its physical scalar; Go uses its own
integer types, `float32`, `[]byte`, and the SDK's `Int128`, `Uint128`,
`Date`, `Decimal` and `time.Time`. No value passes through a JSON number or
a floating-point conversion. A text the type cannot carry is a corpus
error in both runners, never a rounded value. `NaN` is excluded: hosts do
not agree on its equality, so a corpus row could not be compared.

Every non-null input carries `frame`, its frozen typed transport frame in
hex. Both runners encode the host value and compare it byte for byte,
which pins the width, the logical type tag, the decimal scale and the
timestamp's nanoseconds. The Rust helper that parses the text forms is
held to the frames the value-kinds fixture froze for the same spellings.

## Required behavior

For a case with no `expected_error` whose input is not null:

1. The typed frame equals the frozen `frame`.
2. One record of the input seals, storing ciphertext and exactly the
   declared indexes, with one batched data-key generation.
3. Every stored term is the term a query of the same value derives: `eq`
   for the equality index, `lt` for an order index. A query makes no key
   call. With `equal_query`, that other spelling derives the stored
   equality term too (a decimal without its trailing zeros; a timestamp
   truncated to the microsecond).
4. The record opens to the input with its type, with one batched retrieval.

The key-call counts (one generation, no call per query, one retrieval) and
the refusals' "no key call" are native observations: the Rust runner counts
them on its key source. The Go runner checks everything else; its
deterministic guest has no call counter to read.

A null input carries no `frame`, so requirement 1 does not apply to it.
A sealed null (`"null": "sealed"`, input `null`) meets requirements 2 and
3: it stores ciphertext and the declared indexes with one batched
generation, and a null equality query derives the stored equality term
where one is declared. It opens as null with one batched retrieval, and its `companion` value row's ciphertext has the same
length. A SQL null (`"null": "sql"`, input `null`) meets none of
requirements 1 to 4: it stores no record, so no data key is generated, no
term exists to compare and no ciphertext is opened; its row reads back as
null.

`unanswered` lists stored indexes no query operator answers for the kind. A
query of such an index is refused as `operator_not_answered` in both
runners. Today that is the order index on `bytes`: the declaration admits
it and the engine stores an order term, but no dynamic operator reads it.
Recording it here keeps the gap visible instead of silently skipping it.
Step 1 of the API plan's order of work declares each index's operators
and admitted plaintexts once. That closes the gap one of two ways: an
operator reads the index, or the declaration is refused. Refusing it must
keep data that Go rc.3 stored readable.

`expected_error` cases are refused before any pending operation, with the
structured diagnostic `code`, `reason` and `field`, and no key call. They
cover a value of another width or kind for every new kind (an `int16` for
an `int8` field, an `int64` for an `int128` field, a `float64` for a
`decimal` or `float32` field, an `int32` for a `date`, text for `bytes`,
bytes for `string`, an integer for `bool`) and a null for a required
`bool`, `bytes` or `decimal`. A losslessly convertible value of another
width is still refused on the write path, as the runtime profile says.

## Unsupported host conversions

`host_conversions` lists values a binding's host refuses before the engine
sees them. Each names its `language`; today every entry is `go`. The
`value` is one of a closed vocabulary both runners check:

| `value` | The Go value | Why the host refuses it |
|---|---|---|
| `zero_date` | `encrypt.Date{}` | The zero `Date` is not a date |
| `decimal_scale_29` | `encrypt.Decimal{Scale: 29}` | A decimal's scale is at most 28 |
| `timestamp_year_300000` | `time.Date(300000, …)` | Outside the timestamp decoder's range |
| `complex128` | `complex(1, 2)` | No transport leaf carries a complex number |
| `map_int_key` | `map[int]string` | Object keys are text |
| `channel` | `chan int` | Not a value |

Go refuses each through `Seal` and `QueryTerm` with `ErrEncoding` and no
engine diagnostic, which shows the guest was never asked. Native Rust has
no host conversion layer: the typed API cannot spell these values, and the
dynamic API takes frames. Its runner checks the entries' shape and
vocabulary and runs none of them. Python and TypeScript will add their own
rows (bool/int, bytes/text, Number/bigint) when their runners exist.

## Scope and remaining work

The profile covers the record path and equality/order terms under
`NoTargets`. Match terms, EQL targets, JSON documents, context fields and
fresh cross-language artifact exchange of these kinds remain the other
profiles' coverage. Dates before year 1 and the ends of the timestamp range
are not in the corpus: Go's date parsing does not read them, and the
engine's bound is the decoder's. Negative-zero decimals are not in the
corpus because Go's `Decimal` drops the sign of a zero before sealing.

No existing fixture or test is changed. The value-kinds fixture keeps its
typed Rust comparisons and generated Go methods.
