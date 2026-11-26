# Record fixture: `record_lowering.json`

One declaration, two authors, one engine. Typed Rust code (the engine's
combinators, `indexed(..).under(label)` and the rest, run over fields of type
`stack_encrypt::dynamic::ValueFrame`, the frame a binding's values arrive as)
and the data-plan lowering (`stack_encrypt::dynamic::record`, what a
language binding calls) each sealed the same plaintext under the same
declaration. The fixture's key for the first author is `typed_chain`: it was
first written by the plan chain, which is removed, and the combinators the
chain lowered to open and reproduce the same record. The fixture holds both records, with their term bytes, sealed
under a deterministic key source so they open in any process built from the
same seed. `tests/record_lowering.rs` opens each record with the other
author and checks that both derive the terms it holds. That cross-opening
checks that the two authors are compatible: they derive the same terms and
each opens the other's records. It does not by itself show how
`dynamic::record` runs. ADR-0007 (amended 2026-10-06) records the design
that it runs through the same engine and is not a second executor. A Go
test reads the same file later, once the Go SDK's generated code is the
third author.
Typed code over bare `u32` or `String` fields seals the same leaves too: every
leaf is tagged with its type (vitaminc ADR 0001), whoever wrote it.

Regenerate with `STACK_ENCRYPT_UPDATE_FIXTURES=1 cargo test -p
stack-encrypt --all-features --test record_lowering`. Only the sealed bytes
change between runs (every leaf carries a fresh nonce); the plan, the
plaintext and the terms must not, and the test fails if they do. Each test
rewrites only the entries it owns, so a filter on one test's name
regenerates one case and leaves the rest as committed. Do not edit the file
by hand.

## Schema

```json
{
  "_comment":   "what this file is",
  "key_source": { "kind": "deterministic-sha256", "seed": "<32 bytes, hex>" },
  "keyset_id":  "<uuid the leaves were sealed under>",
  "plan":       { "<field>": { "context": [...], "outputs": [...], "type": "<kind>" }, ... },
  "plaintext":  { "<field>": <value>, ... },
  "records": {
    "typed_chain": { "<field>": { "<output key>": <node>, ... }, ... },
    "lowering":    { "<field>": { "<output key>": <node>, ... }, ... }
  },
  "context_field": {
    "_comment":  "the same proof for a plan whose context is a field of the record",
    "plan":      { "context_field": "<field>", "<field>": { "context": ["<identity>"], ... }, ... },
    "plaintext": { "<field>": <value>, ... },
    "records":   { "typed_chain": { ... }, "lowering": { ... } }
  }
}
```

- **`context_field`.** A second case under the same key source and keyset:
  a plan that takes its context from a field of the record (the data
  grammar's plan-level `"context_field"` key). Its `plan` names the context field, each field's
  `context` is its identity alone, and the context field's node in each
  record is `"passthrough"` carrying the label the record was sealed under
  (`"tenants/acme"`); the sealed field's term is derived under
  `<that label>/<identity>`. `tests/record_lowering.rs` opens each record
  with the other author under the stored context and refuses it under
  another; the Go SDK's `encrypt` tests do the same through a generated
  type with a `context_field` tag.

- **`key_source`.** The test double in `tests/common/mod.rs`
  (`DeterministicSource`): every data key is `SHA-256(seed ‖ "key" ‖ 0 ‖
  descriptor ‖ 0 ‖ iv)`, its tag `SHA-256(seed ‖ "tag" ‖ 0 ‖ descriptor ‖ 0 ‖
  iv)`, and the IV `SHA-256(seed ‖ "iv" ‖ 0 ‖ descriptor ‖ 0 ‖ counter)[..16]`,
  where `descriptor` is the context the leaf was sealed under, rendered as
  ZeroKMS logs it (`users/age`). A reader that re-derives the key from a
  leaf's IV and its field's descriptor can open the leaf; a leaf moved under
  another field's label does not open, as it would not under ZeroKMS. The
  index key is `FakeDataKeySource`'s: `SHA-256("stack-kms::FakeDataKeySource::index-key::v1"
  ‖ keyset_id)`, the same every test in the repository derives terms under.
- **`plan`.** The declaration in the data grammar `dynamic::record::plan`
  parses: per field its label (a list of plain segments), its outputs (`"c"`,
  `"passthrough"`, or an index key `"eq"`, `"match"`, `"ore"`, `"ope"`) and its
  `"type"` (a vitaminc `ValueKind` name). The typed author writes the same
  declaration as one combinator per field under the label `users/<field>`,
  its indexes named as `IndexSpec`s over `ValueFrame` fields.
- **`plaintext`.** The value both authors sealed, each field as JSON at the
  kind `plan` declares for it.
- **`records`.** Each record in the stored shape, field by field, output by
  output: `"c"` is the field's ciphertext as the frozen `SealedValue` leaf
  bytes, hex (the storage encoding a database column holds, see
  `tests/frozen_bytes.rs`); an index key is the term's frozen bytes, hex (an
  equality term's raw 32 PRF bytes, an ORE term's raw CLLW bytes, a match
  term's little-endian `u16` positions); `"passthrough"` is the value as it
  is. The terms of the two records are identical; the ciphertexts are not
  (fresh nonces) but open under the same keys.

`label_segments.json` beside this file is a different fixture: the one rule
for a plain label segment, read by the Rust, derive and Go tests.

# Query fixture: `query_operators.json`

Queries named by operator through the data path
(`stack_encrypt::dynamic::query_term`, what a language binding calls), each
term equal to the one a typed query from a field reference
(`EncryptedUser::AGE.lt(40u32)`) derives for the same query, with a page `verify`
answered and fetch limits `target_limit` sized (ADR-0009; ADR-0007, amended
2026-10-16). `tests/query_operators.rs` derives every entry and checks it
against the typed path; the Go SDK's `encrypt` tests derive, verify and size
the same queries through the guest's `se_query_term`, `se_verify` and
`se_target_limit` exports and compare. No entry depends on a nonce, so the
file changes only when a derivation does: regenerate it with
`STACK_ENCRYPT_UPDATE_FIXTURES=1 cargo test -p stack-encrypt --all-features
--test query_operators`, and do not edit it by hand.

```json
{
  "_comment":     "what this file is",
  "key_source":   { "kind": "deterministic-sha256", "seed": "<32 bytes, hex>" },
  "keyset_id":    "<uuid the terms were derived under>",
  "plan":         { "<field>": { "context": [...], "outputs": [...], "type": "<kind>" }, ... },
  "queries": [
    { "field": "<field>", "operator": "<name>", "input": <value, or [lo, hi]>,
      "term": { "operator": "<name>", "fidelity": "exact" | "probabilistic",
                "index": "<index key>", "domain": null, "term": "<hex>" | ["<hex>", "<hex>"] } }
  ],
  "verify": { "field": "<field>", "operator": "matches", "input": "<text>",
              "values": [<text or null>, ...], "verified": [<bool>, ...] },
  "target_limit": [
    { "field": "<field>", "operator": "matches", "input": "<text>", "term": "<hex>",
      "want": <integer>, "stats": { "rows": <integer>, "histogram": [[<bits>, <rows>], ...],
      "confidence": <float> }, "limit": <integer or null> }
  ]
}
```

- **`key_source`**, **`keyset_id`.** As in the record fixture: terms derive
  under `FakeDataKeySource`'s index key for the nil keyset, whatever the
  seed, so the Go tests run the deterministic guest built from the same
  source.
- **`queries`.** Each query as a binding sends it, and its term in the wire
  form `QueryTerm::to_value` writes, the bytes in hex: one term, or for
  `between` the low bound's then the high's. An input is JSON, read as the
  field's declared type, so `40` queries the `uint32` field `age` and
  `1.5` the `float64` field `score`, whose terms are clww-ore's
  encryption of the float's ADR-0002 order key.
- **`verify`.** A page of decrypted values, null for an empty field, and the
  boolean `verify` answers for each, which is what the typed `MatchQuery`
  answers.
- **`target_limit`.** A match term's bytes, the statistics in the wire form
  `Stats::from_frame` reads (an absent histogram is the declared prior), and
  the limit, null when no finite fetch can be promised, which is what the
  typed `MatchQuery` answers.

# Value-kinds fixture: `value_kinds.json`

One field of each value kind a plan gained in #1144: `int8`, `int16`,
`uint8`, `uint16`, `int128`, `uint128`, `date`, `timestamp` and `decimal`.
The data-plan lowering sealed one record of them under the deterministic key
source, and the file holds that record, each value's transport frame, and two
equality queries whose input differs from the stored value but whose term is
the stored one. `tests/value_kinds.rs` checks that the record opens to the
values exactly, that the record path, the data query path
(`dynamic::query_term`) and the typed path derive the same terms, and that
the committed terms are today's. The Go SDK's `encrypt` tests read the same
file: the generated `testusers.ValueKinds` type, under the same context and
identities, parses each `text` into its Go type, writes it as the same
`frame`, opens the sealed record, and derives the same terms through the
deterministic guest.

Regenerate with `STACK_ENCRYPT_UPDATE_FIXTURES=1 cargo test -p stack-encrypt
--all-features --test value_kinds`. Only the sealed leaves change between
runs; the frames and the terms must not. Do not edit the file by hand.

```json
{
  "_comment":   "what this file is",
  "key_source": { "kind": "deterministic-sha256", "seed": "<32 bytes, hex>" },
  "keyset_id":  "<uuid the record was sealed under>",
  "plan":       { "<field>": { "context": ["value_kinds", "<field>"], "outputs": [...], "type": "<kind>" }, ... },
  "values": [
    { "field": "<field>", "type": "<kind>", "text": "<the value as text>", "frame": "<hex>" }
  ],
  "record":  { "<field>": { "c": "<hex>", "eq": "<hex>", "ore" | "ope": "<hex>" }, ... },
  "queries": [
    { "field": "<field>", "operator": "eq", "text": "<the input as text>", "frame": "<hex>", "term": "<hex>" }
  ]
}
```

- **`values`.** Each field's value, in the order the plan lists the fields.
  `text` is how a test spells it: a decimal integer for the integer kinds,
  `YYYY-MM-DD` for a date, RFC 3339 with nanoseconds in UTC for a timestamp,
  and a decimal with its scale (`-1234.5600` has scale 4) for a decimal.
  `frame` is the value's transport frame, hex: vitaminc's tag and payload
  (ADR-0002's table), which is also the plaintext a sealed leaf holds. A
  date's payload counts days from 0001-01-01 as day 1, a timestamp's is
  Unix seconds then nanoseconds, and a decimal's is rust_decimal's flags
  word and 96-bit mantissa, so the scale is kept.
- **`record`.** The stored record: `"c"` is the frozen `SealedValue` leaf,
  and each term its frozen bytes, as in the record fixture. Every field has
  an equality term; the 16-bit and wider integers, the date, the timestamp
  and the decimal have an ORE or OPE term too.
- **`queries`.** Queries vitaminc folds onto a stored term, for equality
  and for order alike: `-1234.56` finds the stored `-1234.5600` (the scale
  is normalised), and `…03.123456Z` finds the stored `…03.123456789Z` (a
  timestamp's terms are truncated to the microsecond; the ciphertext keeps
  every nanosecond).
  Each `term` equals the stored field's `eq`.

# Stored-rows fixture: `stored_rows_v1.json` (FROZEN)

Rows the `next` build stored, which every later build must still read. The
fixtures above prove that two authors of one record agree *today*, and are
regenerated when the encoding moves. This one is the opposite: it is written
once and **never regenerated**, and edited only as the exception below allows.
A change that alters the bytes of a stored row (the leaf encoding, the AAD, a
term derivation, the stored tree's shape) fails `tests/stored_rows.rs` instead
of being regenerated away.

`tests/stored_rows.rs` checks every case two ways:

- the stored tree opens, through `dynamic::record::decrypt`, to exactly the
  `opened` frame; and
- sealing `source` again under `plan` gives the same tree, apart from the
  sealed leaves (which carry a fresh nonce): the same shape and map keys in
  order, the same terms and the same passthroughs.

One declaration in the file is no longer accepted: an order index on a
`bytes` field (`blob` with `ore`, and the index-only `blob_ope`, in
`every_kind`). The file keeps it, because it records what was stored. The
test removes those indexes from the plan before it builds it, as a user
whose plan declared one must. It opens each row as stored, retired terms
included, under that plan. It seals the source again and compares the two
trees without the retired terms and without `blob_ope`.

Nothing reads `STACK_ENCRYPT_UPDATE_FIXTURES` for this file. The one test that
creates it, `write_stored_rows_v1`, is `#[ignore]`d and refuses to run when the
file exists. The check rewrites it only under
`STACK_ENCRYPT_REFREEZE_ORDER_TERMS=1`, for the exception below. The rows
depend on `stack_kms::DeterministicSource` and the seed below; both are part
of the frozen contract.

**If this test fails, the change broke stored data.** Do not regenerate the
file. Either fix the change, or, for a deliberate change to the stored
format, add `stored_rows_v2.json` (and a `write_stored_rows_v2`) beside this
one, keep v1, and say in the CHANGELOG how v1 rows migrate.

**Order terms are the one exception, until stack-encrypt 1.0.**
Until then a deliberate change to how an ORE or OPE term is derived may
re-freeze the `ore` and `ope` passthroughs that moved, and nothing else:
the leaves, the AAD, every other term and the shape stay as written. Run

```bash
STACK_ENCRYPT_REFREEZE_ORDER_TERMS=1 mise x --env test -- \
  cargo nextest run -p stack-encrypt --all-features --test stored_rows
```

It checks that every row opens as it did and that the resealed tree matches
the stored one in everything but its order terms' bytes, and only then
copies the new order terms over the old. Any other difference fails it and
nothing is written.

The change must also say in the CHANGELOG's `Breaking` section that its
order terms changed bytes, which released versions wrote the old ones, and
that a column holding them is to be encrypted again. That matters more than
the word "exception" suggests. An order term is never opened, only
compared, so a stale one is not refused: every `<`, `BETWEEN` and
`ORDER BY` over the column silently misses or misplaces rows, where a leaf
that no longer opens fails loudly. stack-encrypt 0.1.0 and 0.2.0 and the Go
module's v0.1.0-alpha.1 already shipped order terms. The exception rests on
those being pre-1.0 and pre-release, not on nobody holding one.

The exception has been used once beyond re-freezing: when `u8` and `i8`
lost their order term (a 256-value domain ranks every row, the leak a
`bool`'s order term is refused for), the `every_kind` case dropped the
`ore` terms of its `i8` and `u8` fields and its `i8_ope` and `u8_ope`
twin fields, which held only an OPE term. Its plan and source lost those
entries with them; every leaf, equality term and other order term is as it
was written.

## Schema

```json
{
  "_comment":   "what this file is",
  "key_source": { "kind": "deterministic-sha256", "seed": "<32 bytes, hex>" },
  "keyset_id":  "<uuid the leaves were sealed under>",
  "cases": [
    {
      "name":             "<case name>",
      "about":            "<what the case covers>",
      "plan":             { "<field>": { "context": [...], "outputs": [...], "type": "<kind>" }, ... },
      "source":           "<the plaintext record (or batch) as a transport frame, hex>",
      "expected_context": "<the context decrypt is told to expect>" | null,
      "stored":           <node>,
      "opened":           "<the frame decrypt returned, hex>"
    }
  ]
}
```

A `<node>` is one stored-tree node, an object with one key: `{"leaf": hex}`
(a `SealedValue`'s frozen bytes), `{"seq": [<node>, ...]}`, `{"empty_seq":
hex}`, `{"map": [[key, <node>], ...]}` (in stored order), `{"empty_map":
hex}`, or `{"passthrough": hex}` (the payload's frame; a term is a
passthrough of its bytes).

The cases:

| Case | Covers |
| --- | --- |
| `every_kind` | one field per value kind with every index it admits (OPE on a twin field), the non-default match options, an array and an object (with empty containers), an untyped field, a field whose key is not its label's last segment, and a passthrough |
| `three_segment_label` | labels of three segments |
| `one_extension_part` | every label extended by an integer part |
| `two_extension_parts` | every label extended by an integer part, then a text part |
| `context_field` | a plan whose context is the record's tenant field, opened expecting it |
| `batch` | a batch of two records under one plan |

# Value-bytes fixture: `value_bytes_v1.json`

The bytes of every way a plaintext value is written, for each scalar kind
the engine takes: its transport frame, and the plaintext its sealed leaf
holds, on the typed Rust path and on the dynamic record path. The other
fixtures pin frames and terms, and open stored leaves. A leaf carries a
random AES-GCM nonce, so none of them compares the plaintext a leaf was
sealed with. `tests/value_bytes.rs` seals each value under the
deterministic key source, keeps the data keys it generated, opens each leaf
with them and the engine's leaf AAD, and compares the plaintext with this
file.

It pins today's behaviour, including rules that may change on purpose. A
change to one of them is a reviewed change to this file. Regenerate with
`STACK_ENCRYPT_UPDATE_FIXTURES=1 cargo test -p stack-encrypt --all-features
--test value_bytes`, then run `pnpm run code:fix` to format it. The test
compares the parsed file, not its text, and compares all of it, so a key
it no longer writes fails it. Nothing in it depends on a nonce. Do not edit it
by hand.

```json
{
  "_comment":   "what this file is",
  "key_source": { "kind": "deterministic-sha256", "seed": "<32 bytes, hex>" },
  "context":    ["conformance", "value"],
  "typed":      { "<Rust type>": { "frame": "<hex>", "leaf": "<hex>" }, ... },
  "dynamic":    { "<kind>": { "text": "...", "frame": "<hex>", "value": <outcome>,
                              "null_sealed": <outcome>, "null_sql": <outcome> }, ... },
  "host":       { "<case>": { "type": "<kind or empty>", "host_frame": "<hex>",
                              "frame": "<hex>" | { "refused": true }, "value": <outcome> }, ... },
  "host_typed_null": { "frames": { ... }, "<case>": <outcome>, ... },
  "json":       { "typed_leaf": { ... }, "opened_frame": "<hex>",
                  "record_without_target": <outcome>, "untyped_text": <outcome> }
}
```

An `<outcome>` is what the record path did with one row whose field
`value` has that plan: `{"leaves": [hex, ...]}`, the plaintext of each leaf
of the field's ciphertext in walk order (an empty container's marker is
`""`); `{"stored": "sql_null"}`, no ciphertext stored; `{"refused":
"<code>/<reason>"}` or `{"plan_refused": "<code>/<reason>"}`; or
`{"frame_refused": true}`, refused by `ValueFrame::check` before the plan
is read.

- **`typed`.** Each Rust type sealed alone by `encrypt_tree`: its frame as
  `vitaminc_aead::to_frame` writes it, and its leaf. A `None` of a
  fixed-width type seals as a typed null of that type (`0x15`, the type's
  tag, zeros), as long as a value. A `bool`'s `None` is the exception: a
  bool leaf is one byte, so its null is the plain null `00`, which is as
  long. A `None` of any other type is the plain null.
  A text or bytes frame carries a four-byte length that its leaf does not.
- **`dynamic`.** One value per kind a data plan declares, as a binding
  sends it, through `record::encrypt`: the frame, the stored leaf, and a
  null under `"null": "sealed"` and `"null": "sql"` (a sealed `bool` null
  is `00`, as on the typed path). `untyped_object` is an untyped field
  holding an object with an array and two empty containers: each scalar is
  a leaf and each empty container a marker. `untyped_null` is a null in an
  untyped field.
- **`host`.** Frames a host writes that no Rust value here writes: a
  timestamp in seconds, milliseconds (a JavaScript `Date`) or
  microseconds, which the engine rewrites to nanoseconds; a nanosecond
  timestamp and a date (2024-02-29) over an `i64` in the `0xF3` envelope,
  which the engine refuses because each has a shorter tag of its own; a
  UUID, which it refuses; `undefined`, which an untyped field seals as
  written and a typed field refuses; and an `f64` for a `float32` field,
  which it refuses. The two millisecond frames are the frames the
  JavaScript bridge writes for `new Date(123)` and `new Date(-1)`;
  `scripts/__tests__/recipher-js-frame-parity.test.mjs` holds them to
  the bridge's pinned frames.
- **`host_typed_null`.** A typed null a host sends. The frame keeps no
  type, so an untyped field, and an array inside one, seal the plain null.
  A typed field refuses it with no `"null"`, stores nothing under
  `"sql"`, and under `"sealed"` seals the typed null of its own declared
  type, whatever type the host sent.
- **`json`.** Opaque JSON, a document sealed as one value. A
  `JsonPlaintext` on the typed path is a text leaf of its compact JSON. A
  document a `json` field opens to is a bytes frame (`json_frame`). A data
  plan's `json` field needs a target and is refused without one; through
  EQL's opaque `Json` target it seals the same text leaf, which
  `packages/eql/tests/encryption/tests/opaque_json_bytes.rs` pins. An
  untyped field holding the same text seals it as a text leaf. The JSON
  tree (EQL's `JsonSearch`) is another scheme, sealed by the JSON index,
  and is not in this file.
