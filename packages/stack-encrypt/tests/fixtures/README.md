# Record fixture: `record_lowering.json`

One declaration, two authors, one engine. A Rust chain
(`cipher.encrypt(&user).context("users").fields()…`, over fields of type
`stack_encrypt::dynamic::ValueFrame`, the frame a binding's values arrive as)
and the data-plan lowering (`stack_encrypt::dynamic::record`, what a
language binding calls) each sealed the same plaintext under the same
declaration. The fixture holds both records, with their term bytes, sealed
under a deterministic key source so they open in any process built from the
same seed. `tests/record_lowering.rs` opens each record with the other
author and checks that both derive the terms it holds. That cross-opening
is the proof that `dynamic::record` is a lowering into the plan builder and
not a second executor (ADR-0007, amended 2026-10-06). A Go test reads the
same file later, once the Go SDK's generated code is the third author.  A
chain over bare `u32` or `String` fields seals the same leaves too: every
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
  a plan that takes its context from a field of the record (the Rust
  chain's `FieldsBuilder::context_field`, the data grammar's plan-level
  `"context_field"` key). Its `plan` names the context field, each field's
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
  `"type"` (a vitaminc `ValueKind` name). The Rust chain writes the same
  declaration as `Plan::context("users").fields()` with one verb per field,
  its indexes named as `IndexSpec`s over `Value` fields.
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
term equal to the one the typed query chain (`cipher.query(op::Lt,
&40u32).on(&plan)`) derives for the same query, with a page `verify`
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
