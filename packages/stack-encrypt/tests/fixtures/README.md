# Record fixture: `record_lowering.json`

One declaration, two authors, one engine. A Rust chain
(`cipher.encrypt(&user).context("users").fields()…`, over fields of type
`stack_encrypt::dynamic::FfiValue`, the plaintext type a binding's values have)
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
  field's declared type, so `40` queries the `uint32` field `age`.
- **`verify`.** A page of decrypted values, null for an empty field, and the
  boolean `verify` answers for each, which is what the typed `MatchQuery`
  answers.
- **`target_limit`.** A match term's bytes, the statistics in the wire form
  `Stats::from_value` reads (an absent histogram is the declared prior), and
  the limit, null when no finite fetch can be promised, which is what the
  typed `MatchQuery` answers.
