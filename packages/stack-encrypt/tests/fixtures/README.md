# Record fixture: `record_lowering.json`

One declaration, two authors, one engine. A Rust chain
(`cipher.encrypt(&user).context("users").fields()…`, over fields of type
`stack_encrypt::dynamic::Value`, the plaintext type a binding's values have)
and the data-plan lowering (`stack_encrypt::dynamic::record`, what a
language binding calls) each sealed the same plaintext under the same
declaration. The fixture holds both records, with their term bytes, sealed
under a deterministic key source so they open in any process built from the
same seed. `tests/record_lowering.rs` opens each record with the other
author and checks that both derive the terms it holds. That cross-opening
is the proof that `dynamic::record` is a lowering into the plan builder and
not a second executor (ADR-0007, amended 2026-10-06). A Go test reads the
same file later, once the Go SDK's generated code is the third author. A
chain over bare `u32` or `String` fields derives the same terms but a
different leaf encoding, which the other reader cannot open or tell apart;
`dynamic::record`'s docs say why the lowering does not bridge that.

Regenerate with `STACK_ENCRYPT_UPDATE_FIXTURES=1 cargo test -p
stack-encrypt --all-features --test record_lowering`. Only the sealed bytes
change between runs (every leaf carries a fresh nonce); the plan, the
plaintext and the terms must not, and the test fails if they do. Do not edit
the file by hand.

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
  }
}
```

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
