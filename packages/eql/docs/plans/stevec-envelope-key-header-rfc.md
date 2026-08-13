# RFC: SteVec envelope key header + selector-derived nonces

**Status:** Draft
**Created:** 2026-07-18
**Authors:** Dan Draper (with Claude assistance)
**Related design:** Value-inclusive selectors; `eql-payload-scheme-discipline-rfc.md`

## Summary

The SteVec (`sv`) wire format currently stores a **complete, self-describing
`EncryptedRecord`** in every entry's `c` field: IV, AEAD ciphertext, ZeroKMS
key-retrieval tag, descriptor, and keyset UUID, MessagePack-encoded and
base85'd. All 2N entries of a document are encrypted under **one** data key, and
the AEAD nonce is derived from that key's IV — so every entry shares an
identical (key, nonce) pair, and every entry repeats identical key-retrieval
material on the wire.

This RFC changes the SteVec document payload so that:

1. The **key header** (IV, key tag, descriptor, keyset id) is hoisted to the
   document envelope and stored **once**, in a new top-level field `h`.
2. Each entry's `c` becomes the **raw AEAD output only** (ciphertext ‖ 16-byte
   AEAD tag), base85-encoded.
3. The AEAD nonce for each entry is **derived from that entry's selector**:
   `nonce = hex_decode(s)[0..12]`. No nonce is stored anywhere.

The change is breaking at the wire level. It ships inside the Stack 1.0 window,
which is already breaking and already requires re-encryption;
nothing on the current v3 wire has shipped to customers. The payload version
stays `v: 3`.

Scalar payloads are **out of scope**: one ciphertext per record-key means
`iv[..12]` is already a unique (key, nonce) there, and there is no selector to
derive from.

## Motivation

### Security: kill the intra-document equality leak

Today all entries of one document encrypt under the same (key, nonce).
AES-256-GCM-SIV makes this safe (it degrades to deterministic encryption, not a
keystream break), but deterministic encryption within a document means **equal
plaintexts at different paths produce byte-identical ciphertexts** —
`{"a": "x", "b": "x"}` announces the equality of `$.a` and `$.b` to anyone who
can read the column. The value selectors deliberately avoid exactly this leak
(the path is MAC'd into the selector); the ciphertexts currently undo it.

With `nonce = f(selector)`, ciphertext equality requires selector equality
*and* plaintext equality. Selector equality is already public by design (it is
what containment queries). Walking the cases:

- **Value entries**: the selector binds path + value, so distinct paths or
  distinct values ⇒ distinct nonces ⇒ distinct ciphertexts. The identical
  `Enc("")` twins disappear.
- **Path entries at different paths**: distinct selectors ⇒ distinct
  ciphertexts. The `{"a":"x","b":"x"}` leak dies.
- **Residual case** — sibling array elements share a wildcard path selector
  (`ArrayWildcardItem`); equal values there produce equal ciphertexts. But
  their *value selectors* are also equal, which is already public. The
  ciphertext reveals nothing the index does not already announce.

So deterministic leakage collapses exactly onto the leakage profile already
accepted for the selectors. Two further properties come for free:

- **s↔c binding**: in GCM-SIV the nonce feeds the authentication tag, and
  decrypt re-derives it from the stored `s`. A ciphertext grafted onto a
  different selector within the same document fails to decrypt. Before this
  change, the shared nonce left ciphertexts freely permutable across a
  document. The residual wildcard case above shares the same selector, so
  swapping equal sibling ciphertexts there is intentionally indistinguishable.
- **Fail-soft truncation**: a 12-byte collision between two distinct 16-byte
  selectors is a 96-bit birthday event across ~2N entries — negligible — and
  even then GCM-SIV only degrades to determinism for that colliding pair.

### Size: stop repeating the key header 2N times

Measured on the generated fixture (`tests/sqlx/fixtures/v3_ste_vec.sql`,
row 1, plaintext `{"hello": "world-1", "nested": {"deep": "constant"},
"number": 1}` — 5 JSON nodes, 10 sv entries):

| | chars |
|---|---|
| whole payload | 2,238 |
| sum of the 10 entry `c` fields | 1,078 (48%) |
| typical entry `c` (encodes `""` or a small scalar) | 95–107 |
| shared prefix across all 10 `c` (the IV) | 25 |

Each `c` today is `base85(msgpack({iv: 16B, ciphertext, tag: 16B,
descriptor: "", keyset_id: 16B}))` — roughly **70 encoded chars of identical
framing per entry** wrapped around a tiny AEAD payload. Under this RFC a value
entry's `c` (`Enc("")` = bare 16-byte AEAD tag) drops from ~97 chars to
**20**; the header is paid once (~75 chars) at the envelope. On the fixture
document the payload shrinks ~30%; the saving grows with document size since
the eliminated framing is per-entry.

Smaller payloads are not just storage: **every** SQL operation on a stored
jsonb value first detoasts and decompresses the whole value, so total payload
size is the dominant constant in every extractor, operator, and index build.

## Current wire format

```jsonc
{
  "v": 3,
  "k": "sv",                      // form discriminator (occupied — see naming note)
  "i": { "t": "table", "c": "column" },
  "sv": [
    {
      "a": false,
      "s": "239883ccafacebd507ba433d1c300096",
      "c": "mBbK_HRw$TNiihH5|x<dkxyU5...",   // FULL EncryptedRecord, mp-base85
      "op": "0142e14a..."                    // ordered path entries only
    },
    // ... 2N entries, every c repeating iv/tag/keyset
  ]
}
```

`EncryptedRecord` (`vitur_client/encrypted_record.rs`): `{iv, ciphertext, tag,
descriptor, keyset_id, decryption_policy?}`. Note the field `tag` here is the
ZeroKMS **key-retrieval** tag; the **AEAD** tag is the last 16 bytes of
`ciphertext`. Both are currently repeated per entry.

## Proposed wire format

```jsonc
{
  "v": 3,
  "k": "sv",
  "i": { "t": "table", "c": "column" },
  "h": "mBbK_...",                // key header, ONCE: mp-base85({iv, tag, descriptor, keyset_id, decryption_policy?})
  "sv": [
    {
      "a": false,
      "s": "239883ccafacebd507ba433d1c300096",
      "c": "k3%aB...",            // base85(AEAD ciphertext ‖ AEAD tag) — nothing else
      "op": "0142e14a..."
    }
  ]
}
```

- **`h` (key header)**: a single **opaque** base85 string. SQL never parses
  inside it — it is carried and grafted wholesale, so its internal encoding is
  free to evolve under serde without touching SQL. Contents: everything
  `retrieve_key_payload()` needs (`iv`, key-retrieval `tag`, `descriptor`,
  `keyset_id`, optional `decryption_policy`) — i.e. `EncryptedRecord` minus
  `ciphertext`. Serialized as a **dedicated `KeyHeader` struct** (resolved —
  not an empty-ciphertext `EncryptedRecord`); since the blob is opaque to
  SQL, the struct can evolve under serde freely. The `descriptor` is
  **populated** (resolved — closing the standing `build_final` TODO) with the
  field's canonical descriptor, as scalar encryptions already do: repeating
  it 2N times was prohibitive, paid once here it is cheap, and because the
  descriptor participates in ZeroKMS key retrieval
  (`RetrieveKeyPayload{iv, descriptor, tag}`), a payload grafted onto a
  different field now fails at retrieve-key — cross-field tamper evidence at
  the key layer.
- **Naming**: `k` is occupied by the form discriminator (`"sv"`), so the
  header takes `h`. No collision anywhere on the v3 surface (envelope keys:
  `v i c k sv a hm ob bf`; entry keys: `s c op a`).
- **Nonce rule**: for every ciphertext in `sv`, including the root pair's,
  `nonce = hex_decode(s)[0..12]` (selector is 16 bytes / 32 hex chars). There
  is no IV-derived nonce anywhere on the SteVec path, and no stored nonce.
- **Entries are unchanged in shape**: still `{s, c, op?, a?}`. Only the
  *content* of `c` slims down.
- **Query needle (`eql_v3.query_json`)**: unchanged. Needles carry selectors
  (± `op`) and never ciphertext, so they never carried a header either.

### Value entries keep `c`, and it encrypts a sentinel (resolved)

Value entries retain their ciphertext field, but the plaintext changes from
`""` to a **fixed, versioned sentinel** — a constant byte string
domain-separated from every legal JSON subtree encoding (exact encoding is a
client implementation detail; it should carry a version byte). Rationale:

- **Disambiguation (correctness)**: `Enc("")` is ambiguous with a *genuine*
  empty-string leaf — `{"a": ""}` produces a path entry whose subtree
  ciphertext is `Enc("")`, the same plaintext as every value entry. A
  decryptor holding an extracted entry cannot tell "value-selector entry,
  skip" from "the field really is `""`". The sentinel makes value entries
  verifiable on decrypt.
- **Shape uniformity (leakage)**: dropping `c` would structurally mark value
  entries as `{s}` vs `{s, c, op?}`, immediately revealing which selectors
  are value selectors without any query traffic.
- **Forward-compatibility**: the current design encrypts the *whole subtree*
  at every path entry (root `c` = whole document, shrinking toward the
  leaves — O(size × depth) total ciphertext). A future design encrypting only
  node-local content, with a derived-key/linkage mechanism locating child
  ciphertexts within the sv, would use exactly this slot for the linkage
  token. Keeping the slot keeps that evolution additive. (Future work — see
  Out of scope.)
- **Fixed beats randomized**: with selector-derived nonces, a fixed sentinel
  already yields a distinct ciphertext per entry, and per-document keys break
  cross-document determinism — a randomized plaintext adds no measurable
  hiding, while a fixed sentinel is assertable on decrypt.

Honest caveat: ciphertext **length** still fingerprints value entries (a
constant small `c`, near `true`/`null` leaf entries but distinguishable from
container subtrees). Full indistinguishability would require length
bucketing/padding across all entries, which this RFC deliberately does not
take on; the sentinel's value is disambiguation first, the forward-compat
slot second, length camouflage a distant third.

## SQL extraction: how `h` and `c` are reached efficiently

This is the load-bearing design question. The answer is that the expensive
part of jsonb access is **detoast**, not key lookup, and the one place that
must compose header + ciphertext already has an inlinable graft mechanism.

### Cost model

For a stored jsonb value, any access — `->`, `?`, `@>` — first detoasts and
decompresses the entire column value: cost proportional to **total payload
size**. After that, a top-level key lookup (`val -> 'h'`) is a binary search
over the root object's sorted keys: sub-microsecond, independent of `sv`
length. So (a) adding one more top-level key fetch to an already-detoasted
value is noise, and (b) shrinking the payload ~30% makes *every* operation on
the column faster. The format change improves the dominant term and adds an
O(log k) lookup to paths that already paid the O(size) cost.

### Path by path

**Containment (`@>`, GIN, `to_ste_vec_query`, `jsonb_array`)** — never touches
`c` or `h`. `to_ste_vec_query` strips entries to `{s, op}`; the GIN expression
indexes that. **Zero change**, slightly faster via smaller detoast.
(Housekeeping while there: `eql_v3.jsonb_array` still lists `'hm'` in its
deterministic-key filter — retired, drop it.)

**Entry extraction (`->`, `jsonb_path_query`, `jsonb_array_elements`)** — the
precedent already exists. `eql_v3."->"` is:

```sql
SELECT (eql_v3.meta_data(e) || jsonb_path_query_first(e, '$.sv[*] ? (@.s == $sel)', ...))::public.eql_v3_json_entry
```

`meta_data` already grafts the envelope's `i`/`v` into the emitted entry —
precisely so a `json_entry` is self-describing off the wire. The change is one
field in that graft:

```sql
SELECT jsonb_build_object('i', val->'i', 'v', val->'v', 'h', val->'h');
```

Everything stays `LANGUAGE sql IMMUTABLE`, single-statement, no `SET` clause —
inlinable per the payload-scheme-discipline RFC, so `->` in index expressions
and WHERE clauses keeps matching functional indexes structurally. The graft is
an in-memory jsonb concat that was already being performed; +1 key.

**Design invariant preserved: a `public.eql_v3_json_entry` is self-contained
decryptable.** Today that holds because `c` is a full record; after this RFC it
holds because the extractor grafts `h`. Anything holding an extracted entry —
protect.js result rows, `jsonb_array_elements` output — can decrypt it without
re-fetching the parent document. The alternative (bare entries + a separate
`eql_v3.key_header(col)` accessor forcing callers to select two expressions)
breaks that contract for every downstream consumer and is rejected.

**Term extractors (`ope_term`, `ord_term`)** — read `op` only. `ope_term` is
the raw-byte inspection name; `eq_term(json_entry)` remains a deprecated
compatibility alias because OPE bytes are not exact equality terms. The
grafted `h` on an entry flowing into `ord_term` is dead weight measured in
nanoseconds of jsonb concat; functional indexes on
`eql_v3.ord_term(col -> 'sel')` are unaffected.

**Ciphertext access** — `eql_v3.ciphertext(val)` still returns `c` verbatim;
its docs change to state that on the SteVec surface `c` alone is no longer
decryptable — the decryption unit is the entry (`s`, `c`, `h`).
`eql_v3.jsonb_array_elements_text` (SETOF bare `c` text) becomes an attractive
nuisance under the new wire: its output cannot be decrypted. Re-shape it to
return entries (delegate to `jsonb_array_elements`) or drop it; recommend
dropping — the entry-returning twin already exists.

### CHECK / domain changes

- **Document CHECK** (`eql_v3_is_valid_ste_vec_document_payload` + the
  `public.eql_v3_json_search` domain): additionally require
  `jsonb_typeof(val -> 'h') = 'string'`. One conjunct.
- **Entry CHECK**: **no change.** Extra fields are already tolerated (`i`/`v`
  merged by `->` today); the grafted `h` is just another one. The inline
  expression in the `eql_v3_json_entry` domain and its validator-parity test
  stay as they are.
- **Query CHECK**: no change (needles have no `h`, and the validator doesn't
  forbid unknown top-level keys).

## Decrypt flows

**Full document** (protect.js `decrypt`):
1. `h` → mp-base85-decode → `(iv, tag, descriptor, keyset_id)` → ZeroKMS
   retrieve-key → data key. One round trip, exactly as today.
2. Locate the root path entry (`s = SEL($)`, computable client-side from the
   field config).
3. `nonce = hex_decode(s)[0..12]`; AES-256-GCM-SIV decrypt `base85_decode(c)`.

**Extracted entry** (a `json_entry` from `->` / `jsonb_array_elements`):
identical — the entry carries grafted `h` plus its own `s` and `c`. Steps 1
and 3 only.

The ZeroKMS service and the retrieve-key API are untouched; the entire blast
radius is client-side serialization plus the nonce input to the AEAD call
(`Aes256GcmSiv::decrypt(nonce, ct)` where `nonce` comes from `s` instead of
`key.iv[..12]`).

## Change map

| Repo | Change |
|---|---|
| cipherstash-client (2103) | `SteVecPendingEncryption::encrypt` emits envelope header + slim entries; `EncryptionTarget::nonce()` for SteVec targets derives from the entry selector; value-entry plaintext becomes the versioned sentinel; descriptor populated; `a` emitted only when true; decrypt path mirrors all of it. New `KeyHeader` struct + serialization. |
| EQL | `types.sql` document CHECK gains `h`; `meta_data` grafts `h`; `jsonb_array` drops `'hm'`; `jsonb_array_elements_text` dropped; `eql_v3.ciphertext` doc update; bindings (`SteVecDocument.h: KeyHeader` newtype, `Ciphertext` docs) + TS/JSON Schema regen; fixtures regen; `docs/reference/json-support.md` + payload docs. |
| protect-ffi | Decrypt reads `h` + per-entry `s`/`c` as part of its native-v3 support. |
| ZeroKMS | Nothing. |

## Resolved questions

1. **Value-entry ciphertext** — kept; encrypts a versioned sentinel (see
   "Value entries keep `c`" under Proposed wire format).
2. **Descriptor** — populated in `h` (see the `h` bullet under Proposed wire
   format; closes the `build_final` TODO, adds cross-field tamper evidence
   at retrieve-key).
3. **`a` emission** — emit only when `true`; absence means `false`. The
   bindings already model `a` as `Option<bool>` skipped when `None`, so this
   is client-emission-side only.
4. **Header blob encoding** — dedicated `KeyHeader` struct.

## Follow-up work (outside this RFC)

- **Is `a` needed on the wire at all?** Its only consumers are the
  encrypted-array surface — `eql_v3_internal.is_ste_vec_array`,
  `eql_v3.jsonb_array_length`, `eql_v3.jsonb_array_elements`, and the
  integer `->` overload. Determine whether array-ness must be a per-entry
  wire marker or can be derived (selectors / field config), and whether the
  array surface itself earns its keep in v3. Ignored for now: emit-only-when-
  true makes it near-free on the wire either way.

## Out of scope

- Scalar payload records (`hm`/`ob`/`bf` families) — self-contained
  `EncryptedRecord` per value remains correct there.
- **Node-local encryption with derived-key linkage**: replacing per-node
  *subtree* ciphertexts (O(size × depth) total) with node-local ciphertexts
  linked by a derived-key mechanism that locates each child's entry in the
  sv. The value-entry sentinel slot is where the linkage token would live;
  designing it is deliberately deferred.
- Length bucketing/padding of entry ciphertexts (see the sentinel caveat).
- Renaming `k`/form discrimination, purpose-named fields (`e`/`r`/`m`) — the
  v3 target state of the payload-scheme-discipline RFC is a separate track.
