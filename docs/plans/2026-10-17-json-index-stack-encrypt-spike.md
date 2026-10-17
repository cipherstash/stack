# A JSON index for Stack Encrypt: node-local entries, a token chain, and exact containment

**Status:** exploration, for a spike
**Date:** 2026-10-17
**Author:** Dan Draper (with Claude assistance)
**Relates to:** #1231 (containment matches across array elements), #1209 (`Contains`, `ContainedBy`, `AtPath` declared), ADR-0009 (operators select the index), system ADR-0002 (EQL v4 by producer), `packages/eql/docs/plans/stevec-envelope-key-header-rfc.md` (the v3 envelope), `docs/plans/2026-10-04-plan-builder.md` ("The JSON index" under Additions)
**Prototypes:** `2026-10-17-json-index-stack-encrypt-spike/` beside this file, three SQL files that run on a stock PostgreSQL 16 with no extension

## Summary

Stack Encrypt has no JSON index yet. The operators exist (#1209 merged `op::Contains`, `op::ContainedBy` and `op::AtPath<Op>` on `next`), the plan-builder document reserves `Json: Index<Value>` as "a new core operation", and EQL v4 has a storage-only `public.eql_v4_json` but "no SteVec bindings yet". The v4 JSON wire format is therefore unconstrained by anything shipped. This document proposes what to build, and a spike to prove it.

Three changes to the v3 SteVec design, taken together:

1. **One entry per JSON node, encrypting only that node.** A path entry today encrypts its whole subtree, so a document's ciphertext is O(size × depth) and the root entry alone is the size of the document. Under this proposal an entry's ciphertext holds the node's edge label, its kind and, for a scalar, its value. Total ciphertext is O(size). The separate value entry is folded into the same entry as a second selector field, halving the entry count.
2. **A token chain links a node to its children, and the server can walk it from a query key.** Each node has a secret 16-byte token. The client derives a path's token from the index key and the path alone. Each child entry stores a *parent tag* (a hash of the parent's token) and its own token *wrapped* under the parent's token. A `WITH RECURSIVE` query that is handed one start token finds that node's children by tag, unwraps their tokens, and recurses, in core SQL (`sha256`, bytea XOR). Without the token the tags and wraps are unlinkable random bytes. This is what makes node-local ciphertexts usable: `doc -> '$.a'` on an object returns the subtree's entries in one round trip, and the client reassembles the object. The prototype in `token-chain.sql` does exactly this.
3. **Exact containment, closing #1231.** Every entry under an array element carries the element's *group tag*. Containment stays a GIN-indexed `jsonb @>` over the selector sets, which is a necessary condition, and gains a recheck, run only on the rows the index returned and only when the needle has an array element that is a container, that requires each needle element's selectors to come from one stored element. The prototype in `containment-oracle.sql` agrees with PostgreSQL's `jsonb @>` on every case tried, including the six cross-element cases where today's selector containment is wrong. The issue's "plausible" false negative (`'["a"]' @> '"a"'`) is verified real and fixed by letting a root-scalar needle carry two selector sets.

Everything here works on standard PostgreSQL, as a non-superuser, with no extension: the SQL uses `sha256(bytea)` (core since 11), `get_byte` / `set_byte`, recursive CTEs and the `jsonb_path_ops` GIN operator class.

## Where we are

### The v3 SteVec, as cipherstash-client 0.42.3 produces it

Read from the crate source (`src/encryption/json_indexer/`), not from memory:

- `flatmap_json` walks the document. Every node emits a **path entry** `{s, c, op?}` and a **value entry** `{s, c}`. `s` is a 16-byte keyed Blake3 MAC of the canonical JSONPath (`$['a'][*]['x']`), under a per-column `prefix`. The value entry's `s` is `MAC(6-byte type tag ‖ path token ‖ canonical value)`; containers get a tag only (`MAP0{}`, `ARRY[]`). `op` is a CLLW OPE term on string and number leaves only. A value entry's `c` encrypts a fixed three-byte sentinel.
- Arrays are indexed under `ArrayIndexMode`: wildcard `[*]`, item `[@]` and positional `[n]` selectors, any combination. Under the wildcard every element of an array shares one path selector, which is the root of #1231.
- The path entry's `c` is the AEAD of the node's **whole subtree** as a `Plaintext`. The root entry (index 0) is the whole document; decryption of a document reads only the root (`into_root_record_with_nonce`).
- Since the envelope RFC: one `KeyHeader` `h` per document (iv, key tag, descriptor, keyset id), entries carry raw AEAD output, nonce `= s[..12]`, AAD `= descriptor ‖ tag ‖ s`, AES-256-GCM-SIV. SIV is what makes equal selectors (sibling array elements with equal values) safe: the cipher degrades to determinism rather than breaking.
- The SQL (`packages/eql/src/v3/json/`): `@>` is `to_ste_vec_query(a)::jsonb @> to_ste_vec_query(b)::jsonb`, where `to_ste_vec_query` projects each entry to `{s}`; a GIN `jsonb_path_ops` index on that expression serves it. `->` by selector grafts `h`, `i`, `v` onto the matched entry so it is self-contained decryptable. `jsonb_array_elements` and `jsonb_array_length` rely on a per-entry `a` flag.

### What Stack Encrypt has

- `op::Contains`, `op::ContainedBy`, `op::AtPath<Op>` and the arity `Pathed<A>` (PR #1209, on `next`). `TermFor<Contains>` is implemented for every `QueryTerm`, so the containments are declared **exact**, and the issue keeps that declaration on purpose. No `Supports<Contains, _>` impl exists; a query with these operators does not compile.
- `IndexSpec` is `Equality | Match | Ore | Ope`. The plan-builder document reserves `"json"` as the fifth key and describes the operation: "it mints one document key and seals every entry under it, a new core operation (one generate request, a fulfilment that seals N entries with selector-derived nonces)".
- The PRF: `KeysetCipher::prf()` is an `HmacSha256Prf` keyed by the keyset's index key, with PAE-framed domains per term kind (`sem/mod.rs`). Selectors and tokens derive through it. Nothing is byte-compatible with cipherstash-client, by design.
- Leaves seal with vitaminc's `Aes256Cipher`, AES-256-GCM with a random nonce. There is no GCM-SIV in the dependency tree. The JSON operation needs a deterministic nonce under one document key, so nonce uniqueness has to hold by construction (see "Keys, nonces and AAD").
- The data plan (`dynamic`) and the Go guest spell indexes as `IndexSpec`; the match index already needed a wire form for its options, and the JSON index will too (plan-builder Additions, item 7).

### What EQL v4 has

ADR-0002: v4 is the v3 SQL rendered under `eql_v4` names, for values Stack Encrypt writes. `eql-bindings::v4` exists on `next` with `public.eql_v4_json` as `{v, i, c}` storage only. `v4/mod.rs` says "v4 has no SteVec bindings yet; those follow in `@cipherstash/eql` 4.0". The build renders `src/v3/**` as both bundles, so a v4-only JSON surface is a build change as well as new SQL (see "Where it lands").

## Goals and constraints

- **Security.** No new leakage beyond what the selectors already announce, except where exact containment needs it, and then the minimum. Ciphertext equality must not reveal plaintext equality anywhere the selectors do not already. Nonce reuse under one key must be impossible by construction, since AES-GCM, not SIV, is what the engine has.
- **Speed.** Containment stays a GIN probe. Scalar extraction stays one entry. Encryption cost drops with depth, because no byte is encrypted twice.
- **Size.** Remove the O(size × depth) subtree duplication. Halve the entry count. Do not grow the per-entry constant by more than the duplication saves on a flat document.
- **Standard PostgreSQL.** Core functions only, no extension, no superuser. Supabase and every managed Postgres EQL supports today.
- **Fits the engine's shape.** A `Json` index implementing `Index<Value>`, one `generate_keys` request, `Supports<Op, In>` for the operators #1209 declared, a wire form for its options, EQL's v4 JSON type as the `EncryptFrom` that frames it (plan-builder decision 5 and "EQL v4 types as field targets").

## Design

### 1. One entry per node, node-local ciphertext

The flattening is unchanged in what it visits: every node, with arrays indexed under the wildcard path. What each node emits changes:

| field | content | present on |
|---|---|---|
| `s` | path selector: `PRF(json/selector ‖ column, canonical wildcard path)`, 16 bytes | every entry |
| `vs` | value selector: `PRF(json/value ‖ column, kind tag ‖ s ‖ canonical(value))`, 16 bytes; containers contribute the tag only, as today | every entry |
| `p` | parent tag, `H("p" ‖ iv ‖ t(parent))[..16]` | every entry but the root |
| `w` | wrapped token, `t(node) XOR H("w" ‖ iv ‖ t(parent) ‖ c)[..16]` | every entry but the root |
| `n` | own group tag, `H("g" ‖ iv ‖ t(node))[..16]` | array elements only |
| `g` | enclosing group tag: the `n` of the nearest enclosing array element | every entry inside an array element |
| `c` | `AEAD(k_doc, nonce(s, j), aad, label ‖ kind ‖ scalar)`: the edge label (object key or array index), the node kind, and for a scalar its value; nothing else | every entry |
| `op` | the leaf ordering term, as today, on string and number leaves | leaves that order |

`t(node)` is the node's token (next section). `iv` is the document key's IV from the header `h`, already public, reused as a per-document salt. `j` is the entry's ordinal in `sv`.

The value entry and its sentinel disappear: `vs` sits on the node's own entry. The entry count halves. `a` disappears: `n` marks an array element, and the chain enumerates an array's elements.

What the client gets back for a scalar path (`doc -> 'sel'` where the leaf is a string) is unchanged in shape: one entry, decryptable with the grafted `h`, its own `s` and `c`, and its ordinal `j` (grafted by the extractor, as `h` is today). For a container path the client gets the subtree's entries and rebuilds the value from each entry's decrypted `(label, kind, scalar)` and the depth the walk reports. Whole-document decryption is the same walk, run by the client over the whole `sv` with the root token it can derive itself.

### 2. The token chain

```
t(root)        = PRF(json/token ‖ column, "$")[..16]                 client only
t(child)       = H("t" ‖ t(parent) ‖ 0x01 ‖ key)[..16]               object member
t(child)       = H("t" ‖ t(parent) ‖ 0x02 ‖ LE64(index))[..16]       array element
p(child)       = H("p" ‖ iv ‖ t(parent))[..16]                        stored
w(child)       = t(child) XOR H("w" ‖ iv ‖ t(parent) ‖ c(child))[..16] stored
```

`H` is SHA-256. Only `t(root)` needs the index key; everything below it is hashing, so the server can do its half with core functions. The tokens are a function of the column and the **positional** path, so the client derives a start token for any path it can name without a wildcard: `$.nested`, `$.a[2].b`. Labels are bound with a kind byte and as the final variable-length field, so `("ab", "c")` and `("a", "bc")` cannot collide.

Server side, the subtree under a start token is one recursive query. From `token-chain.sql`, which runs as written on PostgreSQL 16:

```sql
WITH RECURSIVE walk(depth, t, entry) AS (
    SELECT 0, $start_token, NULL::jsonb
  UNION ALL
    SELECT w.depth + 1,
           xor16(decode(e->>'w', 'hex'), h16(w.t || 'w' || iv || decode(e->>'c', 'hex'))),
           e
    FROM walk w
    JOIN LATERAL jsonb_array_elements(doc->'sv') e
      ON e->>'p' = encode(h16(w.t || 'p' || iv), 'hex')
)
SELECT depth, entry FROM walk WHERE entry IS NOT NULL;
```

Run against the fixture document with the token for `$.nested`, derived on the client from the labels alone, it returned the six entries under `$.nested` (`deep`, `list`, both elements, both `x` leaves) with their depths, nothing else; a garbage token returned zero rows; the root token returned all nine non-root entries. The mask for `w` includes the child's own ciphertext so that two siblings with the same `p` get different masks without the server needing to know anything about them.

What a token is: a capability for the **structure** of one subtree, in every row of the column, because the tokens are column-deterministic. It reveals nothing about content, which is under the ZeroKMS data key. Handing the server `t($.a)` in a query lets it see, for that query, which entries sit under `$.a` and how they nest. That is the same trust the client already extends when it sends a selector, and the server learns it only for the path asked.

The per-document salt (`iv`) in `p`, `g` and the mask means that **at rest**, with no token, the tags of two rows with identical shape are unrelated bytes. Nothing links shape across rows until a query supplies a token. This is the one place the proposal leaks strictly less than the alternative of a public parent pointer, and it costs nothing: the IV is already in `h`.

Wildcard paths. A client cannot derive `t($.a[*].b)`, because the token is positional. Extraction under a wildcard anchors at the nearest non-wildcard ancestor and gates on the selector: `subtree_at(doc, t($.a), s($.a[*].b))` walks from `$.a`, and emits an entry only once the walk has passed through an entry whose `s` matches. Scalar leaves under a wildcard need no token at all: `->` by selector returns them as today, and their nonce and AAD depend on `s` and `j`, not on `t`.

Arrays. `jsonb_array_length(doc, t)` is the count of children of `t`; `jsonb_array_elements(doc, t)` is the children, each a subtree root. Positional access (`$.a[2]`) is a token, not a selector, so the item (`[@]`) and positional (`[n]`) `ArrayIndexMode`s have no reason to exist in v4: wildcard only, and the chain for positions.

### 3. Exact containment (#1231)

**The gap, verified.** `jsonb-semantics.sql` pins PostgreSQL's own answers, and `containment-oracle.sql` runs a plaintext-selector simulation of the v3 flattening (the PRF is injective in practice, so string selectors give the same containment answers as MAC'd ones) beside it:

| case | `jsonb @>` | v3 selector containment |
|---|---|---|
| `{"a":[{"x":1,"y":5},{"x":7,"y":2}]} @> {"a":[{"x":1,"y":2}]}` (the issue's example) | false | **true** |
| `{"a":[{"b":[{"x":1},{"y":2}]}]} @> {"a":[{"b":[{"x":1,"y":2}]}]}` (nested arrays) | false | **true** |
| `{"a":[{"b":{"c":1,"d":5}},{"b":{"c":3,"d":2}}]} @> {"a":[{"b":{"c":1,"d":2}}]}` (object inside element) | false | **true** |
| `{"a":[[1,2],[3,4]]} @> {"a":[[1,4]]}` (array inside element) | false | **true** |
| `["a"] @> "a"` (the issue's "plausible" false negative) | true | **false** |
| every other case tried (empty containers, duplicates, scalar vs array at depth, `{}` against an array, nulls, type confusion) | | agrees |

So the bug is exactly the issue's diagnosis: a needle array element that is a container with two or more constraints can be satisfied by different stored elements. Scalars in arrays are fine, single-constraint elements are fine. And the top-level scalar case is a real false negative today.

**The fix at rest.** Every entry under an array element carries `g`, the group tag of the nearest enclosing element; an element entry carries its own tag as `n` and its enclosing element's as `g`. Tags are `H("g" ‖ iv ‖ t(element))`: per document, random-looking, deterministic given the token.

**The fix in the needle.** The `Contains` query term serialises to `{sv: [...], grp: [...], alt?: {sv: [...]}}`:

- `sv` is the flat selector set, as today.
- `grp` is one group per needle array element that is a container: `{at: s(element path), need: [vs...], sub: [groups...]}`. `need` holds the value selectors inside the element down to, but not into, nested elements; `sub` holds the nested elements' groups. The element's own `vs` (its `MAP` or `ARRY` tag) is in `need`.
- `alt` is present only when the needle's root is a scalar: a second `sv` with the root value selector under `$[*]` instead of `$`, so a stored root array containing the scalar matches. `'"a"' @> '"a"'` matches through `sv`, `'["a"]' @> '"a"'` through `alt`.

**The fix in SQL.** Two stages, in one expression the planner handles well:

```sql
to_query(doc) @> q.sv                              -- GIN jsonb_path_ops, necessary condition
AND groups_ok(doc->'sv', q.grp, NULL)              -- recheck on the rows the index returned
OR (q.alt IS NOT NULL AND to_query(doc) @> q.alt)  -- a second GIN probe, bitmap OR
```

`to_query` projects each entry to `{s, vs}`; a needle element `{s: X}` or `{vs: Y}` is contained by any entry carrying it, so the existing GIN strategy carries over with both selectors on one entry. `groups_ok` is the recursive recheck: for each group, some element entry with `s = at` (and, below the top level, `g` equal to the enclosing group's chosen element) has every `need` selector on itself or on an entry whose `g` is its `n`, and satisfies its `sub` groups. It is plpgsql, it runs only on rows that passed the index, and it is a no-op for a needle with no container array elements, which is every needle the Rust `AtPath<Eq>` operator produces.

**Result.** `containment-oracle.sql` agrees with `jsonb @>` on all 31 cases, the six cross-element false positives included, with two listed simulation artefacts: the file canonicalises numbers as `numeric::text` so `2` and `2.0` differ (the real producer canonicalises by value, as cipherstash-client's `canonical_number` does), and the root-scalar case is fixed by `alt`, which the simulation does not implement.

**Portability to v3.** The group tags and the recheck do not depend on the chain. If #1231 must also be fixed for rows cipherstash-client writes, the same `g`/`n` fields and the same `groups_ok` can be added to the v3 wire and SQL, with `g` derived from the document key instead of a token. This document does not propose that; it records that the fix is separable.

### 4. Wire format

A v4 searchable JSON document, `public.eql_v4_json_search`:

```jsonc
{
  "v": 4,
  "k": "sv",
  "i": { "t": "users", "c": "profile" },
  "h": "…",                       // key header, once: iv, key tag, descriptor, keyset id (opaque to SQL)
  "sv": [
    { "s": "…", "vs": "…",                                  "c": "…" },            // $      (root: no p, w)
    { "s": "…", "vs": "…", "p": "…", "w": "…",              "c": "…", "op": "…" }, // $.hello = "world-1"
    { "s": "…", "vs": "…", "p": "…", "w": "…",              "c": "…" },            // $.list  (array)
    { "s": "…", "vs": "…", "p": "…", "w": "…", "n": "…",    "c": "…" },            // $.list[*]  element 0 (object)
    { "s": "…", "vs": "…", "p": "…", "w": "…", "g": "…",    "c": "…", "op": "…" }  // $.list[*].x = 1, inside element 0
  ]
}
```

A `Contains` needle, `eql_v4.query_json`:

```jsonc
{
  "sv":  [ {"s": "…"}, {"vs": "…"}, … ],
  "grp": [ { "at": "…", "need": ["…", "…"], "sub": [] } ],   // only when an array element is a container
  "alt": { "sv": [ … ] }                                      // only when the needle root is a scalar
}
```

An `AtPath<Eq>` needle is `{"sv": [{"vs": "…"}]}`. An `AtPath<Gte>` term is the pair the ADR-0009 appendix already shows: a selector for `->` and a leaf ordering operand. A subtree request is `(t_start, s?)`.

**Size.** Per 16-byte field, hex costs 32 characters plus about six of framing. Measured against the envelope RFC's fixture document (`{"hello":"world-1","nested":{"deep":"constant"},"number":1}`, 5 nodes):

| | v3 today | proposed |
|---|---|---|
| entries | 10 | 5 |
| per leaf node | ~180 chars (path entry + value entry) | ~230 chars (`p`, `w` added; one entry) |
| per container node | ~40 chars + the whole subtree's ciphertext | ~190 chars, no subtree |
| this document | ~1,060 chars | ~1,140 chars |
| 100-element array of 5-leaf objects | ~5 KB document ciphertext at the root, repeated once more across the element entries, plus the leaves | leaves only |

On a flat five-node document the proposal is about 8% larger: the two chain fields cost more than the sentinel entry saved. The saving is the duplication, which grows with size and depth and is the term that dominates every real document. Encoding the 16-byte fields as base64url (22 characters) instead of hex (32) saves about 40 characters per entry and puts even the flat case ahead; `decode(x, 'base64')` is core SQL, so the choice is free. The spike should measure three shapes (flat, nested, array-heavy) before fixing the encoding.

### 5. Keys, nonces and AAD

- **One ZeroKMS data key per document**, requested under the column's descriptor, as today; the header `h` carries what `retrieve_keys` needs, once.
- **Nonce** `= H("nonce" ‖ s ‖ LE64(j))[..12]`, where `j` is the entry's ordinal. Unique within a document by construction, so AES-256-GCM is safe without SIV: no two entries share `j`. It is derivable for an extracted entry from public fields, so a wildcard-extracted leaf decrypts without a token. Reordering entries breaks decryption, which is tamper evidence, not a hazard: jsonb preserves array order.
- **AAD** `= PAE("stack-encrypt/json/entry/v1", keyset_id, descriptor, key_tag, s, j)`. A ciphertext moved to another entry, another document or another column fails to open.
- **PRF domains**, all PAE-framed and versioned as the existing terms are: `json/selector/v1`, `json/value/v1`, `json/token/v1`. The v3 `prefix` string is replaced by the column context, which the plan-builder document already decided.
- **Leaf ordering terms** derive as the `Ope` index derives them today, keyed by column, so the v4 scalar ordering query domains serve `AtPath<Gte>` unchanged. Binding them to the selector as well would stop two paths' leaves comparing against each other and is a one-line change; the spike should decide it, because it changes which query operand domain `AtPath<Gte>` takes.
- **Equal sibling values.** Two elements with the same value share `s` and `vs` (public, as today) but now have different ciphertexts, because `j` differs. The v3 residual case where equal siblings produce byte-identical ciphertexts is gone.

### 6. Leakage, side by side

| observer sees | v3 today | proposed |
|---|---|---|
| which paths a row has | yes, `s` | yes, `s` |
| which (path, value) pairs a row has | yes, value `s` | yes, `vs` |
| node count | yes (2N entries) | yes (N entries) |
| size of every subtree | yes, each path entry's ciphertext is its subtree | no, only leaf scalar lengths, as the v3 leaf entries already show |
| parent and child relation | inferable from subtree sizes and cross-row co-occurrence | hidden at rest; sibling grouping (`p`) and element grouping (`g`) visible at rest as per-document random tags; linkable only with a token the query supplies |
| shape equality across rows | selectors are column-deterministic, so yes | tags are salted by the document IV, so no, until a token is supplied |
| which leaves sit in the same array element | no | yes, `g`. The one new leak, required for exact containment, and bounded to array elements |
| equal values at two paths | hidden | hidden |
| equal values in sibling elements | ciphertexts equal (selectors already equal) | ciphertexts differ |
| key names | hashed into `s` | hashed into `s`; also encrypted in `c` |
| at query time, a subtree extraction | reveals the selector asked | reveals the selector or token asked; a token also reveals that subtree's shape for the rows scanned |

### 7. Performance

- **Encrypt:** per node two PRFs (`s`, `vs`), three hashes (`t`, `p`, mask), one small AEAD. v3 does two MACs and one AEAD over the subtree bytes. Fewer bytes encrypted at every depth above the leaves.
- **Containment:** the GIN probe is unchanged in cost (two keys per entry instead of two entries with one key). The recheck runs per returned row, in plpgsql, only for needles with container array elements, and scans `sv` once per group.
- **Scalar `->`:** one entry, as today.
- **Subtree `->`:** a recursive CTE, one `jsonb_array_elements` scan of `sv` per depth level. Linear in document size times depth of the subtree. Adequate for documents of hundreds of entries; `bench-eql` should measure a 1,000-entry document before this is called settled.
- **Decrypt a document:** the client walks the chain locally. N hashes plus N small AEADs instead of one large AEAD; the client has the index key, so no extra round trip.

### 8. Standard PostgreSQL

Everything the server does: `sha256(bytea)` (core since PostgreSQL 11), `get_byte` / `set_byte` for a 16-byte XOR in plpgsql, `decode` / `encode`, `WITH RECURSIVE`, `jsonb_array_elements WITH ORDINALITY`, and `jsonb_path_ops` GIN. No pgcrypto, no superuser, no C. The same posture as the v3 surface Supabase runs today.

## Where it lands

**`packages/stack-encrypt`**

- `target::Json`, `Index<serde_json::Value>`, `IndexSpec::Json(JsonOptions)` with the fifth output key `"json"` the plan-builder document reserved. Options for the spike: none that change the wire (wildcard arrays only; case folding deferred).
- A new operation beside `ciphertext()` and the term operations: one `generate_keys` request, a fulfilment that flattens, derives selectors and tokens, and seals N entries. The plan-builder table calls this "a new core operation" under `index(name, idx)`.
- Terms: `JsonDocument` (stored; reversible with the index key and the document key), `JsonQuery` (`Contains`, `ContainedBy`, `AtPath<Eq>`), `JsonLeafQuery` (selector plus leaf ordering operand, for `AtPath<Lt | Lte | Gt | Gte | Between>`), `JsonSelector` and `JsonSubtreeKey` for extraction. `Supports<Op, In>` impls on `Json` for each; `Input<Pathed<One>>` and `Input<Pathed<Pair>>` for `(JsonPath, S)` and `(JsonPath, (S, S))`, which #1209 left unimplemented until the index existed.
- PRF domain constants in `sem/mod.rs` beside the existing ones.

**`packages/eql/crates/eql-bindings`**

- `v4::json`: `SteVecDocument`, `SteVecEntry`, `SteVecQuery` with the fields above, `v: 4`, and the `stack-encrypt` feature's `EncryptFrom<Value>` / `DecryptInto<Value>` for `public.eql_v4_json_search` that frames the index's output with `i`, `v`, `h`. The v3 structs are untouched.
- `encryption/targets.rs`: `Json` becomes producible in the `se_targets` table once the type exists.

**`packages/eql` SQL**

- A v4-only `src/v4/json/{types,functions,operators,blockers}.sql`: the two domains and the query domain with their CHECKs, `to_query`, `@>` and `<@` as the two-stage expression, `groups_ok`, `->` with `h` and `j` grafted, `subtree(doc, token)` and `subtree_at(doc, token, selector)`, `jsonb_array_elements(doc, token)` and `jsonb_array_length(doc, token)`, the ordering extractor on an entry, and the blockers the v3 surface has.
- **A build change.** `tasks/build.sh` renders `src/v3/**` as both bundles and `verify_installer_complete.sh` asserts every ordered v3 file is in the v4 installer. A v4 JSON surface that differs from v3's needs the renderer to exclude `src/v3/json/**` from the v4 render and include `src/v4/json/**`, and the completeness check to follow. During the spike the v4 JSON SQL can be installed as a separate file over the v4 bundle; the build integration is a task of its own.
- Tests: `mise run test:stack_encrypt_pg` on `next` already installs the v4 bundle and runs a Stack Encrypt PostgreSQL test with fresh encryption under a fake KMS and no credentials. The JSON suite joins it. The SQLx fixture machinery is not needed for this and should not be used: the point of the fake key source is that the whole suite runs on a fork PR.

**`languages/golang`**

- Nothing in the spike. After it, `JSON` moves from "the JSON index is a new operation in the engine" to producible in `encrypt/eql`'s table, and the data plan carries the `json` index with its options (plan-builder Additions, item 7).

**Documentation that #1231 asks for now, independent of the spike:** the `Contains` and `ContainedBy` docs in `stack-encrypt/src/op/mod.rs`, ADR-0009 and the EQL JSON reference should say that v3 containment over arrays of containers returns extra rows until the v4 surface ships. That is the issue's step 3 and needs no code.

## The spike

Scope: prove the three changes end to end with real encryption under the fake key source against a real PostgreSQL, measure size and query cost, and leave the wire fields decided. Not in scope: Go, TypeScript, bindings regeneration, the build-tool integration, case folding, ORE leaf terms, lock context.

**Phase 0, the oracle, no crypto.** Port `containment-oracle.sql` into the SQLx suite as a DB test that drives the **real** `eql_v3` functions with plaintext string selectors (the v3 domain CHECKs accept any string for `s`, `c` and `h`), and reports every disagreement with `jsonb @>` over a corpus of documents and needles. This is #1231's step 1, it pins the six false positives and the false negative against the shipped SQL, and it runs on a fork PR. Acceptance: the test fails on v3 for exactly the cases this document lists, and nothing else.

**Phase 1, the index in Rust.** `Json: Index<Value>` with the flattening, selectors, tokens, tags, nonces and AAD above, behind a `json` feature; the `JsonDocument` round trip; `JsonQuery` with `grp` and `alt`; `JsonSelector` and `JsonSubtreeKey`. Tests under `FakeDataKeySource`: round trip of nested documents and arrays; every entry's nonce distinct; unwrap of every child from its parent's token and of nothing from a wrong token; an entry moved, reordered or regrafted fails to open; the needle generator's `grp` against a hand-written expected shape for the issue's example; the selector for a path equal to the `s` of the stored entry; a property test that a document's entries decrypt and reassemble to the input for arbitrary `serde_json::Value`s. Acceptance: `cargo nextest run -p stack-encrypt --features json` green, no credentials.

**Phase 2, the SQL.** `src/v4/json/*` as listed, installed over the v4 bundle in the test database. The SQLx test encrypts a corpus with the Phase 1 code, inserts it, and checks: `@>` against `jsonb @>` on the plaintexts for the Phase 0 corpus plus random documents (the real oracle, with real selectors); `->` on a scalar decrypts to the leaf; `subtree` on an object reassembles to the sub-document; `jsonb_array_elements` and `jsonb_array_length`; `AtPath<Gte>` ordering against plaintext ordering; a GIN index on `to_query(col)` engages for `@>` (`EXPLAIN` shows the bitmap index scan, as `database-indexes.md` describes for v3). Acceptance: zero oracle disagreements over the corpus; every `EXPLAIN` the suite asserts shows the index.

**Phase 3, measure.** Three document shapes (flat 5-node, nested depth 4, 100-element array of objects), v3 size versus v4 size in hex and in base64url; encrypt time per document; `@>` latency with and without the recheck at 100k rows; `subtree` latency on a 1,000-entry document. `packages/bench` or `bench-eql.yml` as fits. Acceptance: a table in this document, and a decision on token encoding.

**Phase 4, decide.** With the numbers, fix the wire (field names, encoding, whether leaf ordering terms bind the selector), write the ADR for the JSON index, and open the build-integration, Go and bindings issues.

Each phase is a PR against `next`, where #1209 landed.

## Decisions to take before Phase 1

1. **Token encoding on the wire:** hex, matching v3's `s`, or base64url, saving about 40 characters per entry. Proposal: measure in Phase 3, default to base64url.
2. **Leaf ordering terms bound to the column only, or to the column and the selector.** Column-only reuses the v4 scalar ordering query domains unchanged and matches the ADR-0009 appendix; selector-bound stops cross-path order comparison at the cost of a JSON-specific query domain. Proposal: column-only for the spike, revisit in the ADR.
3. **Array index modes.** Wildcard only, with the chain serving positional access, retiring `[@]` and `[n]`. Proposal: yes.
4. **Group tags on by default**, or opt-in per column for callers who accept the v3 behaviour in exchange for not revealing element grouping. Proposal: on by default; `Contains` is declared exact and that declaration has to be true.
5. **`c` for container nodes**: label and kind only, as proposed, or label, kind and child count (lets the client pre-size and detect a truncated subtree). Proposal: add the child count; it is two bytes and it turns a missing entry into an error instead of a silently shorter array.
6. **Whether to fix v3 too** by porting the group tags and recheck to cipherstash-client and the v3 SQL. Separable; not proposed here.
