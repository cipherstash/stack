---
'@cipherstash/stack': minor
---

Add EQL v3 JSON columns. `types.Json('col')` declares a `public.eql_v3_json`
column that encrypts a JSON document to an ste_vec `SteVecDocument` and
round-trips it losslessly through `encrypt`/`decrypt` and the model path. A new
`searchableJson` query capability emits the ste_vec index; the index uses
`mode: 'compat'`, which eql-3.0.0's `eql_v3_json` requires (it orders ste_vec
entries by the CLLW-OPE `op` term, so v2's `'standard'`/CLLW-`oc` terms are
rejected). Containment querying through the adapters follows.
