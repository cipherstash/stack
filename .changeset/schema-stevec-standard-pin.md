---
'@cipherstash/schema': patch
---

`searchableJson()` now pins the SteVec encoding mode to `standard` explicitly.
protect-ffi 0.29 flipped the library default to `compat` (the EQL v3
encoding); pinning keeps the v2 wire format byte-stable so existing encrypted
JSON columns stay queryable and comparable.
