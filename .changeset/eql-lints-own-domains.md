---
'@cipherstash/eql': patch
---

`eql_v3.lints()` now judges only EQL's own `public.eql_v3_*` domains. It used to take every `jsonb` domain in `public`, so a database with another set of encrypted domains installed beside EQL v3 got thousands of false `inlinability_*` errors from the self-check.
