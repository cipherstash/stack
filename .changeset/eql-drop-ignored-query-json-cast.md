---
'@cipherstash/eql': patch
---

Drop the `CREATE CAST (public.eql_v3_json_search AS eql_v3.query_json)` that PostgreSQL always ignored (it warned "cast will be ignored because the source data type is a domain" on every install). `doc::eql_v3.query_json` was never converting; call `eql_v3.to_ste_vec_query(col)` instead. Also corrects the `eql-bindings` wire-format docs: `op` backs `_ord` / `_ord_ope` (and `text_ord` / `text_search` carry `hm` + `op`), `ob` only `_ord_ore`.
