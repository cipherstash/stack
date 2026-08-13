---
'@cipherstash/eql': major
---

**`eql_v3.ste_vec_contains` is renamed to `eql_v3.jsonb_document_contains`.** This
consolidates the last `ste_vec_*`-named public object into the `jsonb_*` family,
matching the earlier renames of the SteVec entry/query surface (`jsonb_entry`,
`jsonb_query`). The function backs the `json` `@>` / `<@` containment operators;
its behaviour is unchanged. Callers that invoke the function by name (Supabase /
PostgREST, which call functions rather than operators) must update the name.
