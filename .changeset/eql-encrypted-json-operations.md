---
"@cipherstash/eql": minor
---

**`JsonSearch` answers its JSON operators by name.** `eql-bindings`' target table row now tells Stack Encrypt the domain an ordering at a path binds as (`Target::leaf_query_sql_domain`, `eql_v4.query_json_leaf`), so a data plan's `lt_at`, `lte_at`, `gt_at`, `gte_at` and `between_at` bind their operand as that domain, beside `contains`, `contained_by` and `eq_at`, which bind the needle as `eql_v4.query_json`. No SQL changes.
