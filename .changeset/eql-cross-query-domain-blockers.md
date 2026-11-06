---
"@cipherstash/eql": patch
"stash": patch
---

Comparing an encrypted column with a different domain's query operand now raises instead of silently returning no rows. For example `public.eql_v3_text_ord = $1::eql_v3.query_text_eq`, or `eql_v3_text_ord < $1::eql_v3.query_text_ord_ope`, previously fell through to native `jsonb` comparison and answered false for equal values. Within a type family, every pair of a column domain and another domain's query operand now resolves to a blocker for the operators both sides support, naming both operands and telling the caller to use the query domain that matches the column. Use the query domain of the column's own domain (`eql_v3.query_<column domain>`). The install bundle grows by about 1,060 functions and the same number of operators.
