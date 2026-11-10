---
"@cipherstash/eql": minor
---

EQL v4 `json_tree`: a predicate on one array element, `eql_v4.json_tree_element_match(col, $1::eql_v4.query_json_elements)` (#1440).

`exists($.contacts[*] ? (@.relationship == "Sibling" && @.calls > 5))` asks for one contact that is both. On a `public.eql_v4_json_search` column the nearest query, `@>` for the relationship and an ordering over `eql_v4.json_tree_path_query` for the calls, can be answered by two different contacts, so it returned more rows than the plaintext query. The new function answers the element-scoped question with one operand, the new domain `eql_v4.query_json_elements`, which Stack Encrypt's `element_match` query operator derives: for each field of the element, the tokens of a subtree read of its path and its bounds. Every field must be at a path the column orders, and equality is the ordering term's, so text compares case- and accent-folded and integers past 2^53 can tie. A row whose array is longer than the bound the operand was derived to raises `invalid_parameter_value` rather than answer over part of the array.

`eql_v4.json_tree_subtree_indexed(col, tokens, budget)` is the subtree read with `k`, the place in `tokens` of the token whose node each row sits in, which pairs the fields of one element. `eql_v4.json_tree_subtree` now returns its rows without `k`, and is otherwise unchanged.
