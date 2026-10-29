---
"@cipherstash/eql": minor
---

EQL v4 `json_tree`: a whole filter as one parameter, `eql_v4.json_tree_match(col, $1::eql_v4.query_json_predicate)` and `col @@ $1::eql_v4.query_json_predicate` (#1441).

An application that compiles a filter language into SQL targets `jsonb_path_match(col, $1, $2)` on a plaintext column: one predicate, one set of values. On a `public.eql_v4_json_search` column each question is its own operator, so the same filter had to be assembled by hand, one operand per leaf. The new domain `eql_v4.query_json_predicate` is a boolean tree (`and`, `or`, `not`) whose leaves are the operands those operators already take (a `contains` needle, an `exists` selector, `cmp` ordering bounds and an `elements` predicate), each checked by its own domain's rule, and `eql_v4.json_tree_match` evaluates it with SQL's three-valued logic, the answer the hand-written WHERE gives. Stack Encrypt's `match` query operator compiles a jsonpath predicate in the subset the terms can answer into the tree. The tree is evaluated inside a function, so it filters a scan and engages no index; the operators written out per leaf are the fast path. The operand must carry its type: an untyped operand on the right of `@@` is refused as ambiguous, and `@@` with a `jsonpath` is still blocked.

`eql_v4.json_tree_element_match` now reads an opened document through `eql_v4_internal.json_tree_element_match_opened`, which `json_tree_match` shares; its answers are unchanged.
