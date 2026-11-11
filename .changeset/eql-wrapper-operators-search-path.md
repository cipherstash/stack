---
'@cipherstash/eql': patch
'stash': patch
---

Fix: the `_ord_ore` comparison functions (`eql_v3.lt`, `lte`, `gt`, `gte`, `eq`,
`neq`), and the operators on `_ord_ore` columns when named with their schema
(`col OPERATOR(public.<) $1`), no longer give wrong answers when `public` is not
on the `search_path`. These functions are kept free of a pinned
`search_path` so PostgreSQL can inline them into index scans, which means they
look up their comparison operator through the caller's `search_path`. The ORE
comparison operators live in `public`, so a caller without it, such as a
`SECURITY DEFINER` function with `SET search_path = ''` (the hardening Supabase
recommends), got PostgreSQL's built-in record comparison instead. That compares
the ciphertext bytes, so equality and ordering were silently wrong rather than
raising an error. Every generated comparison function now names its operator
with its schema (`OPERATOR(public.<)` for ORE, `OPERATOR(pg_catalog.<)` for the
HMAC, bloom filter and OPE terms), so the result no longer depends on the
`search_path`, and the functions still inline. A bare `col < $1` still needs
`public` on the `search_path`, because the operators on encrypted columns are
created in `public`; without it, call the function (`eql_v3.lt(col, $1)`) or
name the operator's schema. Reinstall or upgrade EQL to pick up the fix.

The `stash-postgres` skill now explains how to query encrypted columns from a
function or role whose `search_path` leaves out `public`.
