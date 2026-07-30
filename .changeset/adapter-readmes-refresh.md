---
'@cipherstash/stack-supabase': patch
'@cipherstash/stack-drizzle': patch
'@cipherstash/stack-prisma': patch
---

Refresh the adapter READMEs (they ship on each package's npm page):

- **stack-supabase**: full rewrite — the old README was a stub. Now covers the
  introspecting `encryptedSupabase(url, key)` factory, the encrypted filter
  surface (`eq`/`neq`/`in`/`match`, range, `order()` on OPE-backed columns),
  the EQL 3.0.2 PostgREST limitations, and the quick start.
- **stack-drizzle**: fix the hero example — `ops.contains` is encrypted-JSONB
  containment (a `types.Json` column) and would throw on a text column; the
  free-text operator is `ops.matches`. The operator table no longer lists
  `contains` under free-text match.
- **stack-prisma**: correct the encrypted-column-type catalog (domain-named
  factories across text/integer/float/numeric/date/timestamp/boolean/JSON, not
  "six types"), fix the authentication docs URL, and replace relative links
  (which 404 on npm) with absolute ones.
- All three: add the badge header and the architecture diagram from the root
  README.
