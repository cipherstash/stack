---
'@cipherstash/stack-supabase': major
---

`single()` and `maybeSingle()` now type `data` as the ROW, not an array.

Both have always returned one object at runtime, but the builder kept
advertising the array shape it was created with, so `data` was typed `T[] | null`
while holding a single row. Every caller had to launder it:

```typescript
const { data } = await supabase.from('users').select('id, email').single()
// before: data is `User[] | null` — wrong; a cast was the only way through
const user = data as unknown as User
// after: data is `User | null`
data?.email
```

`single()`/`maybeSingle()` now return `EncryptedSingleQueryBuilder<T>`, which
awaits to `EncryptedSupabaseResponse<T>` (`data: T | null`). That covers the
zero-row case for `maybeSingle()` and the error case for both, so no separate
null modelling was needed.

Filters and transforms are not chainable after `single()`/`maybeSingle()`,
matching supabase-js — applying one afterwards would change the query the
single-row promise was made about. `returns<U>()` preserves the awaited shape,
so `.single().returns<U>()` still awaits one row.

**Migration:** delete the cast. Code that worked around the old typing with
`data as unknown as Row` (or read `data![0]`) should now use `data` directly;
the cast still compiles but is no longer needed, and `data![0]` becomes a type
error.
