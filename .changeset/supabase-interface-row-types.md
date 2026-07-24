---
'@cipherstash/stack-supabase': minor
---

Row-type generics now accept an `interface`, not just a `type` alias.

`from<Row>()`, `returns<U>()` and `single().returns<U>()` constrained their row
parameter to `Record<string, unknown>`. An `interface` has no implicit index
signature, so the most ordinary way to declare a row type failed to compile:

```typescript
interface User { id: string; email: string }

// before: TS2344 — Index signature for type 'string' is missing in type 'User'
// after: fine
const { data } = await supabase.from<User>('users').select('id, email')
```

A `type User = { … }` alias worked, which is why the existing type tests never
caught it. The constraint is now `object`, which still rejects `string`/`number`
row types. upstream `postgrest-js` constrains `returns` to nothing at all, so
this brings the adapter in line with the API it mirrors rather than being
stricter than it.

Also corrects the `EncryptedSingleQueryBuilder` documentation, which claimed
that "everything that only re-types or re-configures the pending request is
carried over" after `single()`/`maybeSingle()`. `overrideTypes` and `setHeader`
are not carried over — they have no adapter equivalent, and since
`single()`/`maybeSingle()` return the same builder instance rather than a
passthrough, calling them would fail at runtime, not just fail to typecheck.
