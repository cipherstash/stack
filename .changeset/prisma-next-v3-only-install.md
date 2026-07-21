---
'@cipherstash/prisma-next': minor
---

Make `@cipherstash/prisma-next` **EQL v3 only**. The EQL v2 surface is removed
entirely — install path, authoring constructors, runtime codecs, and the v2
subpath exports.

**Why:** the v2 and v3 baselines were chained — the v3 migration edge started
from the v2 baseline's `to` state and the head ref required both invariants — so
the only path to head ran the v2 install first. The v2 bundle's install fails on
managed Postgres (e.g. Supabase) where the connecting role is **not a
superuser**, which made the adapter unusable there even for v3-only apps.
Installing only EQL v3 (which applies fine as a non-superuser) fixes this.

**Breaking — install path:** the EQL v2 baseline migration
(`20260601T0000_install_eql_bundle`) is removed, and the contract now models no
storage (the retired `eql_v2_configuration` table is gone). The v3 baseline
(`20260601T0100_install_eql_v3_bundle`) is re-rooted as the sole invariant-only
**genesis** edge (`from: null`); the head ref requires only
`cipherstash:install-eql-v3-bundle-v1`. `prisma-next migration apply` now
installs EQL v3 exclusively and works on Supabase as a non-superuser.

**Breaking — API:** the EQL v2 authoring/runtime surface is removed:

- `cipherstashFromStackV2`, `deriveStackSchemas`, and `createCipherstashSdk`
  (from `./stack`) — use `cipherstashFromStack` (v3).
- The `encrypted*V2` TS column factories and the `cipherstash.Encrypted*V2` PSL
  constructors (from `./column-types`) — use the v3 domain factories/constructors
  (`text`/`textSearch`/`bigIntOrd`/… and `cipherstash.TextSearch()` etc.).
- The v2 runtime codecs, `createCipherstashRuntimeDescriptor`, the `cipherstash*`
  query operators/helpers, and the `EncryptedDouble` envelope (from `./runtime`)
  — use the v3 runtime (`createCipherstashV3RuntimeDescriptor`,
  `bulkEncryptMiddlewareV3`, the `eql*` operators, `EncryptedNumber`). The
  version-neutral envelopes (`EncryptedString`/`BigInt`/`Boolean`/`Date`/`Json`)
  and `decryptAll` are unchanged.
- The `./middleware` and `./migration` subpath exports are removed (the v2
  bulk-encrypt middleware and call-classes). Use `bulkEncryptMiddlewareV3` from
  `./runtime` / `./v3`.

Apps still on the v2 surface must move to the v3 constructors and regenerate
their contract (`prisma-next contract emit`); there is no supported EQL v2 path
in this package anymore.

**Also:** the "bulk-encrypt middleware not wired" diagnostic is now raised on the
v3 write path. Encoding an unencrypted value with an SDK that has no
`bulkEncryptMiddlewareV3(sdk)` registered against it fails fast with
`RUNTIME.ENCODE_FAILED` and a copy-pasteable wiring snippet, instead of surfacing
as an opaque pg-level serialise error. (The guard existed on the v2 codec; the v3
codec had never wired it up.)
