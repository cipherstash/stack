---
'@cipherstash/stack': patch
---

Upgrade `@cipherstash/protect-ffi` to 0.31.0, and adapt to the two breaking
changes it carries.

**Unknown option keys are now rejected rather than dropped**
(protectjs-ffi#147). The bulk paths were sending a local `id` alongside each
payload — bookkeeping this package uses to label results, which the binding
never read. serde silently discarded it before; 0.31 fails the whole call with
``unknown field `id` ``, a serde error naming a field the caller never wrote.
Every affected caller re-associates results **positionally** against the array
it passed in, so the `id` is now stripped at the FFI boundary and nothing about
the public `{ id, plaintext }` / `{ id, data }` envelope changes. This fixed
`bulkEncrypt`, `bulkDecrypt`, `encryptModel`, `decryptModel`,
`bulkEncryptModels`, `bulkDecryptModels`, and every DynamoDB operation built on
them.

**The `ProtectError` class is gone** (protectjs-ffi#150). Both bindings now
throw an ordinary `Error` with `code` set by Rust, so `getErrorCode` reads the
field structurally instead of narrowing with `instanceof` — which was
unreliable anyway (`instanceof` is false across duplicate copies of a package,
and the WASM build never shipped the class, which is why the edge entry already
had its own structural reader).

That change also closes a latent bug in the DynamoDB adapter: its fallback
branch accepted **any** string `code` with an unchecked cast, so a Node error
such as `ECONNRESET` was recorded as though it were an encryption failure code.
Codes are now validated against protect-ffi's known set via
`isProtectErrorCode`, and anything else falls back to
`DYNAMODB_ENCRYPTION_ERROR` as intended.

**The WASM entry's client construction moved.** protectjs-ffi#143 converged both
entries onto one `NewClientOptions`, so credentials now nest under `clientOpts`
rather than sitting at the top level — combined with #147 above, the old
placement failed *every* `@cipherstash/stack/wasm-inline` client construction
with ``unknown field `clientId` ``. Fixed, and the `as never` cast at that call
site is gone: 0.31 types the wasm `newClient` as `(opts: NewClientOptions)`, so
the compiler checks the object rather than being asserted past — the cast is
precisely why the misplacement was invisible.

**`cast_as` is no longer pre-translated on the WASM path.** That entry used to
rewrite the SDK vocabulary (`'string'` → `'text'`, `'number'` → `'double'`)
because the wasm build, unlike the Neon one, did not normalise and rejected the
SDK spellings. 0.31 normalises both entries inside Rust, and keeping the
translation would now be wrong rather than redundant: `'double'` and `'jsonb'`
are in neither the public nor the canonical vocabulary (those are `'float'` and
`'json'`), and unknown values are now rejected. The config crosses as authored.

No public API changes. Error `code` values that were already surfacing continue
to surface identically.
