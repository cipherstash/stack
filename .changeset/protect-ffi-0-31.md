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

No public API changes. Error `code` values that were already surfacing continue
to surface identically.
