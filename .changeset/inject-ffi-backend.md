---
'@cipherstash/stack': minor
---

Inject the FFI binding into the encryption operations (#798, stages 1–3).

The native and `wasm-inline` entries had drifted into different client surfaces
because the operation classes reached their FFI binding by module-level
`import`. A value import of `@cipherstash/protect-ffi` is a *runtime load* of a
native binary, which cannot happen in a V8 isolate — so nothing importing an
operation was reusable on the edge, and `wasm-inline` reimplemented the surface
separately, where it never gained `.audit()` or `.withLockContext()`.

Operations now take a `CryptoBackend` instead of importing one, and the native
client injects `backend-native.ts` over the Node-API binding. This is the seam
that lets one operation layer serve both entries; the WASM entry does not use
it yet.

**`.catch()` and `.finally()` work on an operation.** They previously did not
exist, so an operation was awaitable but not assignable to `Promise<…>`. This
is the only user-visible change in this release.

Note that an operation is lazy and executes per settlement, not once: `then`,
`catch`, and `finally` each run it. `op.catch(h)` followed by `await op` is two
ZeroKMS round trips, as is awaiting the same operation twice. Hold the promise,
not the operation, if you need to settle it more than once.

No behaviour change otherwise — same Result shape, same error codes, same
payloads.
