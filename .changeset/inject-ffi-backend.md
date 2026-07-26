---
'@cipherstash/stack': minor
---

Share one operation layer across the native and `wasm-inline` entries (#798).

The two entries had drifted into different client surfaces because the
operation classes reached their FFI binding by module-level `import`. A value
import of `@cipherstash/protect-ffi` is a *runtime load* of a native binary,
which cannot happen in a V8 isolate — so nothing importing an operation was
reusable on the edge, and `wasm-inline` reimplemented the surface separately,
where it never gained `.audit()` or `.withLockContext()`.

Operations now take a `CryptoBackend` instead of importing one. Each entry
injects its own — `backend-native.ts` over the Node-API binding,
`backend-wasm.ts` over `@cipherstash/protect-ffi/wasm-inline`.

**`@cipherstash/stack/wasm-inline`: `encrypt()` now returns an operation.**
Source-compatible — `await client.encrypt(…)` still yields
`{ data } | { failure }`, and existing `Promise<…>` annotations still accept
it, because operations now satisfy `Promise<T>` structurally. New on this
entry: `.audit()` and `.withLockContext()` are chainable, since they live on
the shared operation rather than being reimplemented per entry. The other WASM
methods are unchanged for now.

**Both entries: rejections keep their detail.** Non-`Error` rejections were
losing their message on the native path — a string rejection became a generic
"Something went wrong". The WASM entry's coercion is now shared, so strings are
kept verbatim, objects are JSON-serialised, and a structural `code` survives
onto `failure.code`.

**Both entries: `.catch()` and `.finally()` work on an operation.** They
previously did not exist, so an operation was awaitable but not assignable to
`Promise<…>`.

Error-code extraction is now structural rather than `instanceof ProtectError`.
It matches any object carrying a string `code`, so a non-FFI error that happens
to have one yields that string where it previously yielded `undefined`. Call
sites use the value for reporting, not control flow.
