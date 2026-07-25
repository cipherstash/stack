# Sharing one operation layer across both entries (#798)

Plan for removing the native/WASM client split. Stage 1 has landed; stages 2–5
are proposed and not yet started.

## The finding that changes the shape of this work

The Result-vs-thenable choice flagged in #798 is a false dichotomy. The native
entry already has both: `EncryptionOperation.then()` (`base-operation.ts:42`)
is twelve lines delegating to `execute()`, so `await client.encrypt(…)`
resolves to a `Result` **and** the same object carries `.audit()` /
`.withLockContext()`.

`@byteslice/result` imposes nothing — its entire surface is
`type Result<S,F> = Success<S> | Failure<F>` plus a `withResult` wrapper. And
the two Result types are already structurally the same:

```ts
// wasm-inline.ts:387
type WasmResult<T> = { data: T; failure?: never } | { data?: never; failure: EncryptionError }
// @byteslice/result
type Result<S, F> = { data: S; failure?: never } | { failure: F }
```

So the real question is only: should the WASM methods return the chainable
operation object instead of a bare `Promise`? Today that would be breaking,
because TypeScript's `Promise<T>` structurally requires `then`, `catch`,
`finally`, and `[Symbol.toStringTag]`, and the operation has only `then`.

**Adding the other three makes it non-breaking.** Verified against tsc
(`--strict`): a class with all four is assignable to `Promise<T>`, still
awaits to a `Result`, still chains, and still works with `Promise.all`. That
turns the "pick one, break the other entry" decision into a compatibility
shim, and is why the staging below front-loads it.

## Stage 1 — the seam (landed)

`CryptoBackend` (`encryption/backend.ts`) restates the six FFI functions both
entries already call, with type-only imports so the interface is portable.
`backend-native.ts` implements it over the Node-API binding and is the only
value import of `@cipherstash/protect-ffi` on the migrated path.
`EncryptOperation` takes a backend and calls `this.backend.encrypt`.

No public behaviour change. 1073 tests pass.

Two details that will recur: the backend delegates through a namespace so
bindings resolve at call time (eager destructuring broke three suites that
partially mock the FFI module), and `null-guards.test.ts` now injects a
throwing Proxy backend, so "no FFI call" is asserted positively.

## Stage 2 — `Promise<T>` conformance on `EncryptionOperation`

Add `catch`, `finally`, and `[Symbol.toStringTag]` to `EncryptionOperation`,
each delegating to `execute()` as `then` already does.

Purely additive on the native entry: every existing `await`, `.then()`,
`Promise<…>` annotation, and `Promise.all` keeps working, and `.catch()` /
`.finally()` start working where they previously did not compile.

This is what makes stage 4 non-breaking, so it lands first and alone.

**Verify:** existing suites unchanged; a `.test-d.ts` asserting an operation is
assignable to `Promise<Result<…>>`, awaits to a Result, and survives
`Promise.all`.

## Stage 3 — migrate the remaining five operations

`decrypt.ts`, `bulk-encrypt.ts`, `bulk-decrypt.ts`, `encrypt-query.ts`,
`batch-encrypt-query.ts` — same change as `EncryptOperation`: constructor takes
a backend, call sites go through it, the NAPI import becomes `import type`.

Two helpers also value-import the binding and need the same treatment:
`helpers/error-code.ts` (narrows with `instanceof` against the native
`ProtectError`, which is a runtime value — `wasm-inline.ts:392` already
documents why it uses a structural reader instead, so this is where the two
converge) and `helpers/model-helpers.ts`.

Still no public behaviour change; each operation is independently landable.

**Verify:** full `@cipherstash/stack` suite per operation. After the last one,
no value import of `@cipherstash/protect-ffi` remains outside
`backend-native.ts` and `encryption/index.ts` — assert that with a test.

## Stage 4 — WASM adopts the shared operations

Add `backend-wasm.ts` over `@cipherstash/protect-ffi/wasm-inline`, and have the
WASM client construct the shared operation classes instead of its own methods.

`WasmEncryptionClient` is ~938 lines and 10 async methods; most of it becomes
deletion. What must be preserved rather than dropped:

- the per-item `bulkEncrypt` routing (see #792 — the FFI primitive is per-item;
  native narrows it, so converging should widen native rather than narrow WASM)
- the structural error-code reader, which is the portable one
- the null/position-stability semantics its JSDoc pins

Because of stage 2, `await client.encrypt(…)` is unchanged for WASM callers and
`.audit()` / `.withLockContext()` appear on the entry for the first time. That
closes **#797**, the capability half of **#793**, and **#792** by construction.

**Verify:** the WASM entry's own suite; a cross-entry round-trip test
(encrypt native → decrypt WASM and back, with and without a lock context).

## Stage 5 — enforce the boundary

A build test asserting the shipped `packages/stack/dist/wasm-inline.js`
contains no reference to the Node-API specifier. Today that property holds and
is verified by hand; once operations are shared it must be enforced, because a
single stray import silently reintroduces a native load into an edge bundle.

Model it on `runtime-versions-embed.e2e.test.ts`, which asserts against the
built artifact rather than source for the same reason.

**This is the one stage that must not be deferred.** Everything else degrades
into ordinary bugs; this one degrades into a WASM entry that fails only at
runtime, in a customer's Worker.

## Open questions

1. **Does `Client` need abstracting?** `types.ts:48` is
   `Awaited<ReturnType<typeof newClient>>` — a native-derived type, though the
   import is type-only so it does not force a load. It may be tolerable as-is;
   decide at stage 4.
2. **Does the WASM binding accept `lockContext`?** Its `opts` are typed `any`
   across serde into the same Rust core, and the NAPI types declare
   `lockContext?: Context` on both single and bulk paths. Confirm against the
   Rust before stage 4 — #793.
3. **Bulk shape convergence direction.** #792 argues for widening native to
   per-item routing via an overload. That is additive; the reverse is not.
4. **Release sequencing.** Stages 1–3 are internal. Stage 4 changes the WASM
   entry's public surface additively, but deletes a lot — worth its own
   release regardless of semver strictness.

## What this does not do

It does not abstract encryption. `CryptoBackend` is deliberately a 1:1
restatement of the FFI so that swapping bindings is the only thing it enables.
Retries, caching, or validation added there would sit below the operation
classes, where the Result contract and audit/lock-context plumbing live, and
both entries would silently inherit it.
