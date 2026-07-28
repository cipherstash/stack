# Sharing one operation layer across both entries (#798)

Plan for removing the native/WASM client split.

**Status:** stages 1–3 landed. Stage 5 turned out to be already complete (see
below — the plan was wrong to list it). Stage 4 was attempted and reverted;
**its upstream blocker is now fixed and released**, so stage 4 is ready to
restart once the bump lands. Read "What stage 4 hit" first — four of its five
problems are still live and only one of them was the blocker.

Before restarting, note what changed underneath:

- **The blocker is gone.** protectjs-ffi#143 closed #142 and shipped in
  protect-ffi **0.31.0**: the WASM `.d.ts` now imports the named option types
  from a shared module instead of typing every `opts` as `any`. `CryptoBackend`
  no longer has to borrow the native types, and the six `as never` casts in
  `backend-wasm.ts` can go. **Stage 4 depends on the 0.31 bump landing** (#809).
- **Problem 1 now has a test.** `wasm-inline-edge-safety.test.ts` evaluates the
  built `dist/wasm-inline.js` in a realm with no `process`, so the failure that
  forced the revert is caught automatically. That was the real gap: every gate
  was green while the entry was broken on import.
- **Problem 2 is partly pre-solved.** protect-ffi 0.31 normalises `cast_as` in
  Rust for both entries, so `normalizeCastAs` is gone from `wasm-inline.ts`.
  The `Date`-crossing normalisation (`toWasmFfiPlaintext`) is a separate
  concern and still has to move into the operation or the backend.

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

### What stage 4 hit (attempted, then reverted)

The `encrypt` migration was written and reverted. Five problems, four of them
confirmed against the built artifact rather than reasoned about. None was
caught by the suite, which is the more useful finding: **1073 unit tests and
the bundle-isolation test all passed while the WASM entry was broken on
import.**

1. **The logger crashed the entry.** `EncryptOperation` imports
   `@/utils/logger`, whose `initStackLogger()` runs at module scope and read
   `process.env.STASH_STACK_LOG` unguarded. So `import`ing
   `@cipherstash/stack/wasm-inline` threw `ReferenceError: process is not
   defined` in any runtime without the Node global — a Worker without
   `nodejs_compat`, or a browser. The guard is now in place (see the JSDoc on
   `levelFromEnv`), so this specific trap is disarmed, but the general shape
   recurs: **anything the operations transitively import ships to the edge.**
   The bundle-isolation test checks import *specifiers*, so it cannot see a
   global; the Deno e2e cannot either, because Deno provides `process`.
2. **The single-encrypt path lost `toWasmFfiPlaintext`.** A JS `Date` has no
   enumerable own properties, so wasm-bindgen carries it across as `{}` —
   silent corruption of every date/timestamp column. The bulk and query paths
   kept the call; encrypt became the only one without it. Any shared operation
   must apply this normalisation, which means it belongs *in* the operation (or
   in the backend), not in the entry's own method body.
3. **Guards moved outside `withResult`.** `execute()` calls
   `log.set({ column: this.column.getName() })` before the `withResult`
   wrapper, so a malformed column rejects instead of returning `{ failure }`.
   The old WASM body ran `getColumnName()` *inside* `wasmResult`, with a named
   error message. This breaks the contract
   `wasm-inline-result-contract.test.ts` exists to protect, and that test did
   not catch it because it only covers FFI rejections.
4. **The published types stopped being self-contained.** See the section below
   — this is the blocker.
5. **`unverifiedContext: undefined` reached the serde boundary** for the first
   time on this entry (the WASM client had never sent the field). Unconfirmed
   whether the Rust rejects it, but `toFfiQueryTerm`'s comment records exactly
   this failure for `queryOp`: "serde on the WASM side rejects
   explicitly-undefined fields … the native NAPI layer tolerates undefined; the
   WASM one does not." Omit the key when there is no metadata.

### The blocker: protect-ffi's option types are native-only

`dist/wasm/protect_ffi.d.ts` types every binding function as
`(client: WasmClient, opts: any)`. It exports none of `EncryptOptions`,
`DecryptOptions`, `Context`, `ProtectErrorCode`, `JsPlaintext`, or
`EncryptedPayload` — those exist only in the Node-API `.d.ts`.

Two consequences follow, and they are the same root cause:

- `CryptoBackend` must import those types from `@cipherstash/protect-ffi`, the
  native specifier. Emitting a WASM-entry `.d.ts` that references
  `CryptoBackend` therefore puts that specifier into the published types of the
  bundle whose whole purpose is to avoid the native binding. `wasm-inline.ts`
  already documents this class of regression: `WasmResult` is declared locally
  rather than re-exported precisely so `@byteslice/result` stays out of the
  emitted `.d.ts`.
- `backend-wasm.ts` needs six `as never` casts, so the WASM call sites get no
  type-checking at all. The one interface that was supposed to keep the two
  bindings honest checks only one of them.

**The fix was upstream, in protect-ffi** — filed as
cipherstash/protectjs-ffi#142: have the WASM `.d.ts` use the same named option
types as the Node-API one, rather than `any`.

**RESOLVED.** protectjs-ffi#143 did exactly that and shipped in **0.31.0**:
`dist/wasm/protect_ffi.d.ts` now imports `EncryptOptions`, `DecryptOptions`,
`NewClientOptions`, `Context`, `JsPlaintext` and the rest from
`../../lib/types.js` and re-exports them, so both builds describe themselves
with one set of names. `CryptoBackend` can import from the `/wasm-inline`
specifier on that side, and the `as never` casts become unnecessary.

Two caveats for whoever restarts stage 4:

- **It needs the bump.** The 0.31 upgrade is #809; stage 4 cannot land before
  it. That upgrade is not free — 0.31 also rejects unknown option keys
  (protectjs-ffi#147) and removes the `ProtectError` class (#150), both of
  which this repo depended on.
- **`@byteslice/result` is a separate leak.** The revert found the emitted
  `.d.ts` gained imports of *both* the native protect-ffi root and
  `@byteslice/result`. Only the first is fixed upstream. The second is why
  `WasmResult` is declared locally, and a shared operation layer whose return
  type comes from `@byteslice/result` reintroduces it — so stage 4 still has to
  decide between inlining that type into the emitted declarations or keeping a
  local structural alias.

Note the four protect-ffi type names still in the reverted `.d.ts`
(`EncryptedPayload`, `EncryptedQuery`, `EncryptedV3Query`, `ProtectErrorCode`)
predate this work — they arrive through `@/types` re-exports. So the upstream
change is worth making regardless of #798; it just becomes load-bearing here.

### Also still outstanding

- `model-helpers.ts` value-imports `decryptBulk` / `encryptBulk` from the
  native binding, so the four model operations cannot join the shared path. The
  non-fallible `decryptBulk` is deliberately absent from `CryptoBackend`, so
  this needs a decision about widening the interface, not just a mechanical
  edit. The commit message for stage 3 overstated this as "migrate the
  remaining operations" — the model operations were never migrated.
- `wasm-inline.ts` still carries its own `toError`, `readErrorCode`, and
  `safeString`. They should be shared, but `helpers/error-code.ts` is back on
  `instanceof` (see its JSDoc), so it is not WASM-reachable again until stage 4.
- Operations re-execute per settlement. Stage 2 added `.catch()` / `.finally()`
  without memoising `execute()`, so `op.catch(h)` then `await op` is two round
  trips. Documented in the changeset; memoising would change existing native
  semantics for double-await, so it deserves its own decision.

## Stage 5 — enforce the boundary (ALREADY DONE)

**Correction: this stage was already complete when the plan was written.**
`__tests__/wasm-inline-bundle-isolation.test.ts` was added during #741 and is
stricter than what this plan proposed. It extracts every module specifier from
the built `dist/wasm-inline.js` and asserts three things:

1. `protect-ffi` is reached only via `/wasm-inline`, never the native root.
2. `@cipherstash/auth` likewise — it also ships a native entry.
3. An allowlist of *every* external the bundle imports, so any addition is a
   deliberate change rather than a silent transitive leak.

It also gates on freshness — rebuilding when `dist` is older than `src` or
`tsup.config.ts` — so it can never pass against a stale artifact.

Its header records that this exact leak already happened once: during #741,
importing `@/encryption/helpers/error-code` pulled the native `ProtectError`
class in for an `instanceof` narrow, and it was caught only in review.

**That is a direct constraint on stage 4**, and corroborates deferring
`error-code.ts` in stage 3: the shared operation path must not reach it from
the WASM entry, which is exactly why `wasm-inline.ts:392` carries its own
structural error-code reader. Converging the two means the *structural* reader
wins; the `instanceof` one cannot be shared.

So the boundary is enforced today, and stage 4 will be caught by an existing
test if it regresses. Nothing to build here.

## Open questions

1. **Does `Client` need abstracting?** `types.ts:48` is
   `Awaited<ReturnType<typeof newClient>>` — a native-derived type, though the
   import is type-only so it does not force a load. It may be tolerable as-is;
   decide at stage 4.
2. **Does the WASM binding accept `lockContext`?** Its `opts` are typed `any`
   across serde into the same Rust core, and the NAPI types declare
   `lockContext?: Context` on both single and bulk paths. Confirm against the
   Rust before stage 4 — #793. **Still open.** Stage 4 shipped `.withLockContext()`
   on the WASM entry with this unresolved, which is a large part of why it was
   reverted: if serde drops the field, the caller gets a successful-looking
   payload whose key is not bound to the claim they asked for. Failing loudly
   would be fine; succeeding quietly is not. Settle this with a live call
   before re-attempting, and add a WASM lock-context test — there is none.
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
