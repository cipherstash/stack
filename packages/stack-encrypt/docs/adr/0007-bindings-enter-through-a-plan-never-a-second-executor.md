---
status: accepted
date: 2026-10-04
extends: ADR-0003, ADR-0004
---

# Bindings enter the engine through a plan lowered from data, never through a second executor

Stack Encrypt has one execution engine: the `Encryption` and `Decryption`
descriptions in `target/` and the batched `Pending` they produce. ADR-0003
made targets declarative and put execution in the cipher; ADR-0004 threaded
one context through a declaration. Neither said who may drive the engine.
This ADR does: a binding reaches it through a **plan**, a saved declaration
lowered from data into the same builder a Rust caller and the derive use,
and nothing else executes.

## The problem

By 2026-10 two front ends drove the engine by hand. The `#[derive(EncryptFrom)]`
codegen composed the combinators (`ciphertext().accepting().zip(equality())…
.under(label).project(select)`) per field. `dynamic::record`, which the Go
guest calls, walked a data plan, called the term functions and the seal path
per field itself, collected the pendings and merged them with `Pending::all`.
It never touched `Encryption`. The two encoded the same rules, one context per
field, extension by the caller, batching, and nothing but tests kept them in
step. They had already drifted: a derive over a bare `u32` sealed four
untagged bytes while a plan sealed the tagged encoding, so the same field
written by each did not interchange, and the record module's own docs
recorded it as "by design". A third executor was the natural next step for
any binding feature the data plan did not yet express.

## Options considered

1. **Keep two executors, add tests.** Cheapest now. Every rule exists twice
   and a fixture is the only thing holding them together; the tagged
   encoding divergence shows what that is worth.
2. **A generic FFI entry per target kind** (`EncryptAs(ctx, keyset, source,
   Target[O])` and friends): the first draft of the #1046 plan. It named the
   value / record / probe split in a new vocabulary and still ran through
   `dynamic::record`, so it added surface without removing an executor.
3. **One builder, three authors.** A chained builder that lowers to the
   combinators and is the only thing that runs them. A Rust caller writes the
   chain; the derive emits it from attributes; a binding lowers a data plan
   into it. `dynamic::record` becomes that lowering, and its executor is
   deleted.

## Decision

Option 3.

- A **plan** is the reusable, validated declaration of how a value is
  encrypted: a context and indexes, or field by field each field's. It is the
  one concept a binding has. Cipher-directed and target-directed encryption
  (ADR-0001, ADR-0003) remain the preferred entry points for a native Rust
  caller; target-directed is Rust-only.
- The builder lowers every call to an existing combinator, with three
  additions the engine lacked: a `passthrough()` constructor, execution of a
  description held by value, and `Index<S>` / `Indexes<S>` so a tuple of
  indexes composes once in the engine.
- The derive emits the builder rather than the combinators.
- `dynamic::record` parses a data plan and drives the builder. The one step
  that stays dynamic is dispatching a runtime scalar to a typed index. Its own
  per-field loop, batching and output shaping are removed.
- No binding, guest or module may call the term functions or the seal path
  directly to produce a record. A capability a plan cannot express is added
  to the plan grammar and to the builder, once, and every author gets it.

## Consequences

- One code path from any author to the bytes: a Rust chain, a derived type,
  the Go guest and a future binding produce the same ciphertext and terms for
  the same declaration because they run the same code. The tagged-versus-
  untagged divergence closes by construction rather than by fixture.
- The combinators stay public as the extension point (custom targets, EQL
  domain types, `transcode`) but are not a front door. An `Encryption` is
  single-use and is not data, so it could never have been a plan.
- A plan yields a `Pending` synchronously, like a typed target: term
  derivation is local to the keyset cipher, whose index key was loaded when
  the keyset was resolved. `dynamic::record::encrypt` is `async` today only
  because it settles each term eagerly; the lowering removes that.
- The plan grammar is now wire format shared by the derive, the guest and
  Go. A change to it is a change to all three, which is the point.

The design history, the names rejected on the way and the sequencing are in
`docs/plans/2026-10-04-plan-builder.md`.
