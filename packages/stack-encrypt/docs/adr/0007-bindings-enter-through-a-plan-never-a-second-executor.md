---
status: accepted
date: 2026-10-04
extends: ADR-0003, ADR-0004
---

# Bindings enter the engine through a plan lowered from data, never through a second executor

> **Amended 2026-10-04**, after the first implementation PRs (#1068, #1069,
> #1071). The decision is unchanged. Amended: when the derive emits the plan
> (after its grammar is narrowed to the plan's), how EQL types are assembled
> (per language, from standard outputs), and the consequence that the EQL
> encoding lives twice.
>
> **Amended 2026-10-06**, by #1070. The decision is unchanged. Amended: the
> words binding and language SDK, what crosses the binding from Go, the proof
> of the lowering, where the generator gets the engine's rules, and what the
> guest takes in one call.

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
- The derive emits the builder rather than the combinators, once the two
  speak one grammar. The derive's attribute grammar is first narrowed to the
  plan's: it loses the field-level literal context (replaced by `identity`),
  non-plain literal contexts, `nested`, and a second output per source field.
  The plan then gains what the derive needs: the typed verb `encrypt_into`,
  `context_field`, the picker (a field name with an accessor) and the two
  starts, `Plan::value::<S>()` and `Plan::fields()`. The typed parts are
  Rust-only and have no data form. Only then does the derive emit the plan.
- The engine returns standard outputs (ciphertexts, terms, passthrough
  values) and never an EQL type. Each language assembles EQL types from
  them: Rust through the EQL type's own `EncryptFrom`, Go through generated
  code. There is no registry of EQL types and no target name in the data
  grammar, so the guest stays EQL-free.
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
  because it settles each term eagerly; the lowering removes that. Should
  term derivation become a ZeroKMS call, it arrives as a new `Request` kind
  batched with the data keys, and a plan still yields a `Pending`
  synchronously.
- The plan grammar is now wire format shared by the derive, the guest and
  Go. A change to it is a change to all three, which is the point.
- The EQL byte encoding lives twice, in `eql-bindings` (Rust) and in a Go EQL
  package, because Go assembles EQL types itself. A standing cross-language
  fixture guards it: encode in Rust, decode and re-encode in Go, compare the
  bytes. That is a fixture holding two encoders together, the thing this ADR
  rejects for executors; it is accepted here because an encoder is a pure
  function of standard outputs, with no keys, batching or context rules in
  it, and the alternative is EQL inside the guest.

The design history, the names rejected on the way and the sequencing are in
`docs/plans/2026-10-04-plan-builder.md`.

## Amended 2026-10-06 (#1070)

G1 to G8 and Go-1 to Go-13 name the principles in
`docs/sdk-design-principles.md`, general and Go.

ADR-0008 fixes two words this ADR used as one. A **binding** is the WASI or
FFI interface between the engine and a language: the guest's exports and the
data that crosses them. A **language SDK** is what users of that language work
with. The decision above is about the binding: a plan is the one thing that
crosses it. The Go SDK is struct tags, a generator and generated code, and its
users never see a plan (Go-7). Each "binding" above that names Go reads as the
Go SDK's generated code.

**A field crosses the binding only when its value does.** The first Go design
sent the full declaration and skipped passthrough values, which contradicted
decision 9 of the plan: every plan field is present in the value. Generated Go
code now sends a declaration and a value for each sealed and each indexed
field, and nothing for a passthrough or omitted field. The data grammar does
not change. The generated file still names every field, so a reviewer reads
the whole declaration (G1, Go-10).

**The record fixture is the proof of the lowering.** Sequencing rested on Go's
`plantest.Golden` snapshots not changing, and the Go SDK removes the package
that writes them. The proof is now a fixture both test suites read: the Rust
chain and the lowering each open the records that the other encrypted, and
both derive the same bytes for each term. The same fixture later holds
generated Go code to the Rust chain (G7: a claim is run before it is written).

**The generator asks the engine, and holds no copy of its rules.** `stashgen`
refuses an index that does not fit a Go type and an EQL type the engine cannot
produce. A second copy of those rules in Go would be the "lives twice" cost
this ADR accepts only for an encoder. `stashgen` runs the guest the SDK embeds
to check each declaration at `go generate`, so the rules have one source (G1)
and the check runs at the earliest stage Go allows (G3, Go-1).

**The guest takes one plan in one call.** `se_encrypt_record` takes one plan,
and the engine runs one plan under one key request. So one Go call covers one
type, and one request for several types is later work: the engine runs several
plans under one key request, then a guest export takes several plans with
their values. G5 allows an SDK to put several types in one request; it does
not require it before the engine can.

**The guest's value exports have no caller in Go.** The Go SDK seals a whole
value through a declaration (ADR-0008), so `se_encrypt`, `se_decrypt` and the
element exports have no Go caller. They stay while another host of the guest
may need them; they are not a Go path.
