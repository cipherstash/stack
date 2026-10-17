---
status: accepted
date: 2026-10-04
extends: ADR-0003, ADR-0004
amended: 2026-10-16, proposed with ADR-0009 and in effect when ADR-0009 is accepted
---

# Bindings enter the engine through a plan lowered from data, never through a second executor

> **Amended 2026-10-04**, after the first implementation PRs (#1068, #1069,
> #1071). The decision is unchanged. Amended: when the derive emits the plan
> (after its grammar is narrowed to the plan's), how EQL types are assembled
> (per language, from standard outputs), and the consequence that the EQL
> encoding lives twice.
>
> **Amended 2026-10-06**, by #1070. One bullet of the decision changes: the
> data grammar names an EQL type as a target, and the guest build that holds
> the EQL types returns the finished value. Also amended: the words binding
> and language SDK, what crosses the binding from Go, the proof of the
> lowering, where the generator gets the engine's rules, what the guest takes
> in one call, and the value exports.
>
> **Amended 2026-10-07**, by #1094. One sentence of the decision was wrong:
> it listed `context_field` among "the typed parts" that are Rust-only and
> have no data form. `FieldsBuilder::context_field` is not typed — it names
> a field whose value is the context, as `passthrough` names one — so the
> last bullet of the decision applies to it: a capability the data grammar
> cannot express is added to the grammar, once. The data grammar now has it,
> as a plan-level `"context_field"` key (`dynamic::record`), and so does the
> Go SDK, as the `context_field` tag word. The typed parts that stay
> Rust-only are the typed verb `encrypt_into`, the picker and the one-value
> start.
>
> **Amended 2026-10-16**, by #1188, **proposed**. This amendment depends on
> ADR-0009, which is proposed, and takes effect when ADR-0009 is accepted;
> until then it is proposed with it, and changes with it. The decision is
> unchanged. Added, under its last bullet: the operator and its input in the
> data grammar, the query term and its query domain back, `verify` and
> `target_limit` as engine exports, and the operators each EQL type answers,
> with their fidelity, in the catalog.

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

A later ADR changed parts of this decision: ADR-0008, the language SDK
principles, and the Go SDK design it governs. This amendment records what
changed. G1 to G8 and Go-1 to Go-13 name the principles in
`docs/sdk-design-principles.md`, general and Go.

ADR-0008 fixes two words this ADR used as one. A **binding** is the WASI or
FFI interface between the engine and a language: the guest's exports and the
data that crosses them. A **language SDK** is what users of that language work
with. The decision above is about the binding: a plan is the one thing that
crosses it. The Go SDK is struct tags, a generator and generated code, and its
users never see a plan (Go-7). Each "binding" above that names Go reads as the
Go SDK's generated code.

**The whole struct crosses the binding, both ways.** Generated Go code sends
every field with its value, passthrough fields included, and the engine
returns the whole struct the same way. That is heavier on the wire than
sending sealed fields alone. It needs no reconstitution on either side, so the
code stays simpler. Decision 9 of the plan holds: every plan field is present
in the value, and the data grammar does not change (G1, Go-10).

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

**The guest's value exports are removed.** The Go SDK seals a whole value
through a declaration (ADR-0008), so `se_encrypt` and `se_decrypt` have no
caller. They are removed rather than kept for a host that does not exist.

**The guest returns an EQL value when a plan names the type.** The decision
above said no registry, no target name in the data grammar, and a guest that
stays EQL-free. That is reversed. The data grammar gains a target field form,
exclusive with the output verbs. A dispatch that `eql-codegen` generates
resolves the name, in a guest build that holds the EQL types; the build
without them refuses a target name. Go stores the value the guest returns and
has no EQL encoder, so the "lives twice" consequence below no longer applies
to Go (G1: one engine). The reasons recorded against this on 2026-10-04 were
guest size and an EQL-free guest for programs that never store into EQL. Two
guest builds answer the second, and the first is measured before the SDK ships
one build or two (G7).

## Amended 2026-10-16 (#1188), proposed with ADR-0009

**Status: proposed.** ADR-0009 is proposed, and this amendment rests on it:
it takes effect when ADR-0009 is accepted, and is revised or withdrawn with
it. The code it describes lands first, as ADR-0009's Rust side has
(#1182 to #1186), because Stack Encrypt has no stored data and no released
binding a change could break.

ADR-0009 makes the operator, not the index, what a query names, and gives a
probabilistic term `verify` and `target_limit`. The data grammar a binding
lowered named a field and, for a query, took the term the field's EQL type
chose. It had no operator and no operator input, and no export could verify
a decrypted value or size a fetch. The last bullet of the decision says what
to do with a capability the grammar cannot express: add it to the grammar,
once, so every author has it. This amendment does that for the query side.
ADR-0009's appendix B is the sketch it was amended from.

**A query names a field, an operator and the operator's input.** The
operator crosses as its name: `eq`, `lt`, `lte`, `gt`, `gte`, `between` or
`matches`. The input is one value, or for `between` a list of two, low then
high. The engine reads the input as the field's declared type first
(`dynamic::read`), so a host's float `34.0` queries a `uint64` field as the
`u64` the field stored. It then finds the index that answers the operator by
the table the typed path's `DefaultIndex` impls state, written over a type
and the indexes a field declares (`dynamic::OpSpec::answered_by`): `eq`
through an equality index, `matches` through a match index over text, the
orderings through an ORE index over an integer, or OPE when the field
declares no ORE. A field that does not answer the operator is refused with
the same shape of error as a mistyped field: an input error naming the field,
with the reason `operator_not_answered` (or `unknown_operator`,
`not_a_range`). The refusals the typed path makes before a term exists, a
range the wrong way round and match text that cuts no token, are refused the
same way here, before the cipher is consulted.

**The term comes back with its query domain.** The guest's
`se_query_term(input, plan, field, operator, options)` returns one object:
the operator, its fidelity, the index that answered, the PostgreSQL domain
the term is cast to, and the term. A field with indexes derives that index's
term under the field's context, by the derivation its stored terms came
from, as bytes, and `between` derives one term per bound under the one
context, as a list of two. A field that names an EQL type runs the type's
query twin, and the term is the twin's JSON and the domain its
`query_sql_domain`. One query domain per operator is EQL v4's (ADR-0009,
decision 8); until that lands in the catalog a type's twin carries every term
of the type.

**`verify` and `target_limit` are engine exports.** `se_verify(input, values,
plan, field, operator)` answers one boolean per decrypted value, a page in
one call. `se_target_limit(term, stats, plan, field, operator, want)` answers
the rows to fetch, or null for no finite fetch. Neither uses a key, so each
runs in a guest that holds no cipher, as `se_plan_check` does. `verify` names
the query as it was derived, by the field, the operator and the input, and
the engine cuts the input's tokens again with the field's own tokenizer and
options. The tokens are plaintext, so no term carries them across the
binding. Sending the input and a page of decrypted values back in is no new
exposure: the input came from the host, and the values came out of the
guest as a decrypt. The alternative, a tokenizer in each language, is the
"lives twice" cost this ADR accepts only for an encoder, and a tokenizer that
drifts from the one that built the stored filter verifies the wrong thing.
`target_limit` takes the term's bytes, because the number of bits the query
sets is a property of the term the engine built, and the fill formula
belongs beside the index configuration. Both refuse an exact operator, which
has nothing to verify and no fetch to size, as the typed path does not
compile the call.

**The catalog reports the operators each EQL type answers, and their
fidelity.** Each `se_targets` entry gains `operators`: one object per
operator the engine answers for a field that names the type, with its name,
its fidelity (`exact` or `probabilistic`), its arity (`one` or `pair`) and
the type's index that answers it. The engine computes the list from the
type's row by the same table every plan field is held to, so a generator
asks the engine it embeds rather than holding a copy of the rules, as the
2026-10-06 amendment asks of every rule. ADR-0009 rejects a fidelity value
on a term, because Rust says it with a trait. A generator asks before the
program runs, so it needs the answer as data, and the code it generates
carries `Verify` only where the answer is `probabilistic`, which rebuilds
decision 4 of ADR-0009 in a language without traits. Today `TextEq` answers
`eq`, `TextMatch` answers `matches`, and the storage-only types have no twin,
so answer nothing. A type answers `matches` through its twin only when the
engine knows the options its match index is built under, since `verify`
must cut the query's tokens as the stored filter was cut: `eql-bindings`
gives them for each type with a match index (`Target::match_options`, EQL's
one match configuration), and the guest hands them to the engine with the
type's descriptor. They are not on the wire, because a host has no use for
them. `verify` and `target_limit` then run under those options, reading the
twin's `bf`. No type answers `between` yet: a twin is one value, not a
range.

What does not change: a binding still reaches the engine through a plan, and
nothing here derives a term outside the engine's own derivation, so a query
from Go and the typed query chain derive the same bytes. A cross-language
fixture holds them together (`tests/fixtures/query_operators.json`): the Rust
side checks each recorded term against the typed chain, and the Go SDK's
tests derive, verify and size the same queries through the guest.
The catalog answers for an EQL type; a field declared with indexes has no
type to look up, so `se_operators` answers for any field of a plan: the
plan and the field's name in, the same operator objects out, computed by the
one table `se_query_term` reads (`dynamic::field_operators`). The Go
generator asks it for every sealed field, `encrypt_into` fields included,
and writes one method per operator (#1189).

`se_query`, which derived a target field's twin with no operator, is
removed: the generated Go code names operators (#1189), and `eq` on a target
field is the twin. `se_term`, a term by index under an explicit context, no
longer serves a query. It stays for one host need: a record call's term
failure does not say which row and field it came from, and the Go SDK asks
`se_term` again for each term to name them. When the record exports name the
field themselves, it goes too.

A data plan's match index declares no `expected_tokens` prior, so
`target_limit` on a field declared as data is unbounded without a measured
histogram. A data form for the prior is later work.
