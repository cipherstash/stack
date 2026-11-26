# Move vitaminc's AEAD crates into the stack, and define the value types once

Status: draft, rewritten 26 November 2026. Decisions by Dan Draper:

- Move the AEAD crates into this repository as crates. Do not fold them into
  modules of `stack-encrypt`.
- Work in two stages: move first with no change in behaviour, then
  consolidate.
- Keep the move as small as possible. `vitaminc-protected` and
  `vitaminc-random` never move.
- No more work on the TypeScript SDK until this is done.

The first draft of this plan (14 November) moved nine crates, with `ore.rs`,
into `stack-encrypt` as modules. This draft replaces it.

AEAD means authenticated encryption with associated data. The AEAD crates
define the value types, how each is encoded, and how a value is sealed.

## Summary

Three crates move from `cipherstash/vitaminc` into this repository:
`vitaminc-aead`, `vitaminc-aead-frame` and `vitaminc-aead-derive`. They keep
their names and are published from here.

Then the value handling is consolidated. Today the list of value types is
written down in vitaminc, written again in the engine (`stack-encrypt`), and
reconciled a third time in each language SDK. After this plan:

- The AEAD crates define the types, the encodings, the null rule, the
  canonical form of each type, and the name of each type. Nothing else does.
- The engine depends on the AEAD crates. It does not wrap their types, hold
  its own list of them, or rewrite a value.
- A language bridge converts a host language's values to and from the AEAD
  types, and does nothing else.

No stored format changes. A change to stored bytes during this work is a
defect.

## Why

### The same list is written at least five times

vitaminc defines the types as `Logical` and `Physical`. The engine's
`dynamic` module then restates them:

| Where | What it restates |
|---|---|
| `ValueKind` (`dynamic/kind.rs`) | A second enum of 21 types, with the text names a plan uses |
| `model`, `model_null` (`dynamic/value_frame.rs`) | An allow-list of the types the engine accepts |
| `scalar_kind` (`dynamic/value_frame.rs`) | A value's type as a `ValueKind` |
| `scalar_of` (`dynamic/kind.rs`) | A sample value for each `ValueKind` |
| `ValueKind::sealed_null` (`dynamic/kind.rs`) | The fixed-width type of each kind's null |
| `ordered`, `order_of` (`dynamic/term.rs`) | Which types an order index takes, twice |

Outside the engine, the Go module (`record.Kind`), EQL (`plaintext_of` and
the `Plaintext` trait) and the TypeScript SDK each hold a copy as well. Go and
EQL call these "vitaminc's ValueKind names". vitaminc has no `ValueKind`.

### The copies disagree

- **A UUID.** vitaminc has the type, a sealed form, a null, an equality term
  and an order term for it. The JavaScript bridge reads and builds one. The
  engine's allow-list leaves it out, and no reason is recorded (#1821). The
  engine is not consistent with itself either: `dynamic::term()` gives a UUID
  an equality term, and the record path cannot store one.
- **A timestamp.** The JavaScript bridge writes a `Date` in milliseconds. The
  engine rewrites every timestamp to nanoseconds. The bridge's README says a
  `Date` is stored as its millisecond count, which is false once the value
  passes through the engine.
- **An integer.** Go converts an integer to the declared type before it
  encodes it. The engine refuses a value of another width on write, and
  converts one on a query. The JavaScript bridge sends a `bigint` at the
  narrowest width that fits, whatever the field declares.

### An SDK pays for each disagreement

The TypeScript SDK's addon classifies a value to explain the engine's refusal
(`is_uuid`), wraps the engine's wrapper to satisfy a trait (`OneValue`), and
copies every value twice: the bridge writes a frame, then the engine parses
it and copies it into a second buffer.

### `ValueFrame` is not needed for what it is assumed to do

`ValueFrame` is the engine's wrapper around frame bytes. It is not what wipes
a plaintext. `to_frame` and `decrypt_to_frame` already return
`vitaminc_protected::Buffer`, which wipes its bytes when it grows and when it
drops, and whose `Debug` shows nothing.

What `ValueFrame` does add:

- the allow-list;
- an owned value that can be encrypted, and a target a ciphertext opens into;
- comparison in constant time;
- reading a text value as a context label.

The engine has to write these on a wrapper because it cannot implement the
AEAD crates' traits for a type from another crate. Once the AEAD crates are in
this repository, they can provide them.

## What moves, and what stays

### Stage 1 moves three crates

| Crate | Why |
|---|---|
| `vitaminc-aead` | The types, the sealed leaf, the ciphertext tree, the sinks |
| `vitaminc-aead-frame` | The frame encoding a binding sends |
| `vitaminc-aead-derive` | `vitaminc-aead` depends on it |

The JavaScript bridge, `recipher-value-napi`, is already here. It is a renamed
copy of `vitaminc-aead-napi` 0.10.0, and depends only on `vitaminc-aead` and
`vitaminc-protected`.

### What stays in vitaminc

- **Never moves:** `vitaminc-protected`, `vitaminc-random`.
- **Stays, and does not depend on the AEAD crates:** `vitaminc-context`
  (`vitaminc-aead` depends on it), `vitaminc-hmac` (it depends on
  `vitaminc-prf`), `vitaminc-traits`, and the rest.
- **Stays for now, and depends on `vitaminc-aead`:** `vitaminc-normalize`,
  `vitaminc-prf`, `vitaminc-ore`, `vitaminc-encrypt`. See the next section.

`clww-ore` and `ore-rs` stay in `cipherstash/ore.rs`.

### The four crates that depend on `vitaminc-aead`

| Crate | What it uses from `vitaminc-aead` |
|---|---|
| `vitaminc-normalize` | The canonical-form helpers (`timestamp_nanos`, `strip_trailing_zeros`, the date and timestamp limits). It implements the `Sink` traits, and uses the encrypting sink's internals (`shape`, `seal_all`, `Tee`). |
| `vitaminc-ore` | `Logical`, `Physical`, the value types. It implements the `Sink` traits. |
| `vitaminc-prf` | `Logical`, `Physical`, behind an optional feature. |
| `vitaminc-encrypt` | `seal::Cipher`, which it implements for the AES cipher, and the ciphertext builder. |

The engine passes AEAD types into all four. So the engine and these four must
build against the same `vitaminc-aead`. Two consequences:

- **The moved crates keep their names.** Under a new name, Cargo would build
  two crates with two sets of types, and the engine's calls into the four
  would not compile.
- **A breaking change to `vitaminc-aead` needs new releases of all four**,
  and then of `clww-ore` and `ore-rs`, which the root `Cargo.toml` pins with
  `=`. A change that only adds a type, a method or a `Logical` variant does
  not break them. A change to the `Sink` traits or to `Physical` does.

Stage 2 decides, step by step, whether a change can be made without breaking
them. If one cannot, the four move too. `vitaminc-normalize` is the most
likely: it holds rules about canonical forms, which this plan gives to the
AEAD crates.

## Stage 0: pin the bytes

Before any code moves, every stored and wire format has a test that fails
when its bytes change. Most exist: the conformance corpus
(`conformance/stack-encrypt/v1`), the engine's stored-row fixtures, and
vitaminc's own storage corpus. The known gaps:

- **What the JavaScript bridge writes.** No TypeScript runner exists for the
  corpus, so nothing compares a `Date`'s frame with the engine's.
- **A host's typed null.** One engine unit test covers it. No conformance
  case does.
- **A JSON document's leaf.** The dynamic path writes a bytes leaf and the
  typed path seals a text leaf. Which one each path stores has not been
  traced.
- **The contents of `stored_rows_v1.json` and
  `record-scalars-v1.expected.rust-native.json`** have not been listed by
  type.

The work is to list what each fixture freezes, fill the gaps, and run the
whole set against the crates.io versions in use today.

## Stage 1: move the three crates, unchanged

1. Copy the three crates in at the version the root `Cargo.lock` resolves.
   Keep their names. Bring their history if possible, as was done for the
   stack-* crates.
2. Bring their tests, fuzz targets and benchmarks, and the checks under
   "Checks that must move with the code".
3. Point every workspace at them: the root workspace, the TypeScript SDK's
   workspace, the two Go guests, and EQL's workspace. Each resolves vitaminc
   on its own today.
4. Do not publish them yet. In each workspace, a `[patch.crates-io]` table
   makes the four crates from crates.io resolve the in-repository
   `vitaminc-aead`. That works while its version stays on the 0.10 line.
5. Move the open vitaminc issues about this code with it: vitaminc #643,
   #473 and #632.

This stage changes no behaviour. The copied source can be compared with the
published crates file by file.

While the crates are unpublished:

- **`stack-encrypt` cannot be published.** A published crate cannot depend
  on a path, and a consumer has no `[patch]` table.
- **The Go and TypeScript SDKs are not affected.** Both build the engine by
  path from the tree.
- **`eql-bindings` can be published until step 2.4.** Its `stack-encrypt`
  feature is compiled against the `stack-encrypt` on crates.io when it is
  published. Stage 1 changes no API, so that still compiles. Step 2.4 changes
  the API that `eql-bindings` uses, and from then an EQL release waits for a
  `stack-encrypt` release.
- **vitaminc must stop changing these three crates**, or the two copies
  diverge.

### Before the next `stack-encrypt` release

Publish the three crates from this repository, under the same names. That
needs the crates.io owners and trusted publishing moved here. If stage 2 has
made a breaking change by then, the four crates that depend on
`vitaminc-aead` need a release against it first, or must have moved.

## Stage 2: consolidate

Each step is its own pull request or small set of them. Each passes the
stage 0 tests with no change to pinned bytes. The steps are in dependency
order.

### 2.1 One canonical form for a timestamp

The sealed leaf has a short form for a timestamp in nanoseconds. Any other
unit is sealed in a longer envelope of a different length. Every value stored
through the engine is in nanoseconds, because the engine rewrites it.

Move the rule into the AEAD crates, so that no caller can seal another unit
by accident, and change the JavaScript bridge to write a `Date` in
nanoseconds. Then delete the engine's rewrite.

If this were skipped, a JavaScript `Date` would seal to a different length
from the same instant written by Go or Rust, and from its own sealed null.

### 2.2 One description of a type, with its name

Add one type to the AEAD crates that describes a value's type without a
value, and that has a text name. It replaces `ValueKind`. The names are a
wire format: plans, error payloads, the Go module, EQL's generated code and
the conformance corpus all use them, so they do not change.

`scalar_kind`, `scalar_of` and `sealed_null` become methods of that type, or
are deleted.

vitaminc has no such type today. `Kind`, `Width`, `KnownLogical` and
`FixedType` each cover part of it, and its only text names include a
parameter (`timestamp(ms)`, `decimal(2)`).

### 2.3 Each index says which types it takes

Delete the allow-list. An index refuses a type it cannot handle:

- **Equality:** already asks `vitaminc-normalize`.
- **Order:** `vitaminc-ore` already refuses a boolean and an 8-bit integer.
  The engine also refuses bytes and a UUID, which `vitaminc-ore` allows.
  Decide whether that stays, and put it in one place.
- **Match:** text only.

A plan is refused when it is built, before a value arrives. The index answers
that for a type from 2.2, with no sample value.

### 2.4 The AEAD crates provide the owned value

Add to the AEAD crates an owned, wiped frame that can be encrypted, that a
ciphertext opens into, and that compares in constant time. Delete
`ValueFrame`, `Modeled`, `Opening`, `Children` and `FromFrameError`.

This is the widest step. `ValueFrame` is named in about 50 files of
`stack-encrypt`, 23 of EQL, and both SDK guests. It is in the public API of
`eql-bindings`, which is published, so this is a breaking release of that
crate.

### 2.5 The bridges and the SDKs

- **TypeScript:** the addon hands the bridge's frame to the engine with no
  second copy. `OneValue`, `is_uuid`, and the `recipher_js::uuid` code are
  deleted.
- **Go:** the guest stops calling `ValueFrame::from_bytes` and
  `ValueFrame::check`.
- **EQL:** the `Plaintext` trait and the generated code use the type from
  2.2.

A UUID then works in every SDK, which closes #1821.

## What waits on this plan

- The TypeScript SDK: #1775, #1776 and the prototype #1829.
- `ScalarFrame` (#1825, draft #1827). It wraps `ValueFrame`, so step 2.4
  replaces it.
- The language integration guide's new sections on the value model (#1828).
  They describe the model this plan removes.
- The UUID fix (#1821).

## Checks that must move with the code

vitaminc runs checks that this repository does not. Each needs a home in this
repository's CI before its code moves:

- Kani proofs, including `kani-storage`;
- sanitizers;
- the storage corpus append-only check;
- `cargo vet` and `cargo deny`;
- the fuzz targets of the moved crates;
- Miri for the moved crates;
- mutation testing. `stack-encrypt` already has it, with `--in-diff`.

## Open questions

1. **Who converts a value to its declared type on a write?** Today Go
   converts on the host, the engine refuses a mismatch, and the JavaScript
   bridge cannot know the width of a `bigint`. Either the AEAD crates convert
   a value to a declared type when the conversion is exact, as the engine
   already does for a query, or every bridge is told the declared type. The
   first keeps a bridge free of types. It also changes a rule the conformance
   corpus pins: a value of another width is refused on a write.
2. **Is a host's typed null kept?** The frame writer drops the type, and a
   plan's `"null": "sealed"` adds the padding back from the declared type.
   Once the declared type is an AEAD type, the two overlap.
3. **Where do `json`, `array` and `object` live?** They are `ValueKind`
   variants and not scalar types. No index takes an array or an object, and
   Go has no constant for either.
4. **Is `undefined` a null to a typed field?** The engine accepts it, gives
   it no type, and does not treat it as a null. No test covers it against a
   nullable field.
5. **Does the order index take bytes and a UUID?** See 2.3.
6. **Do Go's `vcffi` and `vcvalue` move?** They are vitaminc's Go packages,
   with their own encoder, pinned at an unreleased commit. The Go release
   script refuses a final version while that pin is there. They are a bridge,
   so the consolidation applies to them, but they are not Rust crates.
7. **Which licence applies to the moved code?** vitaminc uses the MIT
   licence. Ask the person responsible for licensing.
8. **Does anyone outside CipherStash use the moved crates?** They are on
   crates.io. Nobody has checked.
9. **What is a frame called?** "Frame" does not say whether it is a transport
   or a storage format. Rename it during stage 2, where the type is already
   being replaced.

## Rules this changes

- "A fix always belongs in vitaminc." A fix to the AEAD crates belongs here.
- `AGENTS.md` describes vitaminc as a dependency from crates.io. Update it in
  the stage that changes that.
