# Move vitaminc's AEAD crates into the stack, and define the value types once

Status: draft, rewritten 26 November 2026. Decisions by Dan Draper:

- Move the AEAD crates into this repository as crates. Do not fold them into
  modules of `stack-encrypt`.
- Work in two stages: move first with no change in behaviour, then
  consolidate.
- Keep the move as small as possible. `vitaminc-protected` and
  `vitaminc-random` never move.
- No more work on the TypeScript SDK until this is done.
- vitaminc's Go packages `vcffi` and `vcvalue` move too, as a third stage,
  before the Go SDK's final release. vitaminc's `vcencrypt` is deleted.
- An order index takes no bytes and no UUID. If `vitaminc-ore` ever moves
  into this repository, its UUID order target (behind its `uuid` feature) and
  its bytes order target are removed. Until then, the engine refuses both in
  stage 2.3.
- `vitaminc-aead` describes the complete data model, `json` included.
  `ValueKind` moves there with its name, and `stack-encrypt` re-exports it
  from the same path. The engine adds no wrapper type. JSON stays a kind a
  field declares, not a logical type: no frame or stored byte marks a value
  as JSON.
- Fixtures follow the rule in `packages/stack-encrypt/tests/fixtures/README.md`
  and `packages/eql/tests/encryption/fixtures/README.md`: every fixture is
  Biome-formatted, you run `pnpm run code:fix` after regenerating one, and
  each test compares its fixture as parsed JSON.
- The moved code keeps the MIT licence, which is this repository's licence.
- Nobody outside CipherStash uses the moved crates.

The first draft of this plan (14 November) moved nine crates, with `ore.rs`,
into `stack-encrypt` as modules. This draft replaces it.

AEAD means authenticated encryption with associated data. The AEAD crates
define the value types, how each is encoded, and how a value is sealed.

## Summary

Three crates move from `cipherstash/vitaminc` into this repository:
`vitaminc-aead`, `vitaminc-aead-frame` and `vitaminc-aead-derive`. They are
published from here. `vitaminc-aead` and `vitaminc-aead-derive` keep their
names. The frame crate is renamed `recipher-frame` in step 2.4.

vitaminc's two Go packages, `vcffi` and `vcvalue`, move into the Go module in
a third stage.

The value handling is consolidated in stage 2. Today the list of value types is
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
| `vitaminc-aead-frame` (`recipher-frame` from step 2.4) | The frame encoding a binding sends |
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

- **`vitaminc-aead` and `vitaminc-aead-derive` keep their names.** Under a
  new name, Cargo would build two crates with two sets of types, and the
  engine's calls into the four would not compile. The frame crate is not
  bound this way: none of the four depends on it, and only `stack-encrypt`
  and `stack-guest-abi` do, both by path. So it could be renamed without
  breaking anything outside this repository, and step 2.4 renames it
  `recipher-frame`.
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
   Keep their names. Bring their git history, as was done for the stack-*
   crates.
2. Bring their tests, fuzz targets and benchmarks, and the checks under
   "Checks that must move with the code".
3. Point every workspace at them. Each resolves vitaminc on its own today:
   - the root workspace, where `stack-encrypt` and `stack-guest-abi` name
     the crates, and where the `vitaminc` umbrella crate depends on
     `vitaminc-aead`;
   - the TypeScript SDK's workspace, and the bridge's test addon, which is a
     workspace of its own;
   - the two Go guests;
   - EQL's workspace, for its encryption test crate;
   - the detached fuzz crate `packages/stack-encrypt/fuzz`.
4. Do not publish them yet. In each workspace, a `[patch.crates-io]` table
   makes the four crates from crates.io resolve the in-repository
   `vitaminc-aead`. That works while its version stays on the 0.10 line.
5. Move the open vitaminc issues about this code with it: vitaminc #643,
   #473 and #632.

This stage changes no behaviour. The copied source can be compared with the
published crates file by file.

While the crates are unpublished:

- **A release from this repository builds against crates.io's copy.**
  `cargo publish` drops `[patch]` tables, so a published `stack-encrypt`,
  `stack-kms` or `stack-auth` depends on crates.io's `vitaminc-aead` 0.10.x,
  not on the copy here. A release that needs a change made in the copies
  waits until the copies are published (see "Before the next
  `stack-encrypt` release").
- **The Go and TypeScript SDKs are not affected.** Both build the engine by
  path from the tree.
- **`eql-bindings` can be published until step 2.4.** Its `stack-encrypt`
  feature is compiled against the `stack-encrypt` on crates.io when it is
  published. Stage 1 changes no API, so that still compiles. Step 2.4 changes
  the API that `eql-bindings` uses, and from then an EQL release waits for a
  `stack-encrypt` release.
- **vitaminc stops changing these three crates as soon as the copy is
  taken**, or the two copies diverge. The crates stay in vitaminc, unchanged,
  until everything in this plan is settled, so that the move can be backed
  out. They are deleted from vitaminc only then.

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

Move `ValueKind` into the AEAD crates, keeping its name, and have
`stack-encrypt` re-export it from the same path. It describes a value's type
without a value, and has a text name. The names are a wire format: plans,
error payloads, the Go module, EQL's generated code and the conformance
corpus all use them, so they do not change.

`scalar_kind`, `scalar_of` and `sealed_null` become methods of that type, or
are deleted.

The type covers every scalar, an array and an object, which are shapes of
the AEAD encoding, and `json`. A JSON value is carried as UTF-8 JSON text in
a text or bytes leaf, so a value read from a frame is `string` or `bytes`.
`json` is a kind a field declares: it tells the engine to treat the text as
a JSON document, and the JSON index parses it. Nothing on the wire marks a
value as JSON.

The type also gives the width a sealed null is padded to. A field's declared
type is the only thing that decides that width. A host can send a null with
a type of its own, and the frame writer drops that type, as it does today.
If the host's type counted, it could disagree with the declaration, and a
null padded to the wrong length would show that it is a null.

vitaminc has no such type today. `Kind`, `Width`, `KnownLogical` and
`FixedType` each cover part of it, and its only text names include a
parameter (`timestamp(ms)`, `decimal(2)`).

### 2.3 Each index says which types it takes

Delete the allow-list. An index refuses a type it cannot handle:

- **Equality:** already asks `vitaminc-normalize`.
- **Order:** no boolean, no 8-bit integer, no bytes and no UUID.
  `vitaminc-ore` already refuses the first two. It allows bytes, and a UUID
  behind its `uuid` feature, so the engine's order index refuses those, in
  one place. Nothing in this repository turns on `vitaminc-ore`'s `uuid`
  feature, and `stack-encrypt` names no bytes order target.
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

Done in #1955:

- The frame crate is renamed `recipher-frame` first, in a commit of its own.
  No workspace patches crates.io for it any more.
- Most uses need no owned value. A value read only within a call is a
  `Frame` borrowed from its bytes: `Frame::parse` checks everything the old
  `from_bytes` checked, and `Frame` is `Encrypt`. `kind`, `is_null`,
  `has_passthrough` and `elements` are on `Frame`, and `elements` lends
  each element as a `Frame` with no copy. The engine's readers, the
  `TargetResolver`'s `encrypt` and `query`, and the `eql-bindings` by-name
  entry points and generated dispatch take a `Frame<'_>`. `FieldHandle` and
  `DynamicQuery` take any source, and `Planned` is a target over an
  `OwnedFrame` or a `Frame`.
- The owned value is `vitaminc_aead::frame::OwnedFrame`, re-exported by
  `recipher-frame` and so by `stack_encrypt::dynamic::frame`: a newtype
  over a `Buffer` that `Frame::parse` accepted, with `of`, `from_buffer`,
  `null`, `typed_null`, `frame` and `into_buffer`. It is `Encrypt`,
  `Decrypt` and `Zeroize`, and has no `==`: two frames compare through
  `Frame`'s constant-time `==`. Two places need it: a record's field slots
  (`plan/values.rs`), which hold an owned value, and the TypeScript addon's
  async calls. It is not a `Buffer` with `Encrypt` added, because
  `Protected<Vec<u8>>` already encrypts as a bytes scalar.
- The decrypt sink writes the opened value into one buffer: the frame
  writer is generic over a borrowed or an owned buffer and over the error
  it reports, so a container's children are written in place, with no
  copy per child.
- A zeroized `OwnedFrame` holds the plain null, so it is always one frame
  and `frame()` cannot fail.
- `Planned` is `Zeroize` only for an `OwnedFrame`, which it wipes, and a
  `Frame`, whose owner wipes it. `Frame` does not implement `Zeroize`:
  wiping a view would wipe nothing, and `EncryptTarget`'s `Zeroize` bound
  is on the `Planned`, not on the value.
- The Go guest reads every plaintext input with `Frame::parse` on the
  host's bytes, the page of values to verify included, and the TypeScript
  addon keeps the bridge's buffer with `OwnedFrame::from_buffer`: one copy
  fewer at each boundary.
- In `eql-bindings`, a plaintext that may be absent reads any null, plain
  or typed, as `None`, and seals it padded to its own type.
- `ValueFrame::check` is not replaced: a caller checks a record source with
  `Frame::parse`. `FromFrameError` is replaced by `FrameError`.
- What stays in the engine is engine logic, not a wrapper: reading a text
  frame as a context label (`IntoLabel`, the engine's trait) and splitting a
  record source into one frame per field (`dynamic::source`). The split
  writes with vitaminc's `FrameWriter` and names the field a refusal came
  from itself.
- The `eql-bindings` API that took `ValueFrame` was not released yet, so its
  breaking change is in an unreleased changelog entry.

### 2.5 One place converts a value to its declared type

Today Go converts a value to the field's type on the host, the engine
refuses a write whose width differs from the declared type, and the engine
converts a query's value when the conversion is exact. A JavaScript `bigint`
has no width, so the bridge writes the narrowest one that fits, and a
JavaScript user cannot write `34n` to an `int64` field.

The exact conversion the engine uses for a query also runs on a write, in
one place. A bridge is never told the declared type. The conversion is never
lossy, never between a number and a value that is not a number, and never
from a float to a decimal. The value is sealed at the declared width, so no
stored bytes change. The conformance cases that pin today's refusal change
from refused to accepted.

A typed field takes a value of its type or a null, and nothing else.
JavaScript's `undefined` is refused with an error of its own, and a
conformance case pins that. Today it is refused only because it has no type,
with a general error, and no test covers it. Storing it as a null would hide
a misspelt property name. Inside an untyped value, `undefined` is kept as it
is today.

Done (#1990):

- `dynamic::read` and the write path share one function, `kind::convert`.
  It takes a `Frame` and returns `None` when the value is already of the
  kind, so a value that needs no conversion is not copied. `read` is
  `convert` over any source.
- The write path converts in `check_field`, which now takes the field's
  `OwnedFrame` and returns the value the field stores: the one it came as,
  or the converted one, with the other wiped. `source_rows` calls it for
  each field, so `record::encrypt`, `encrypt_with`, `check_source` and
  `Planned` all convert, and `check_source` and `encrypt` still share the
  code. A target field's `record::query` calls it too.
- The rule for containers: the value is read as a whole. A scalar converts
  to a scalar kind. An `array` or `object` field takes a container as it
  is, and nothing inside one converts, since the field declares no type for
  its elements. A `json` field takes its text or bytes as they are.
- `undefined` is refused in `convert` with the new `Reason::Undefined`
  (`"undefined"`), on a write and on a query, whatever the field's null
  policy. In an untyped field, or inside a container, it is kept.
- No stored bytes moved. `value_bytes_v1.json` pinned two of the changed
  refusals; its `float64_for_float32` case now seals the same leaf as the
  `float32` 1.5, and the test asserts that, and `undefined_for_string` now
  reports `undefined`.
- Conformance: five `record-values-v1` cases (an `int16` for `int8`, an
  `int8` for `uint8`, an `int64` for `int128`, a `uint64` for `uint128`, a
  `float64` 1.5 for `float32`) changed from refused to accepted, with a new
  `stored` key naming the converted value. The runners seal it as a second
  row and compare terms, ciphertext length and the opened value. Three
  `record-runtime-v1` "wrong width" cases became `*-other-width` and are
  accepted; `required-integral-float` and `required-fractional-float`
  were added. A new `int32-given-undefined` case pins the refusal. Go has
  no `undefined`, so its runner skips that case.
- Go needed no change to its reason handling: `Diagnostic.Reason()`
  passes the engine's reason through, and no Go code lists the reasons.
  `Cipher.Seal` now takes a number of another width for a typed field, so
  the Go changelog says so. The Go guest's own test of a refused float now
  uses a fraction.
- The TypeScript addon needs no change: it hands the bridge's frame to the
  engine, which converts. `value-napi`'s README says a typed field reads
  `5` and `5n` alike and refuses `undefined`.

### 2.6 The bridges and the SDKs

- **TypeScript:** `OneValue`, `is_uuid`, and the `recipher_js::uuid` code
  are deleted. (Step 2.4 already hands the bridge's buffer to the engine
  with no second copy.)
- **Go:** the guest stops calling `Frame::parse` itself. (Step 2.4 already
  removed its `OwnedFrame::from_bytes` call.)
- **EQL:** the `Plaintext` trait and the generated code use the type from
  2.2.

A UUID then works in every SDK, which closes #1821.

Done (#1992):

- **TypeScript:** nothing removed on `next`. `is_uuid` and the
  `recipher_js::uuid` code are only on the values and records branches
  (#1775, #1776), and are removed there when they rebase. `OneValue` stays
  on `next`: the addon's `keyset.encrypt` takes a string only, through the
  engine's opaque scalar path, and that path needs a `Scalar`. An
  `OwnedFrame` is not one, because it can hold an array.
- **Go:** the guest keeps its `Frame::parse`. It is not a second check:
  the engine's readers take a `Frame`, and `Frame::parse` is the only way
  to make one from the host's bytes. It also gives the Go SDK its "not a
  frame" error before any key request. The two identical helpers are now
  one, `parse_frame`, with a comment that says why.
- **EQL:** `Target::plaintext` is an `Option<ValueKind>`, and
  `plaintext_kind` is gone. `eql-codegen`'s `plaintext_of` returns a
  `ValueKind`, the generated table writes `ValueKind::Int32` and so on, and
  the Go table writes `ValueKind::name`. The `Plaintext` trait already used
  `ValueKind`. The wire format and the Go file did not change.
- **UUID:** Rust stores, queries by equality and reads a `uuid` field
  (`dynamic::record`'s tests). The Go guest does too, through its record
  and query exports (a new guest test). The Go SDK's `gensupport` takes a
  UUID, but `stashgen` maps no Go type to the `uuid` kind, so generated
  code cannot declare one yet. The TypeScript addon on `next` encrypts a
  string only, so it cannot store a UUID. The values and records branches
  still refuse a `VcUuid` with `recipher_js::uuid`, and test that refusal;
  once they drop it, they need a test that stores, queries and reads one.
  So #1821 stays open for `stashgen` and the addon.
- No stored bytes changed: the pinned fixtures and conformance cases pass
  unchanged.

## Stage 3: move the Go packages

vitaminc has two Go packages that the Go module imports in about 60 places:

| Package | What it is |
|---|---|
| `vcvalue` | The Go value types: `Date`, `Decimal`, `Int128`, `Uint128`, `Timestamp`, `UUID`, `TypedNull`, `Plain`, `Object`. No dependencies. |
| `vcffi` | The frame codec in Go: frames, ciphertext trees and the storage profile (`MarshalStorage`). |

They do not link the Rust crates. The Go host encodes a frame and the guest
decodes it, so the two share a byte format and no code. That is why this
stage does not have to run with stage 1. It starts after stage 1 and can run
beside stage 2.

It must finish before the Go SDK's final release:

- **The types are in the SDK's public API.** `encrypt.Date`,
  `encrypt.Decimal`, `encrypt.Int128` and `encrypt.Uint128` are aliases of
  `vcvalue` types. Moving a type changes its package path, which breaks a
  user's code after a release.
- **The release is blocked on them.** The packages have no tags, so `go.mod`
  pins an unreleased commit, and `scripts/go-release-version.mjs` refuses a
  final version while that pin is there.
- **The codec's test data moves in stage 1.** `vcffi`'s tests read the
  storage corpus that sits beside `recipher-frame` (`vitaminc-aead-frame`
  until step 2.4).

The work:

1. Move both packages into `languages/golang`, with their tests and fuzz
   targets. Decide where each type is declared: the value types are public,
   and the codec need not be.
2. Update the imports. Remove the pin from `languages/golang/go.mod` and
   from the two nested modules that carry it.
3. Remove the matching refusal from `scripts/go-release-version.mjs`.
4. Apply stage 2 to them. `vcvalue.FixedType` is one more copy of the type
   list.
5. Delete `vcencrypt` and its guest from vitaminc. It was a demonstration of
   the approach, and the Go module replaces it.

### Done

Items 1 to 4 are done, on the branch `refactor/go-frame-codec-in-module`:

- The two packages are now one internal package,
  `languages/golang/internal/frame`. The package has the codec, the storage
  profile, and the value model. All three were copied from vitaminc commit
  `f1fc9ae74`, with their tests and fuzz targets. The tests read the value
  corpus (`conformance/vitaminc-aead`) and the storage corpus
  (`packages/recipher-frame/testdata`) from this repository.
- `encrypt.Date`, `Decimal`, `Int128`, and `Uint128` are now types of
  package `encrypt`. `encrypt.UUID`, `Encryptable`, and `Encoder` are new.
  Each value type has the same underlying type as the matching type of the
  codec. `frame.Publish` registers each pair with the codec. The codec then
  encodes the `encrypt` type, and decodes to it.
- The sealed leaf family, `VCValueLeaves`, `TypedNull`, `FixedWidth`, and
  `FixedType` are removed. The typed null for a nil pointer is built from
  the tag table, so the codec has no list of types. `record.Kind` is the
  only list of type names.
- No `go.mod` names a vitaminc module: not the one of the module, and not
  those of its two nested modules. `scripts/go-release-version.mjs` no
  longer refuses a final version because of a vitaminc pin.
- The Go campaign in `fuzz.yml` fuzzes the three decoders every night.

Two things are still to do:

- Item 5, in vitaminc.
- The differential fuzzers that compared the Go codec with a Rust guest, in
  vitaminc's `vcencrypt`. Those fuzzers could run against
  `languages/golang/encrypt/guest`.

## What waits on this plan

- The TypeScript SDK: #1775, #1776 and the prototype #1829.
- `ScalarFrame` (#1825, draft #1827). It wraps `ValueFrame`, which step 2.4
  replaced with `OwnedFrame`.
- The language integration guide's new sections on the value model (#1828).
  They describe the model this plan removes.
- The UUID fix (#1821).
- The Go SDK's final release, on stage 3.

## Checks that must move with the code

Every check vitaminc ran on these crates runs here, or does not apply:

| vitaminc check | Here |
|---|---|
| Storage corpus append-only | `storage-corpus.yml`, on a pull request that changes the corpus or the script. |
| `kani-storage` (the storage reader's proofs) | `kani.yml`: on a pull request that changes the reader or its proofs, and nightly when anything it compiles from changed in the last day. About ten minutes. |
| `kani` | Not here: it proves `vitaminc-protected`, which stays in vitaminc. |
| `cargo deny` | `supply-chain-vitaminc-aead.yml`, per pull request and nightly, over the three crates' graph only (`supply-chain/vitaminc-aead/deny.toml`). |
| `cargo vet` | The same workflow, per pull request, with a store started from vitaminc's (`supply-chain/vitaminc-aead/`), over the three crates' graph only. |
| Mutation testing | `mutants.yml`, `--in-diff`, as for `stack-encrypt`. |
| Per-feature tests, and the release-only jiff tests | `test:vitaminc-aead:features`, in `tests-crates.yml`. |
| Miri, sanitizers | Not needed. vitaminc ran them on `vitaminc-protected` only, and the three crates `#![deny(unsafe_code)]`. A change that adds `unsafe` adds both. |
| Fuzzing | vitaminc's targets are Go, over `vcffi`, and move with it in stage 3. stack-encrypt's targets reach parts of the crates and replay when they change. |

`cargo deny` and `cargo vet` over the rest of the root workspace are #1842.

Pull requests may change the three crates.

## Open questions

1. **What is a frame called?** Resolved in step 2.4: "frame" stays the
   name of the encoding, and the crate that holds its codec is
   `recipher-frame`. The owned value is `OwnedFrame`.

## Rules this changes

- "A fix always belongs in vitaminc." A fix to the AEAD crates belongs here.
- `AGENTS.md` describes vitaminc as a dependency from crates.io. Update it in
  the stage that changes that.
