---
status: accepted
date: 2026-10-08
relates-to: ADR-0001; stack-encrypt ADR-0003, ADR-0007
---

# One value model, three encodings in vitaminc, and EQL v4 separated by producer

Every value Stack Encrypt handles is encoded three times: as a **ciphertext**
(reversible and self-describing), as an **equality term** (a keyed hash that
must be unambiguous) and as an **order term** (bytes whose order is the
value's order). This ADR decides where each encoding lives, which kinds of
value exist, the canonical form each kind takes, and how EQL keeps columns
written by Stack Encrypt apart from columns written by cipherstash-client.

## The problem

In October 2026 Stack Encrypt could produce one of EQL's 51 types, `TextEq`.
The number, date, timestamp and boolean families were blocked on encoding,
not code:

- **The three encodings disagreed about which types exist.** `i16` had an
  equality domain in `vitaminc-prf` and an order encoding, but no ciphertext
  tag, so it could not be a kind. Date, timestamp and decimal had order
  encodings only.
- **The mapping from a kind to a Rust type lived in Stack Encrypt.**
  `dynamic::term::Scalar` mirrored `FfiValue`'s variants one for one to
  dispatch to the term crates, and `dynamic::Value` wrapped `FfiValue` only to
  add `Clone`. Both restated vitaminc's vocabulary in a downstream crate.
- **Ordering was implemented twice.** `orderable-bytes` defines a canonical,
  order-preserving encoding per type. cllw-ore uses it for chrono and decimal
  but hand-rolls integers and floats, and differs on `-0.0`. Block ORE was not
  derivable at all, so `TextOrdOre` and `TextSearchOre` were refused.
- **The existing writer's encodings are inconsistent.** cipherstash-client
  hashes a timestamp's milliseconds but orders by its nanoseconds, and hashes
  a decimal with its scale while ordering ignores it. Its block ORE text is
  ASCII-only, lowercased, maps every digit to one symbol and truncates to six
  blocks. cllw-ore's text decomposes to NFD and strips accents.
- **Two producers wrote the same EQL domains.** A Stack Encrypt query term
  never matches a cipherstash-client term for the same value, and the
  `eql_v3_*` domains could not tell them apart. A query from one against a
  column written by the other returned no rows, silently.

## Options considered

**Where the value model lives.**

1. **Move `vitaminc-aead-value` into Stack Encrypt.** It looks like FFI
   plumbing. But it is the value model for vitaminc's own `Cipher` traits:
   `aead-napi` and vitaminc's Go binding encrypt with `Aes256Cipher` through
   it, without Stack Encrypt. Moving it makes vitaminc Rust-only, makes
   vitaminc depend on Stack Encrypt (which depends on six vitaminc crates),
   or forks the frozen tag table into two copies.
2. **Keep it in vitaminc, and move term derivation there too.** All three
   encodings then live in one repository, and one exhaustive `match` on the
   value type per layer makes "a kind exists in every layer or in none" a
   compile error rather than a convention. Chosen.

**How EQL separates the two producers.** The SQL for both is identical; only
the producer of the terms differs.

1. **Name only.** Stack Encrypt payloads go in the `eql_v3_*` domains,
   distinguished by the `stack-encrypt:1:` ciphertext prefix. Nothing in the
   database stops a cross-producer comparison.
2. **A producer tag in every payload and term, checked by every operator.**
   A runtime check on the hottest SQL paths, across about 24k lines of
   hand-written SQL.
3. **One SQL source, emitted under two names.** The build writes the same
   source out as `eql_v3` (cipherstash-client terms) and `eql_v4` (Stack
   Encrypt terms). A column's domain names its producer, and Postgres refuses
   to compare an `eql_v4_*` query term with an `eql_v3_*` column at plan time.
   Chosen.

**How v3 and v4 ship.** Bumping `main` to v4 and patching v3 from a branch
needs a maintenance release path for five lockstep artefacts that does not
exist, and the EQL publish script puts every stable release on `latest`, so a
3.x patch would move `latest` backwards. A second package doubles the
trusted-publishing and release surface. One package carrying both bundles
needs neither. Chosen.

## Decision

### Kinds and the ciphertext

- vitaminc 0.6.0 adds the kinds `Int8`, `UInt8`, `Int16`, `UInt16`, `Int128`,
  `UInt128`, `Date`, `Timestamp` and `Decimal`, each with a `ValueKind` name,
  a `Value` variant and a ciphertext tag, in one breaking release. Rust `i128`
  and `u128` get `Encrypt` and `Decrypt` impls.
- `FfiValue` is renamed `Value`, with `#[deprecated] pub type FfiValue = Value`
  for one release. `Value` and `ValueKind` become `#[non_exhaustive]`, so later
  kinds are additive.
- `Value` implements `Clone` as a deep copy that rebuilds every leaf into a
  fresh `Protected`. A clone is under the same custody as its original.
- The sealed leaf tag table (`tags.rs`) stays frozen and contiguous. The
  transport codec's framing tags move from `0x10`–`0x12` to `0xF0`–`0xF2`;
  transport carries no compatibility commitment and every user of it updates
  together. The new leaves:

  | Tag | Kind | Payload |
  |---|---|---|
  | `0x0C`–`0x11` | `Int8`, `UInt8`, `Int16`, `UInt16`, `Int128`, `UInt128` | 1, 1, 2, 2, 16, 16 bytes; two's complement for signed; little-endian |
  | `0x12` | `Date` | `i32` days counted from 0001-01-01 (`num_days_from_ce`), little-endian |
  | `0x13` | `Timestamp` | `i64` Unix seconds then `u32` nanoseconds, little-endian, UTC |
  | `0x14` | `Decimal` | rust_decimal's 16-byte `serialize()`, which keeps the scale |

- `transport` stays a module of `vitaminc-aead-value`.

### Canonical forms

The ciphertext keeps the value exactly as given: `1.50` decrypts as `1.50`,
and a timestamp keeps its nanoseconds. Equality and order terms are computed
from one canonical form per kind, and both layers use the same one, so
equality and ordering agree by construction.

| Kind | Canonical form for terms |
|---|---|
| `Timestamp` | truncated to microseconds, Postgres's precision |
| `Decimal` | scale normalised (`1`, `1.0` and `1.00` are equal). NaN and ±Infinity are refused at encode time; rust_decimal cannot represent them |
| `Float32`, `Float64` | `-0.0` folded into `+0.0`; every NaN replaced by one positive quiet NaN, which sorts above +Infinity. This matches Postgres |
| text, equality | NFC |
| text, order | NFC, then NFD, combining marks removed, Unicode default case folding |

Text normalisation is pinned. The Unicode version is part of the encoding's
domain label (for example `text-nfc/unicode-16/v1`), the
`unicode-normalization` crate is pinned to it, and strings containing
unassigned code points are refused. Order terms fold accent and case because
code-point order puts `é` after `z`; a fixed, pinned fold approximates the
first level of Unicode collation without depending on ICU, whose sort keys
change between versions. Equality is not folded: a folded order term only
produces ties, while a folded equality term produces false matches. A
case-insensitive equality is its own domain.

Truncation and alphabet packing are settings of an EQL domain, named in its
label, never part of the shared encoding.

### Which kinds get which terms

- **Every scalar kind has a ciphertext.** Containers and null have no terms.
- **Equality:** every scalar kind except `Bool`, including floats over their
  canonical bits.
- **Order:** every scalar kind except `Bool`, under all three schemes.
- **`Bool` has a ciphertext only.** A keyed hash or an order term over a
  domain of two values hides nothing: it splits the rows into two groups, and
  an order term also says which group is `true`. The existing CLLW order terms
  for `Bool` are removed.

These exceptions are an explicit, documented list kept next to vitaminc's
conformance test, which fails for any kind that is missing from a layer
without an entry.

### Where each encoding lives

- **Ciphertext:** `vitaminc-aead-value`.
- **Equality:** `vitaminc-prf`, which gains domains for every new kind, floats
  and `Decimal`, over the canonical bytes.
- **Order:** a new `vitaminc-ore` crate.
  - The plaintext layer is `orderable-bytes`, which stays its own crate in
    ore.rs and gains a variable-length encoding for text and bytes. Its
    existing fixed-length output does not change.
  - A `Scheme` trait, with block ORE (over ore-rs), CLLW ORE and CLLW OPE
    (over cllw-ore). A scheme only encrypts the bytes the plaintext layer
    produces, so every orderable kind works under every scheme.
  - Block ORE uses each kind's natural width. The 8-byte padding is a
    cipherstash-client detail kept for its stored terms.
  - cllw-ore keeps its typed impls, unchanged, behind a cargo feature that
    cipherstash-client enables, and gains a bytes-level entry point that
    `vitaminc-ore` calls.
- **Term derivation** takes a `&Value` in `vitaminc-prf` and `vitaminc-ore`,
  with one exhaustive match per layer that keeps leaves inside `Protected`. A
  pairing a layer does not support returns a typed error from vitaminc.

### Stack Encrypt

- `dynamic::Value` and `dynamic::term::Scalar` are deleted. `dynamic::term`
  takes a `&vitaminc_aead_value::Value`. `admits` keeps only the rules that
  belong to Stack Encrypt, such as `Match` taking text only.
- Order terms go through `vitaminc-ore`, and a block ORE term kind joins CLLW
  ORE and OPE. Stack Encrypt no longer depends on cllw-ore directly.
- `TextEq` normalises to NFC and moves to EQL v4. The Stack Encrypt targets on
  `eql_v3_*` domains are deleted. The `stack-encrypt:1:` ciphertext prefix
  stays: decryption does not pass through Postgres types, and the prefix is
  what lets it reject the other producer's payload.

### Host languages

- **Go.** `int8`, `int16`, `uint8` and `uint16` map to their own kinds instead
  of widening to 32 bits; this lands before the Go SDK ships, so no stored
  data uses the old mapping. `Int128` and `Uint128` are SDK value types.
  `time.Time` means `Timestamp`, and `encrypt.Date{Year, Month, Day}` is a
  date. A field whose EQL target is a date family accepts `time.Time`,
  truncated to its UTC calendar day.
- **JavaScript.** A `BigInt` maps to the smallest kind that holds it, up to
  128 bits, and decodes as a `BigInt`. `Date` means `Timestamp`; a date has
  its own wrapper.
- **Every binding** runs vitaminc's shared test vectors: a host value, the
  kind it must map to, and the exact `[tag] ++ payload` leaf bytes, including
  normalisation cases. The leaf is deterministic even though the AEAD is not.

### EQL v4

- **v4 is the v3 SQL with Stack Encrypt terms.** One SQL source is emitted
  under two names. The hand-written SQL takes the schema as a build-time
  placeholder, as eql-codegen's templates already do. Consistent with
  ADR-0001, the data-bearing domains (`eql_v3_*`, `eql_v4_*`) live in
  `public` and survive reinstall, and the implementation schemas
  (`eql_v3`, `eql_v4` and their `_internal` schemas) stay disposable. The
  second name separates producers; it is not a versioned upgrade mechanism of
  the kind ADR-0001 rejects.
- **A v4 payload's envelope carries `"v": 4`**, and the `eql_v4_*` domains'
  check constraints test it, as the `eql_v3_*` ones test `3`. The version is
  one more build-time placeholder. A payload written to the other producer's
  domain then fails on insert, rather than only matching nothing when it is
  queried.
- **New EQL targets are v4-only.** In v3 they stay refused, with a reason
  that points to v4.
- **`@cipherstash/eql` 4.x ships both bundles** from `main`. A SQL fix lands in
  both names in one release.
- **`stash eql install --eql-version 3|4|all`** chooses the bundle and defaults
  to 3, which is today's behaviour. The default changes to 4, announced in
  advance, when the TypeScript stack has moved to Stack Encrypt.
- **During the overlap**, expected to last a quarter or more, cipherstash-client
  takes fixes only. New kinds and domains are produced through Stack Encrypt
  and v4. An exception is a decision written down in its issue.

### Review

Using the canonical order bytes as the PRF input is the simplest way to make
equality and ordering agree, and it is frozen once data is stored under it.
Dan Draper signs it off in writing before the `vitaminc-prf` change lands.

## Consequences

- **The release order is fixed.** ore.rs (`orderable-bytes`) and cllw-ore
  first, then vitaminc 0.6.0, then the Stack Encrypt breaking release. Stack
  Encrypt must reach crates.io before `eql-bindings` uses its new API, since
  `cargo publish` builds `eql-bindings` against the registry. The EQL v4
  bundle and the Go SDK changes follow.
- **Adding a kind later is additive**, because `Value` and `ValueKind` are
  `#[non_exhaustive]`. It still takes a tag, a PRF domain, an order encoding,
  a codec in every binding, and test vectors, or an entry in the exceptions
  list.
- **Stack Encrypt's terms change** for `-0.0` and negative-sign NaN floats,
  for non-NFC text equality, and for `Bool` order terms, which are removed.
  None is deployed, so the breaking release carries them without migration.
- **cipherstash-client's terms do not change.** Its fixed-length
  `orderable-bytes` output, cllw-ore's typed impls and its block ORE padding
  are all kept, so every stored v3 payload stays queryable.
- **Moving a column from v3 to v4 means re-encrypting it.** The ciphertext and
  every term change. How that migration runs belongs to the decision that
  moves the TypeScript stack onto Stack Encrypt.
- **The CLI surface changes** (`--eql-version`), so `skills/stash-cli`,
  `skills/stash-indexing` and `skills/stash-postgres` change in the same PR.
- **This replaces a definition in a plan.** `docs/plans/2026-10-04-plan-builder.md`
  calls "EQL v4" a name for a Stack Encrypt payload in the v3 envelope and
  the `eql_v3_*` domains. That plan is updated to this ADR.

## Deferred

- **Block ORE for text** waits for ore-rs's chained, variable-length block ORE
  to be reviewed and released, then arrives in a minor release of
  `vitaminc-ore`. Until then it is an entry in the exceptions list.
- **Block ORE for `Bool`.** Block ORE stored as right ciphertexts only is
  fully randomised and semantically secure, so a two-value domain leaks
  nothing through it. `Bool` could support that scheme alone, enforced by a
  marker trait on schemes. Not built until needed.
- **Locale-aware collation**, as its own domain with the collation version in
  its name.
- **ASCII-packed text domains**, until a customer's column sizes make the
  case.
