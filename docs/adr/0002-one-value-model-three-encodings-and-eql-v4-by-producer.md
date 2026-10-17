---
status: accepted
date: 2026-10-08
revised: 2026-10-12, amended 2026-10-17
relates-to: ADR-0001; stack-encrypt ADR-0003, ADR-0007
---

# One value model, three encodings in vitaminc, and EQL v4 separated by producer

> **Revised 2026-10-12.** This ADR now carries the decisions from
> [`docs/plans/2026-10-11-order-and-equality-terms-layering.md`](../plans/2026-10-11-order-and-equality-terms-layering.md):
> vitaminc sits at the bottom of the stack, equality and order terms take
> per-domain transforms over a shared semantic baseline, `vitaminc-prf` no
> longer depends on order encodings, and `orderable-bytes` is frozen. The plan
> keeps the steps; this document is the decision. One question is still open,
> under "Open decision".
>
> **Amended 2026-10-17 (#1232).** vitaminc 0.6 removed the shared value type
> rather than renaming `FfiValue` to `Value` (vitaminc ADR 0001: a value
> describes itself once, and sinks consume it). Stack Encrypt follows: a
> plaintext whose type is known only at run time is held as its transport
> frame (`dynamic::ValueFrame`) and walked into vitaminc's sinks, and
> `FfiValue` stays in Stack Encrypt as the tree of a binding's control data,
> which carries no secret. The two bullets below that this changes say so
> where they stand.

Every value Stack Encrypt handles is encoded three times: as a **ciphertext**
(reversible and self-describing), as an **equality term** (a keyed hash that
must be unambiguous) and as an **order term** (bytes whose order is the
value's order). This ADR decides where each encoding lives, which kinds of
value exist, how each kind is normalised before a term is derived from it,
and how EQL keeps columns written by Stack Encrypt apart from columns written
by cipherstash-client.

## The problem

In October 2026 Stack Encrypt could produce one of EQL's 51 types, `TextEq`.
The number, date, timestamp and decimal families were blocked on encoding,
not code. (`Bool` was not: it already had a kind, and EQL's only boolean
type, `eql_v3_boolean`, stores a ciphertext and nothing else.)

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
- **Order encodings were spread over three repositories.** Encodings lived in
  ore.rs, schemes in ore.rs and cipherstash-suite, and term derivation in
  vitaminc and Stack Encrypt. Every change needed releases in all of them,
  and the scheme crates accepted raw bytes, so a hand-encoded integer
  (little-endian, sign bit not flipped) encrypted without error and sorted
  wrong.
- **The existing writer's encodings are inconsistent.** cipherstash-client
  hashes a timestamp's milliseconds but orders by its nanoseconds, and hashes
  a decimal with its scale while ordering ignores it. Its block ORE text is
  ASCII-only, lowercased, maps every digit to one symbol and truncates to six
  blocks. cllw-ore's text order form (`orderize_string`) decomposes to NFD and
  then drops every character that is not alphanumeric, whitespace or ASCII
  punctuation, which removes symbols, emoji and non-ASCII punctuation as well
  as accents, and does not fold case.
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
   encodings then live in one repository, next to the value type they
   encode. Chosen. How "a kind exists in every layer or in none" is enforced
   is the open decision below; until it is settled, the conformance test
   described under "Which kinds get which terms" is what enforces it.

**Where order schemes sit.**

1. **`vitaminc-ore` adapts the scheme crates.** It depends on cllw-ore and
   ore-rs and wraps each in its own trait, with `orderable-bytes` underneath.
   This is the spread over three repositories described above.
2. **vitaminc at the bottom.** `vitaminc-ore` owns the order encodings and an
   `OrderScheme` trait and depends on no scheme crate; cllw-ore and ore-rs
   implement the trait. A scheme's input is a sealed type only `vitaminc-ore`
   can build, so raw bytes cannot reach a scheme. Chosen.

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
   Encrypt terms). A column's domain names its producer: a payload written
   to the other producer's domain fails its check on insert, and a typed
   client sees two different types. Names alone do not stop a cross-producer
   `=` in SQL; see Consequences. Chosen.

**How v3 and v4 ship.** Bumping `main` to v4 and patching v3 from a branch
needs a maintenance release path for five lockstep artefacts that does not
exist, and the EQL publish script puts every stable release on `latest`, so a
3.x patch would move `latest` backwards. A second package doubles the
trusted-publishing and release surface. One package carrying both bundles
avoids both, at the cost of teaching the release tooling about a second
bundle (see Consequences). Chosen.

## Decision

### Kinds and the ciphertext

- vitaminc 0.6.0 adds the kinds `Int8`, `UInt8`, `Int16`, `UInt16`, `Int128`,
  `UInt128`, `Date`, `Timestamp` and `Decimal`, each with a `ValueKind` name,
  a `Value` variant and a ciphertext tag, in one breaking release. Rust `i128`
  and `u128` get `Encrypt` and `Decrypt` impls.
- ~~`FfiValue` is renamed `Value`, with `#[deprecated] pub type FfiValue = Value`
  for one release.~~ *Amended 2026-10-17 (#1232):* vitaminc 0.6 has no shared
  value type to rename it to. Its ADR 0001 has a value describe itself once
  (`Encrypt`) and every consumer be a sink: the encrypting sink, a term
  deriver, a frame writer. A host binding walks its transport frame straight
  into those sinks. So Stack Encrypt holds a dynamic plaintext as its frame,
  `dynamic::ValueFrame`, in a wiped buffer, from the source a binding hands
  over to the sealed leaves and from the opened leaves back to the frame it
  returns, with no value tree in between. `FfiValue` stays in Stack Encrypt
  as the tree of a binding's control data (plans, contexts, options,
  statistics, the engine's answers), none of which is secret, and
  `ValueKind`, the vocabulary a plan field declares, stays beside it.
  Whether `ValueKind` is `#[non_exhaustive]` is the open decision.
- Every variant exists in every build. `Date`, `Timestamp` and `Decimal` use
  vitaminc's own representation (the payloads in the table below), with
  conversions to and from chrono and rust_decimal behind those features. A
  variant that appeared only with a feature would break any exhaustive
  handling outside `vitaminc-aead-value`, because features unify across a
  build and a crate can check only its own.
- `Value` implements `Clone` as a deep copy that rebuilds every leaf into a
  fresh `Protected`. A clone is under the same custody as its original.
- The sealed leaf tag table (`tags.rs`) stays frozen and contiguous. The
  transport codec's framing tags move from `0x10`–`0x12` to `0xF0`–`0xF2`;
  transport carries no compatibility commitment and every user of it updates
  together. A leaf is `[tag] ++ payload`. The new leaves, which every binding
  must produce byte for byte:

  | Tag | Kind | Payload |
  |---|---|---|
  | `0x0C`, `0x0D` | `Int8`, `UInt8` | 1 byte; two's complement for `Int8` |
  | `0x0E`, `0x0F` | `Int16`, `UInt16` | 2 bytes, little-endian; two's complement for `Int16` |
  | `0x10`, `0x11` | `Int128`, `UInt128` | 16 bytes, little-endian; two's complement for `Int128` |
  | `0x12` | `Date` | `i32`, little-endian: the day number in the proleptic Gregorian calendar with **0001-01-01 as day 1** (chrono's `num_days_from_ce`). 0001-01-01 is `01 00 00 00`, not zero |
  | `0x13` | `Timestamp` | `i64` Unix seconds, then `u32` nanoseconds, both little-endian, UTC. Nanoseconds are below 1,000,000,000, except at a leap second (seconds modulo 60 is 59), where they may go up to 1,999,999,999 (chrono's representation). Anything else is refused |
  | `0x14` | `Decimal` | 16 bytes: a little-endian `u32` of flags (sign in bit 31, scale in bits 16–23 and at most 28, every other bit zero), then the low, middle and high little-endian `u32` words of the 96-bit mantissa. This is rust_decimal's `serialize()` and keeps the scale. There is no NaN or infinity |

- `transport` stays a module of `vitaminc-aead-value`.

### Semantic baseline and per-domain transforms

The ciphertext keeps the value exactly as given: `1.50` decrypts as `1.50`,
and a timestamp keeps its nanoseconds. Terms are derived in two steps.

**The semantic baseline** makes values that are equal under `Value`'s own
semantics encode the same. Every term applies it; it loses nothing a user
would call a different value.

| Kind | Baseline |
|---|---|
| `Decimal` | scale normalised: `1`, `1.0` and `1.00` are equal |
| `Float32`, `Float64` | `-0.0` folded into `+0.0`; every NaN replaced by one positive quiet NaN, which sorts above +Infinity. This is Postgres's own `float8` semantics: `'NaN' = 'NaN'`, `'-0' = '0'` and `'NaN' > 'Infinity'` are all true |
| text | NFC |
| every other kind | none |

**Lossy transforms** sit on top of the baseline, chosen by each term's
domain: timestamp resolution, text folding and prefix truncation. Each
transform and its version is named in the domain label, for example
`…/timestamp/day/v1`. The ones defined now:

- **Timestamp resolution**: exact, microsecond or day. Microsecond rounds to
  the nearest microsecond, ties to even, on the signed microsecond count
  since the epoch. That is what Postgres does when it parses a timestamp with
  more digits than it keeps (`.1234565` becomes `.123456` and `.1234575`
  becomes `.123458`, before and after 1970; checked on Postgres 17.5). A
  value that already has microsecond precision is unchanged. Day takes the
  UTC calendar day.
- **Text fold, v1**: NFD, then full Unicode case folding (`CaseFolding.txt`
  statuses C and F, so `ß` becomes `ss`), then NFD again, then removal of
  every code point with General_Category `Mn`, then NFC. The order of the
  steps is part of the transform, because folding can produce text that is
  no longer normalised and the steps do not commute.
- **Prefix truncation**: a number of code points kept after any other
  transform. Alphabet packing, if ever built, is a transform of the same
  kind.

Text transforms are pinned to a Unicode version, which is part of the label
(for example `text-fold/unicode-16/v1`), and the `unicode-normalization` and
case-folding tables are pinned to it. Code points unassigned in that version
pass through unchanged (canonical combining class 0, no decomposition, no
case mapping), so the transform is a fixed function and nothing is refused on
write. The cost is that two strings using characters added after the pin,
which a later Unicode would treat as equivalent, may not match. Moving the
pin is a new label: existing columns keep the label they were written under
and stay queryable, and a column moves only by re-encryption.

Order terms fold case and accents because code-point order puts `é` after
`z`; a fixed fold approximates the first level of Unicode collation without
depending on ICU, whose sort keys change between versions. Equality on text
is not folded by default: a folded order term only produces ties, while a
folded equality term produces false matches. A case-insensitive equality is
its own domain.

**Equality and order may take different transforms**, for example an exact
timestamp for equality and the day for order, or the same one ("locked").
Stack's index spec carries the choice per column. Two rules bound it:

- **A non-injective order transform needs an equality term beside it.** In
  the EQL SQL, the numeric, date and timestamp `_ord`, `_ord_ope` and
  `_ord_ore` domains store no `hm` and answer `=` with the order term
  (`timestamp_ord_functions.sql`: `eq` is `ord_term(a) = ord_term(b)`). A
  day-resolution order term there would make `=` match every row from that
  day. So a lossy order transform is allowed only on a domain that also
  stores an equality term and answers `=` through it, the shape `text_ord`
  already has (`hm` and `op`). On the other domains the order transform is
  injective: exact for numbers and dates, and for timestamps whatever
  resolution the equality term would have used.
- **Labels separate domains; they do not make terms incomparable.** Terms
  built with different transforms are unrelated bytes, so a probe built with
  one matches nothing built with the other. Nothing in a stored term records
  its label. Keeping a query on the same transforms as the column is the
  index spec's job, and the EQL domain is what ties a column to its spec.

A column's leakage is the combined leakage of all its terms. Truncating the
order term to the day hides the order of events within a day, but an exact
equality term on the same column still reveals which rows share a timestamp.

### Which kinds get which terms

- **Every scalar kind has a ciphertext.** Containers and null have no terms.
- **Equality:** every scalar kind except `Bool`, including floats over their
  baseline bits. Stack Encrypt refused float equality until now, on the
  grounds that equality on IEEE-754 values is a modelling error. The baseline
  removes the two cases where bitwise equality and numeric equality disagree
  (signed zero and NaN payloads), and what is left is exactly Postgres's
  `float8 =`, which EQL's `real_eq` and `double_eq` domains already expose.
  Whether a computed float is the value the caller meant is the caller's
  problem, as it is for a plaintext float column.
- **Order:** every scalar kind except `Bool`, under all three schemes, with
  one exception: block ORE for text, which waits for ore-rs's variable-length
  block ORE (see Deferred).
- **`Bool` has a ciphertext only.** A keyed hash or an order term over a
  domain of two values hides nothing: it splits the rows into two groups, and
  an order term also says which group is `true`. Stack Encrypt stops
  producing CLLW order terms for `Bool`, and `vitaminc-ore` has no `Bool`
  encoding. cllw-ore keeps its `Bool` impl, so cipherstash-client and its
  stored v3 terms are unaffected.

These exceptions are an explicit, documented list kept next to vitaminc's
conformance test. The test fails for any kind that is missing from
`vitaminc-prf` or `vitaminc-ore` without an entry, and checks that values
equal under `Value` semantics produce equal terms in both.

### Where each encoding lives

- **Ciphertext:** `vitaminc-aead-value`. It does no term normalisation: its
  `canonical` module and its dependency on `orderable-bytes` are removed.
- **Equality:** `vitaminc-prf`, which depends only on `vitaminc-aead-value`,
  gains domains for every new kind, floats and `Decimal`, and applies the
  baseline and its own transforms. It has no ordering dependency. The
  value-derived PRF domains landed after vitaminc 0.5.1 and are unreleased,
  so their bytes are still free to choose.
- **Order:** a new `vitaminc-ore` crate, released in lockstep with the other
  vitaminc crates.
  - It owns the order encodings (ported from `orderable-bytes`, kept in
    `Protected`, pinned by golden vectors), the baseline, the order
    transforms, and derivation of order terms from `&Value`.
  - Its `OrderScheme` trait takes a sealed `OrderPlaintext`, fixed-length or
    variable-length, that only `vitaminc-ore` can build, and returns a
    scheme-defined term, roughly `type Term: Ord + AsRef<[u8]>`. Each scheme
    keeps its own comparison and stored bytes. The trait also covers the key
    type, domain separation (the label goes in as the salt) and typed errors.
  - It depends on no scheme crate; its tests use a mock scheme.
- **Schemes:** cllw-ore (CLLW ORE and OPE) and ore-rs (block ORE) implement
  `OrderScheme` behind an optional `vitaminc` feature, so cipherstash-client
  takes no vitaminc dependency. Their typed APIs are unchanged and not
  feature-gated. Block ORE through the trait uses each kind's natural width;
  the 8-byte padding stays a detail of the typed API cipherstash-client uses.
- **`orderable-bytes` is frozen.** It stays as it is for cipherstash-client's
  stored terms and is not part of the target design.
- **Term derivation** takes a `&Value` in `vitaminc-prf` and `vitaminc-ore`
  and keeps leaves inside `Protected`. A pairing a layer does not support
  returns a typed error from vitaminc.

### Stack Encrypt

- `dynamic::Value` and `dynamic::term::Scalar` are deleted. `dynamic::term`
  takes any source that describes itself to vitaminc (amended 2026-10-17,
  #1232: there is no `vitaminc_aead_value::Value`; a binding's value arrives
  as a transport frame and stays one, `dynamic::ValueFrame`). `admits` keeps
  only the rules that belong to Stack Encrypt, such as `Match` taking text
  only.
- Order terms go through `vitaminc-ore`. The index for an ORE or OPE column
  picks the concrete scheme (cllw-ore or ore-rs, through `OrderScheme`) and
  its transforms; Stack Encrypt no longer calls cllw-ore's typed API. A block
  ORE term kind joins CLLW ORE and OPE.
- `TextEq` normalises to NFC and moves to EQL v4. The Stack Encrypt targets on
  `eql_v3_*` domains are deleted. The `stack-encrypt:1:` ciphertext prefix
  stays: decryption does not pass through Postgres types, and the prefix is
  what lets it reject the other producer's payload.

### Host languages

A binding picks the kind from the field's **declared EQL target**, never
from the host type. This keeps the rule `eql-bindings` already enforces: a
target accepts exactly one kind, and nothing below the binding converts. The
binding converts a host value into the target's kind when it can do so
without loss, and refuses it otherwise.

| Kind | EQL family | |
|---|---|---|
| `Int16` | `smallint` | |
| `Int32` | `integer` | |
| `Int64` | `bigint` | |
| `Float32` | `real` | |
| `Float64` | `double` | |
| `Decimal` | `numeric` | |
| `Date` | `date` | |
| `Timestamp` | `timestamp` | |
| `String` | `text` | |
| `Bool` | `boolean` | |
| `Int8`, `UInt8`, `UInt16`, `UInt32`, `UInt64`, `Int128`, `UInt128`, `Bytes` | none | no EQL domain and no target name yet; a kind is selectable only once a target names it |

- **Go.** Any Go integer type whose every value fits the target's kind is
  accepted (`int8` into `smallint`, `int32` into `bigint`); a wider one is
  range-checked and refused if the value does not fit. `int8`, `int16`,
  `uint8` and `uint16` get their own kinds when a target names them; no
  target does yet, so today they reach `Int16`, `Int32` or `Int64` through
  the fits-losslessly rule.
  `Int128` and `Uint128` are SDK value types. `time.Time` means `Timestamp`,
  and `encrypt.Date{Year, Month, Day}` is a date. A field whose target is a
  date family also accepts `time.Time` and takes its calendar day **in the
  value's own location** (`t.Date()`), which is how Go code builds a date;
  taking the UTC day would store the previous day for a local midnight east
  of UTC.
- **JavaScript.** A `BigInt` takes the target's kind, and is refused if it
  does not fit. It decodes as a `BigInt`. `Date` means `Timestamp`; a date
  has its own wrapper.
- **Decimal.** A host decimal (Go's `shopspring/decimal`, a JavaScript
  string) is refused if it is NaN or infinite, has more than 28 digits after
  the point, or does not fit a 96-bit mantissa at its scale. Postgres
  `numeric` holds values that `Decimal` cannot, and a binding refuses them
  rather than rounding.
- **Every binding** runs vitaminc's shared test vectors: a host value, the
  target, the kind it must map to, and the exact `[tag] ++ payload` leaf
  bytes, including normalisation and refusal cases. The leaf is
  deterministic even though the AEAD is not.

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
  queried. Queries are a different matter; see Consequences.
- **New EQL targets are v4-only.** In v3 they stay refused, with a reason
  that points to v4. A domain that a lossy order transform needs, with an
  `hm` beside its `op`, is one of these, and is the first point where the v4
  SQL differs from the v3 SQL.
- **`@cipherstash/eql` 4.x ships both bundles** from `main`. A SQL fix lands in
  both names in one release.
- **`--eql-version` comes back, on purpose.** It was removed when v3 became
  the only installable generation, and the CLI now refuses it. It returns as
  `--eql-version 3|4|all` on both `stash eql install` and
  `stash eql migration`, so the migration-first paths (Drizzle, and Supabase
  with a local `supabase/` directory, where a direct install does not survive
  `supabase db reset`) can install v4 too. The migration they write carries
  the chosen bundles, and `--supabase` grants on each bundle's schemas. The
  default is 3, which is today's behaviour, and changes to 4, announced in
  advance, when the TypeScript stack has moved to Stack Encrypt. `2` keeps
  its current message pointing at the EQL 2.3.1 release, rather than
  becoming an ordinary invalid value.
- **During the overlap**, expected to last a quarter or more, cipherstash-client
  takes fixes only. New kinds and domains are produced through Stack Encrypt
  and v4. An exception is a decision written down in its issue.

### Review

A domain that locks equality and order together derives both from the same
transformed bytes, and that choice is frozen once data is stored under it.
Dan Draper signs off each such domain in writing before it ships. Domains
whose equality and order transforms are independent need no such sign-off.

## Open decision: exhaustive handling of `Value`

`vitaminc-prf`, `vitaminc-ore` and every binding must handle every kind of
`Value`, and adding a kind should fail to build until each one does. Two
approaches remain:

- **A: drop `#[non_exhaustive]`.** Every crate that matches `Value` gets
  exhaustiveness, and adding a kind is a breaking change for all of them.
- **B: a `ValueVisitor` trait with one required method per kind, keeping
  `#[non_exhaustive]`.** Crates that must handle every kind implement it, and
  adding a kind is breaking only for them; other crates keep a `_ =>` arm.

The leaning is B. The layering plan sets out the comparison. Either way,
the conformance test is the backstop: a `#[non_exhaustive]` enum lets a
downstream match compile with a wildcard, so the compiler alone does not
guarantee coverage under B.

## Consequences

- **The release order is fixed.** vitaminc 0.6.0 first, then cllw-ore and
  ore-rs (additive releases implementing `OrderScheme`), then the Stack
  Encrypt breaking release. Stack Encrypt must reach crates.io before
  `eql-bindings` uses its new API, since `cargo publish` builds
  `eql-bindings` against the registry. The EQL v4 bundle and the Go SDK
  changes follow.
- **Adding a kind later** takes a tag, PRF and order encodings, a codec in
  every binding, test vectors and a row in the kind-to-family table, or an
  entry in the exceptions list. Whether it is a breaking change depends on
  the open decision.
- **Stack Encrypt's terms change** for `-0.0` and negative-sign NaN floats,
  for non-NFC text equality, for `Bool` order terms, which are removed, and
  for every text order term: `orderize_string` drops symbols and keeps case,
  while the fold keeps symbols and folds case. None is deployed, so the
  breaking release carries them without migration.
- **cipherstash-client's terms do not change.** `orderable-bytes`, cllw-ore's
  typed impls (`Bool` included) and its block ORE padding are all kept, so
  every stored v3 payload stays queryable.
- **Separate names do not stop a cross-producer comparison in SQL.** EQL's
  domains are over `jsonb`, and when no operator is defined for an exact pair
  of types, Postgres treats a domain as its base type. `v3col = v4term` then
  runs as the built-in `jsonb = jsonb` and returns no rows, silently, as
  `eql_v3_text_eq = eql_v3.query_integer_eq` already does within v3. A join
  between a v3 and a v4 column does the same, and
  `eql_v3.eq_term(v3col) = eql_v4.eq_term(v4term)` compares the two terms as
  text. Three things do fail loudly: an insert of the wrong version (the
  domain check), the function form `eql_v3.eq(v3col, v4term)` ("not unique"),
  and `OPERATOR(public.=)` between a v3 and a v4 column ("not unique").
  Verified on Postgres 17 with both bundles installed in one database.
- **Tooling that recognises encrypted columns by the `eql_v3_` prefix must
  learn `eql_v4_` before any v4 column can exist.** Today that is
  `stash init`'s introspection (`cli/src/commands/init/lib/introspect.ts`),
  the wizard's tools (`wizard/src/tools/wizard-tools.ts`) and
  `classifyEqlDomain` (`migrate/src/version.ts`), which `stash status` and
  `stash encrypt status` use. Getting this wrong shows an encrypted column as
  plaintext, which invites encrypting it a second time. The installer's
  ADR-0001 capture, rebuild and verify logic hard-codes the disposable
  schemas as `('eql_v3', 'eql_v3_internal')`
  (`installer/derived-search-index-restoration.ts`,
  `installer/installation-state.ts`); without `eql_v4` and
  `eql_v4_internal` there, a v4 reinstall would capture and restore none of
  its own indexes. Both land with the first released v4 bundle.
- **The release tooling assumes one bundle.** The lockstep stamp is read from
  `COMMENT ON SCHEMA eql_v3` (`scripts/sync-lockstep-versions.mjs`,
  `packages/eql/tasks/release/prepare-bindings-assets.sh`); there is one
  `release-manifest.json` per artefact, which the CLI's `bundle-digest.ts`
  and `eql-sql-asset-freshness.test.mjs` check; `eql_bindings::sql` embeds
  only the v3 files; and `_build-eql-sql.yml` uploads only them. The v4
  bundle needs its own stamp, manifest entries, freshness check, crate
  constants and release upload before it ships, or v4 drift goes unnoticed
  with every digest still verifying. The `postgres-eql` image states which
  bundles it installs.
- **Moving a column from v3 to v4 means re-encrypting it.** The ciphertext and
  every term change. How that migration runs belongs to the decision that
  moves the TypeScript stack onto Stack Encrypt.
- **The CLI surface changes** (`--eql-version` on `stash eql install` and
  `stash eql migration`), so `skills/stash-cli`, `skills/stash-indexing` and
  `skills/stash-postgres` change in the same PR.
- **This replaces a definition in a plan.** `docs/plans/2026-10-04-plan-builder.md`
  called "EQL v4" a name for a Stack Encrypt payload in the v3 envelope and
  the `eql_v3_*` domains. That plan is updated to this ADR.

## Deferred

- **Block ORE for text** waits for ore-rs's chained, variable-length block ORE
  to be reviewed and released, then arrives in a minor release of
  `vitaminc-ore`. Until then it is an entry in the exceptions list.
- **Block ORE for `Bool`.** Block ORE stored as right ciphertexts only is
  fully randomised and semantically secure, so a two-value domain leaks
  nothing through it. `Bool` could support that scheme alone, enforced by a
  marker trait on schemes. Not built until needed.
- **Cross-version blocker operators.** Blockers for every v3/v4 pair of the
  same type family and capability would turn the silent cross-producer `=`
  into an error. About 2,300 operators, generated from the catalog like the
  existing blockers. Not built yet; until then, a cross-producer query is
  caught only by typed clients, the function form and `OPERATOR(public.=)`;
  the plain `=` returns no rows. When they are built,
  **the v4 bundle owns them**: it creates them in `eql_v4_internal`, against
  whichever `public.eql_v3_*` domains exist, on every install. A v4 reinstall
  drops them with its schema and creates them again. A v3 reinstall leaves
  them alone, because they depend only on the `public` domains, which
  survive, and not on anything in `eql_v3`. Installing v3 after v4 into a
  database that had no v3 domains leaves them absent until v4 is reinstalled,
  so `--eql-version all` installs v3 first.
- **Locale-aware collation**, as its own domain with the collation version in
  its name.
- **ASCII-packed text domains**, until a customer's column sizes make the
  case.
