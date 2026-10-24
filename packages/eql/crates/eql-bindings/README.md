# eql-bindings

Canonical wire types for EQL payloads — **one Rust definition per payload
shape**, the single source of truth for every tool that produces or consumes
EQL payloads (`cipherstash-client`, `protect-ffi`, CipherStash Proxy).

TypeScript bindings are generated from these definitions via [`ts-rs`] into
[`bindings/`](bindings/), and JSON Schemas via [`schemars`] into
[`schema/`](schema/).

## Why

Type information is lost at every hop of `EQL → cipherstash-client →
protect-ffi → stack`. protect-ffi hand-writes its TypeScript types; they drift
from the Rust they describe; stack widens them further. The result is bugs
like the `protect-dynamodb` search-term check that validates a payload shape
EQL never actually defined. A generated, single-source crate removes the
hand-copying.

## Capability-encoded types

The [`src/v3/`](src/v3/) module has one type per **SQL domain** in the
`eql_v3` schema — `Integer` / `IntegerEq` / `IntegerOrd` / `IntegerOrdOre`, and likewise
for `smallint`, `bigint`, `date`, `timestamp`, `numeric`, and `text` (which adds
`TextMatch`) — each carrying its index terms as **required** fields. The
capability is the type identity; `Option` never appears. A payload missing
its term key fails to deserialize: the Rust analogue of the SQL domain's
CHECK constraint.

Shared wire fields are reusable newtypes in
[`src/v3/terms.rs`](src/v3/terms.rs):

| Newtype | Wire key | Inner | Backs |
|---------|----------|-------|-------|
| `Ciphertext` | `c` | `String` | every domain (envelope) |
| `Hmac256` | `hm` | `String` | `_eq` domains + the text ordering/search domains |
| `OpeCllw` | `op` | `String` | `_ord` / `_ord_ope` domains, `text_search` |
| `OreBlock256` | `ob` | `Vec<String>` | `_ord_ore` domains, `text_search_ore` |
| `BloomFilter` | `bf` | `Vec<i16>` (signed!) | `_match` domains |

EQL v4 shares these except its order terms. A v4 `ob` field is Stack
Encrypt's `stack_encrypt::sem::OreBlockTerm<T>` and an `op` field its
`OpeTerm<T>`, over the type's plaintext (`v4::date::DateOrdOre::ob` is an
`OreBlockTerm<Date>`). Each is one lowercase hex string on the wire, and
reading a payload checks the term's structure, so an EQL v3 term or a term
of the other scheme is refused. `v4::terms::OreBlockHex` and `OpeHex`
describe that JSON to TypeScript and JSON Schema.

Note "v3" names the SQL schema generation (`eql_v3.*`); the JSON envelope
version is `v: 3` — the generated domain CHECKs assert `VALUE->>'v' = '3'`, and
the wire field names are unchanged from v2 (the purpose-named rename in
`docs/plans/eql-payload-scheme-discipline-rfc.md` is deferred).

## Drift protection

`tests/catalog_parity.rs` asserts the domain inventory —
[`v3::all()`](src/v3/mod.rs), a `Vec<Box<dyn DomainType>>` of zero-sized
type-level handles — exactly covers `eql-domains::CATALOG` (the same catalog
that generates the `eql_v3` SQL surface): every domain, in order. Adding a
scalar to the catalog without adding its types here fails the build.
Wire-key strictness (required term keys, unknown-key rejection, envelope
version) is covered per-type in `tests/v3_conformance.rs` and pinned against
the catalog by the JSON Schema parity test in the stacked schemars change.

## Develop

```sh
mise run types:generate   # clean-regenerate bindings/ and schema/
mise run types:check      # regenerate + fail if checked-in outputs are stale
```

Both wrap `cargo test -p eql-bindings`, which runs the conformance tests and
regenerates `bindings/` (TypeScript, via ts-rs) and `schema/` (JSON Schema,
via `tests/export.rs`, with canonical `$id`s injected). Both directories are
checked in so reviewers can see the codegen output without running anything;
CI runs `types:check` to keep them fresh. The crate is also part of the lean
`mise run test:crates` set (fmt, clippy, test — no database).

Note that both exporters default to writing under the crate dir (ts-rs to
`./bindings`, `tests/export.rs` to `./schema`), so a plain
`cargo test -p eql-bindings` (and therefore `mise run test:crates`) regenerates
`bindings/` and `schema/` **in place** as a side effect — it can leave your
working tree dirty if the checked-in copies were stale. Only `types:generate`
isolates the writes (it exports into a temp dir and swaps them in after the
build succeeds).

Published `eql-bindings` crates also include `eql_bindings::sql`, which exposes
the exact self-contained SQL installer and uninstaller built for the same EQL
release identity as the Rust wire types.

## Future direction: self-describing payloads

On the wire, a v3 payload is discriminated only by *which key is present*
(`hm` vs `ob` vs `bf`) — the SQL domain name carries the rest. Once the JSON
leaves SQL (into protect-ffi, into TypeScript, into a log line) that
information is gone, and a consumer is back to sniffing keys: the untagged
failure mode that produced the original protect-dynamodb bug. An earlier
prototype here carried an `IntegerTagged` enum with a one-field capability tag
(`"x": "integer_eq"`), which generates a clean TypeScript discriminated union
and a JSON Schema `oneOf` with per-branch `const`s. It was removed because
the tag is not part of the v3 wire contract (the generated domain CHECKs
know no `x` key) — but it remains the recommended shape if a future payload
revision adds a discriminator. See
`docs/plans/eql-payload-scheme-discipline-rfc.md` for the wider payload
evolution plan.

[`ts-rs`]: https://github.com/Aleph-Alpha/ts-rs
[`schemars`]: https://graham.cool/schemars/

## Rust text equality with Stack Encrypt

The optional `stack-encrypt` feature enables `EncryptFrom<String>` for
`v4::text::TextEq` and `v4::text::TextEqQuery`, and `DecryptInto<String>` for
`v4::text::TextEq`. Stack Encrypt writes EQL v4 only, so no `v3` type
implements these traits. The derives are emitted by `eql-codegen`.

The other v4 types Stack Encrypt produces take a Rust primitive as their
plaintext, or, for a date, a timestamp or a decimal, one of
`eql_bindings::v4::plaintext`'s types:

| v4 type | Plaintext |
| --- | --- |
| `Text`, `TextMatch`, `TextOrd`, `TextOrdOpe`, `TextOrdOre`, `TextSearch`, `TextSearchOre` | `String` |
| `Smallint`, `SmallintEq`, `SmallintOrd`, `SmallintOrdOpe`, `SmallintOrdOre` | `i16` |
| `Integer`, `IntegerEq`, `IntegerOrd`, `IntegerOrdOpe`, `IntegerOrdOre` | `i32` |
| `Bigint`, `BigintEq`, `BigintOrd`, `BigintOrdOpe`, `BigintOrdOre` | `i64` |
| `Boolean` | `bool` |
| `Real`, `RealEq`, `RealOrd`, `RealOrdOpe`, `RealOrdOre` | `f32` |
| `Double`, `DoubleEq`, `DoubleOrd`, `DoubleOrdOpe`, `DoubleOrdOre` | `f64` |
| `Date`, `DateEq` | `v4::plaintext::Date`: an `i32` of days since 1970-01-01 |
| `Timestamp`, `TimestampEq` | `v4::plaintext::Timestamp`: `i64` Unix seconds and `u32` nanoseconds, UTC, no leap seconds |
| `Numeric`, `NumericEq` | `v4::plaintext::Decimal`: an `i128` mantissa (below 2^96) and a `u8` scale (at most 28) |

A date, a timestamp and a decimal have no Rust standard type, and chrono's
and rust_decimal's types cannot be wiped, so these three are this crate's
own. Each is built range checked (vitaminc's ranges, which are chrono's and
rust_decimal's), refusing a value outside them with an error that does not
show it, and wipes its integers when dropped. It is not `Copy`. The `chrono`
and `rust_decimal` features convert to and from `NaiveDate`,
`DateTime<Utc>` and rust_decimal's `Decimal`; the value converted to is the
caller's, and is not wiped. Only a leap second, which a `DateTime<Utc>` can
hold and a `Timestamp` cannot, is refused in a conversion. On `NumericEq`,
`1.5 = 1.50` (the scale is normalised); on `TimestampEq`, an instant is truncated to the microsecond (the nanoseconds below it are dropped, not rounded), so two instants in the same microsecond are equal. Each opens as
it was stored. Their ordered types order a date by its day, a timestamp by
the microsecond (truncated, as on `TimestampEq`) and a decimal by value.

Each seals the same leaf the Go SDK seals for the same value, so values
written here and by the Go SDK open each other. On the equality
types, `=` behaves as Postgres's own does: an integer has one term whatever
its width, and for floats `-0.0 = 0.0` and `NaN = NaN`. The ciphertext keeps
the exact value.
The `Ord` and `OrdOpe` types store an OPE term (`op`), which EQL compares as
bytes, so `<`, `<=`, `>`, `>=` and `ORDER BY eql_v4.ord_term(col)` follow
ADR-0002's order key: integers by value, floats as PostgreSQL's `float8`
sorts them (`-0.0` ties `0.0`, every NaN is one value after `+Infinity`, and
an `f32` orders as the `f64` it widens to), and text by its fold (case and
accents folded, under Unicode 16). On a number column `=` compares the order
term too. A text order type also stores `TextEq`'s equality term, and `=`
reads that one, so `Café` and `cafe` are neither `<` nor `>` each other, and
not `=` either. Text with a code point Unicode 16 does not assign has no
order term and is refused, stored or queried. A family's `Ord` and `OrdOpe`
types store the same term under one column. The query value carries one
bound: `BETWEEN` needs EQL v4's range query domains and is not produced yet.
`TextMatch` builds its filter under a configuration pinned in this crate
(`EqlMatch`: 3-grams of the lower-cased text, `k = 6`, a 2048-bit filter) for
stored values and queries alike. The configuration is part of the stored
format, so changing it means a new domain or payload version. A filter can
match a row that does not contain the query, so re-check after decrypting
where that matters. Write the stored column on the left, `col @@ query`: the
other order finds nothing until #1171 is fixed. Text too short to make a
3-gram (empty strings, two-letter codes) cannot be stored in a `TextMatch`
column yet, and a `TextMatchQuery` for it is refused too: one filter type
builds both, and an empty filter as a query would match every row.
`TextSearch` stores all three terms (`TextEq`'s `hm`, `TextOrd`'s `op` and
`TextMatch`'s `bf`). Text too short for a 3-gram is stored with the empty
filter (`"bf": []`, the `SearchBloomFilter` field type): `=` and `<` find it
through `hm` and `op`, and no `@@` query does, because a query's filter is
never empty. (A `@@` between two stored values, which no producer builds, is
not a query: two stored empty filters match each other there, as in v3.) Its query carries only the term its operator reads: build it
through `TextSearchEqualityQuery` (`=`, `<>`), `TextSearchOrderQuery` (`<`,
`<=`, `>`, `>=`) or `TextSearchMatchQuery` (`@@`) and convert into
`TextSearchQuery`, and the by-name dispatch picks the one for the index that
answers the operator. So `=` and `<` work on short text, a match query on it
is refused, and EQL v4 raises on an operator whose term the query lacks (or
holds as `null`, or as an empty filter).
The ORE types (`*OrdOre`, `TextSearchOre`) store a block ORE term (`ob`):
one element, the hex of a whole ore-rs 6-bit block ORE ciphertext (the
fixed-width scheme for numbers, the chained scheme for text, padded to a
power-of-two bucket of at least 16 bytes). They order by the same key as the
`Ord` types, but EQL v4 compares them with its own comparator,
`eql_v4_internal.compare_ore_block_v2_term`, and `ORDER BY` reads
`eql_v4.ord_term_ore(col)`. Every term carries a random nonce, so a query's
`ob` never equals the stored bytes; the comparator orders them. Text whose
fold is longer than 1023 bytes or ends in NUL has no block ORE term and is
refused. `TextSearchOre` follows `TextSearch`, with `ob` in place of `op`.
`Date`, `Timestamp` and `Numeric` wait for a choice of their Rust plaintext
types, and `Json` for a decision on sealing a document as one leaf.

Each ordered v4 family also has two range query types, one per order term:
`IntegerRangeOreQuery` and `IntegerRangeOpeQuery`, and so on
(`v4::all_range_query()` lists them). A range holds both bounds of one
`BETWEEN`: each bound is the single-bound domain's `ob` (ORE) or `op` (OPE)
value, in a `{v, i, lo, hi}` envelope. It binds as one parameter to
`eql_v4.between(column, $1::eql_v4.query_integer_range_ore)`, which includes
both bounds. Cast the parameter to its exact range domain: an uncast `$1`, a
`jsonb` parameter, or a range of another term or family fails with SQLSTATE
42725 ("function ... is not unique"), unlike the single-bound operators, which
resolve an untyped `$1`. Nothing produces a range yet, since the ordered types
are not producible, and Stack Encrypt will need to build the envelope when
they are. EQL v3 has no range types or `between`.

The generated API docs include a complete, executable example in the
`eql_bindings::encryption` module, from cipher setup through decryption. Its
[source](src/encryption/example.rs) is also run by the encryption test crate:

```bash
# From packages/eql:
cargo test -p eql-encryption-tests --test text_eq_example
```

With an initialized cipher, the essential calls are:

```rust,ignore
use eql_bindings::{Identifier, v4::text::{TextEq, TextEqQuery}};

let column = Identifier::for_column("users", "email")?;
let keyset = cipher.default_keyset();
let email = "alice@example.com".to_owned();
let stored: TextEq = keyset.encrypt_as(&email, column.clone()).await?;
let query: TextEqQuery = keyset.encrypt_as(&email, column.clone()).await?;
let opened: String = cipher.decrypt_as(stored, column.into()).await?;
```

Both identifier components must be nonempty. Encryption stores the identifier
in `i`; its table and column supply the ciphertext AAD, term context, and ZeroKMS
descriptor. The storage field names `c` and `hm` add no further context.
Decryption validates `i` before retrieving keys. Passing an expected identifier,
as above, also checks the destination. `Default::default()` uses the stored
identifier alone, so moving a complete payload with its original `i` still opens.

Ciphertext uses Vitamin C's native string encoding. Equality uses its exact
string PRF input, with no normalization or case folding: `café` and
`cafe\u{301}`, or `Alice` and `alice`, produce different terms. A query contains
only `v`, `i`, and `hm` and requests no data keys. Neither EQL type implements
the plaintext-side `Encrypt` or `Decrypt` traits.

This is a **new producer profile**, independent of existing cipherstash-client
ciphertext and terms. `c` is `stack-encrypt:1:` followed by padded standard base64 of Stack
Encrypt's native `SealedValue` bytes; `hm` is the native 32-byte equality term
encoded as hex. Serde handles the final EQL JSON envelope only. SQL consumes
these payloads through the `public.eql_v4_text_eq` and
`eql_v4.query_text_eq` domains and their equality extractor index. Writers and
query producers for these values must use this same profile.

The `Identifier` stored in `i` is Stack Encrypt's `Describe`: its ZeroKMS
descriptor is `<table>/<column>`, two parts, the same context and descriptor as
a two-segment `stack_encrypt::Label`. A table or column containing `/` is
escaped in the descriptor rather than read as two names.

### Querying an EQL v4 field from Rust

A query names an operator, and a plan for the column's EQL type finds the
index that answers it (Stack Encrypt's ADR-0009). The term that comes back
is the type's query twin, the value the `eql_v4.query_*` domain takes:

```rust,ignore
use eql_bindings::v4::text::{TextEq, TextMatch};
use stack_encrypt::op::{self, Probabilistic, Stats};
use stack_encrypt::Plan;

// A plan for the column's type, under the label that names the column:
// "users/email" is Identifier::for_column("users", "email").
let email_plan = Plan::value::<String>().context("users/email").encrypt_into::<TextEq>().build()?;
let query = cipher.query(op::Eq, "alice@example.com").on(&email_plan).await?; // a TextEqQuery
// WHERE email = $1::eql_v4.query_text_eq, binding sqlx::types::Json(&query)

let name_plan = Plan::value::<String>().context("users/name").encrypt_into::<TextMatch>().build()?;
let query = cipher.query(op::Matches, "ali").on(&name_plan).await?; // a MatchTwin<TextMatchQuery>
let fetch = query.target_limit(10, &Stats::declared(1_000_000)).fetch_or(50);
// WHERE name @@ $1::eql_v4.query_text_match LIMIT $2, then keep the
// decrypted rows for which query.verify(&name) is true.
```

| v4 type | Operator | Query term |
| --- | --- | --- |
| `TextEq` | `op::Eq` | `TextEqQuery` |
| `SmallintEq`, `IntegerEq`, `BigintEq`, `RealEq`, `DoubleEq` | `op::Eq` | `SmallintEqQuery`, `IntegerEqQuery`, `BigintEqQuery`, `RealEqQuery`, `DoubleEqQuery` |
| `DateEq`, `TimestampEq`, `NumericEq` | `op::Eq` | `DateEqQuery`, `TimestampEqQuery`, `NumericEqQuery` (from `v4::plaintext::Date`, `Timestamp`, `Decimal`) |
| `TextMatch` | `op::Matches` | `MatchTwin<TextMatchQuery>` |

`MatchTwin` serializes as the twin and adds `verify` and `target_limit`
under `EqlMatch`: a filter can match a row that does not hold the query's
text, so keep only the decrypted rows that verify. An exact query has no
`verify`. An operator a type does not answer does not compile: `op::Lt` on
`TextEq`, or `op::Matches` on `IntegerEq`. Nor does naming another index
with `.via(..)`, such as the bare `Equality`, whose term the type's SQL does
not take. The ordered types (`IntegerOrd`, `TextOrd`, …) answer nothing in
the typed chain yet: their twins need an order term, or several terms at
once, and the chain sends one index's term. Query them through the data
path (`stack_encrypt::dynamic::query_term`) for now.

The label must name the column the value was written under, as two
segments, table then column. A label of any other length, and a query
extended with `.extend(..)` (whose terms would be derived under more than
the column the twin stores), are refused when the query is awaited, before
any keyset is resolved, with an `encryption::query::QueryLabelError` in
`Error::Other`. A label's segments are plain, so a table or column name
that is not a plain label segment cannot be named on a plan, and such a
column, which `Identifier::for_column` accepts, cannot be queried this way:
for instance a name that starts with a digit, `-` or `b64:`, or one holding
`/`, `(`, `)`, or a control or invisible format character.
The plan is for queries: write with
`keyset.encrypt_as(&value, column)` and open with `cipher.decrypt_as`, since
an EQL type is sealed under its column rather than the plan's label. The
query is the same bytes the data path derives for a field that names the
type (`stack_encrypt::dynamic::query_term`), which is what the Go SDK sends,
and `tests/encryption/tests/typed_queries.rs` checks that for every type and
operator. The `op::Answers` impls are generated into `src/v4/answers.rs`
from the catalog by the rule the data path uses, and need only the
`stack-encrypt` feature, not `targets`; the supporting types are in
`eql_bindings::encryption::query`, whose
[executable example](src/encryption/query_example.rs) runs with
`cargo test -p eql-encryption-tests --test query_example`.

### Interoperability matrix

The plan asked for the three producer/reader pairings to be proven rather than
assumed. Outcomes against today's sources:

| Writer | Reader and query producer | Outcome |
| --- | --- | --- |
| Rust (`stack-encrypt` profile) | Rust (`stack-encrypt` profile) | **Proven.** `tests/encryption/tests/text_eq.rs`: JSON round trip, both canonical directions, PostgreSQL insert and equality query. `tests/encryption/tests/v4_types.rs`: the same for the other producible v4 types, in both directions between the typed plaintexts and the by-name dispatch's value frames. |
| JS / FFI (`cipherstash-client` profile) | Rust | **Not supported.** `c` lacks the `stack-encrypt:1:` prefix and is refused loudly on decryption. A Rust probe against such a column is accepted by SQL and matches nothing. |
| Rust (`stack-encrypt` profile) | JS / FFI | **Not supported.** The JS reader does not know the `stack-encrypt:1:` prefix and the two profiles' equality terms never match. |

Rows 2 and 3 need compatible encryption, decryption and index derivation on
both sides before they can change; that is upstream work, not a flag. The
profiles are separated by EQL version (ADR-0002): Stack Encrypt writes the
`eql_v4` domains and only the [`v4`](src/v4/mod.rs) types derive its traits,
while cipherstash-client writes `eql_v3`. A payload of the wrong version fails
the domain check on insert. A plain `=` between a v3 column and a v4 query
term still returns zero rows with no error, so keep each column to one
version.

### EQL types as plan field targets

A binding has no Rust type to name: its plan arrives as data, and a field of
that plan names its EQL type as a string (`"TextEq"`). The
`eql_bindings::encryption::targets` module is where the string meets the type.
`targets()` is the catalog-generated table of every EQL type a plan may name —
its name across languages, family and suffix, the plaintext kind it takes (a
vitaminc `ValueKind` name, the same names a plan field's `"type"` key uses), the
indexes it carries (`eq` / `match` / `ore` / `ope` / `json`), its query twin,
and whether the engine can produce it today, with the reason when not. A guest
serializes it for its `se_targets` export; the module docs are the wire format.
`encrypt`, `decrypt` and `query` dispatch on the name and run the type's own
Rust plan — the same `EncryptFrom` the typed `encrypt_as::<TextEq>` runs, so
the two paths produce the same identifier and equality term and open each
other's values. An unproducible name is refused with the table's reason; an
unknown one with "no such EQL type".

```rust,ignore
use eql_bindings::encryption::targets;
use stack_encrypt::Label;
use stack_encrypt::dynamic::ValueFrame;

let column = Label::new(["users", "email"])?; // the field's context: table/column
let email = ValueFrame::of("alice@example.com")?; // the plaintext as its transport frame
let stored: Vec<u8> = targets::encrypt("TextEq", &keyset, &column, email.clone())?.await?;
let probe: Vec<u8> = targets::query("TextEq", &keyset, &column, email)?.await?;
let opened: ValueFrame = targets::decrypt("TextEq", &cipher, &column, &stored)?.await?;
```

The table and the dispatch are generated into `src/v4/targets.rs` beside
the v4 family modules (`mise run types:generate`), gated to the `targets`
feature, and drift-gated by the same parity tests. The same generator writes
the Go package `languages/golang/encrypt/eql` from the same rows
(`eql-codegen go-eql`, also under `types:generate` / `types:check`). The
engine's `TargetResolver` (stack-encrypt's `dynamic` module) is implemented
over this module by the Go guest's `eql` build, not here: a resolver in this
crate would need stack-encrypt API newer than the crates.io release the
published crate names, and the guest already depends on both. A type is producible exactly
when its generated struct carries the `stack-encrypt` derives
(`ENCRYPTION_DOMAINS` in `eql-codegen`), because the dispatch runs the derived
plan; `targets::targets()` lists them, each with `producible` and, when it is
`false`, the reason.

### Features

- `stack-encrypt`: the EQL v4 types (`eql_bindings::v4`) with Stack
  Encrypt's `EncryptFrom` and `DecryptInto`, for a Rust program that
  encrypts through `encrypt_as`. It builds Stack Encrypt with no default
  features and without its `dynamic` layer.
- `targets`: `stack-encrypt`, plus the by-name dispatch a language binding
  needs (`encryption::targets`, `v4::targets`), where the EQL type is named at
  run time and the plaintext is a `ValueFrame`. It turns on Stack Encrypt's
  `dynamic` feature. The Go guest's `eql` build enables it.

### Developing the `stack-encrypt` feature

Stack Encrypt lives in this repository (`packages/stack-encrypt`), and the
feature depends on it by path and version: in-tree builds use the path, and the
published `eql-bindings` resolves the version from crates.io. The two agree only
when the `stack-encrypt` on crates.io at that version has the API this feature
uses, which a path build cannot check — 0.1.0 shipped without `Describe`, and
every in-tree test passed against the newer tree. So the feature is also built
from the packaged crate against the registry: `cargo publish -p eql-bindings
--dry-run --all-features` in CI, and `publish_all_features` in
`packages/eql/release-plz.toml` at release time. Bump the requirement in
`Cargo.toml` together with the `stack-encrypt` bump that carries what the
feature needs. While that version is not yet on crates.io the dry run cannot
build against the registry and warns instead of failing; the release-time
verify still refuses to publish `eql-bindings` until it is.

```bash
# From packages/eql. The mise tasks are what CI runs (test-eql.yml, `rust-crates`).
mise run test:encryption            # feature tests, the test crate, clippy; no database
EQL_TEST_DATABASE_URL="host=localhost port=5432 user=postgres password=postgres dbname=postgres" \
  mise run test:encryption:postgres # installs the EQL bundle, then the PostgreSQL test
mise run check:encryption:wasi      # wasm32-wasip1, no HTTP
```
