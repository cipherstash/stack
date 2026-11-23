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

The optional `stack-encrypt` feature implements Stack Encrypt's
`EncryptTarget<String>` for `v4::text::TextEq` and `v4::text::TextEqQuery`, and
`DecryptSource<String>` for `v4::text::TextEq`. These owned traits take the
plaintext by value and wipe it.

Stack Encrypt writes EQL v4 only, so no `v3` type implements these traits.
`eql-codegen` emits the derives.

Each Rust example in this file is a complete program, and the encryption
test crate runs it as a doctest:

```bash
# From packages/eql:
cargo test -p eql-encryption-tests --doc
```

The examples build their cipher over `FakeDataKeySource`, from the
`test-support` feature of `stack-kms`. It holds its keys in memory, so an
example needs no credentials. A real program passes its own key source to
`.kms(..)`, or leaves `.kms(..)` out to use ZeroKMS. That needs Stack
Encrypt's `http` feature, which is on by default.

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
| `Date`, `DateEq` | `v4::plaintext::Date`: a calendar date, built from jiff's `civil::Date` |
| `Timestamp`, `TimestampEq` | `v4::plaintext::Timestamp`: a UTC instant to the nanosecond, built from jiff's `Timestamp` |
| `Numeric`, `NumericEq` | `v4::plaintext::Decimal`: a mantissa (below 2^96) and a scale (at most 28), built from rust_decimal's `Decimal` |

A date, a timestamp and a decimal have no Rust standard type, and jiff's
and rust_decimal's types cannot be wiped. So these three are vitaminc's
types, re-exported at `v4::plaintext`.

- Each is built from the jiff or rust_decimal value: `Date::new`,
  `Timestamp::new`, and `Decimal::new`. The ranges are jiff's and
  rust_decimal's: dates from `-009999-01-01` to `9999-12-31`, instants from
  `-009999-01-02T01:59:59Z` to `9999-12-30T22:00:00.999999999Z`.
- Each stores the value as integers and wipes them when dropped. None is
  `Copy` or `Clone`.
- `to_jiff` and `to_decimal` return a jiff or rust_decimal value. That
  value is the caller's. It is not wiped.
- `Timestamp::new` can fail. When jiff 1.0.0 parses text with a UTC
  offset, it can make an instant before its own `Timestamp::MIN`.
  `Timestamp::new` refuses that instant (`OutOfRange`).

On `NumericEq`,
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

`TextMatch` builds its filter under a configuration pinned in this crate,
`EqlMatch`. Stored values and queries both use it.

`EqlMatch` takes the 3-grams of the lower-cased text. A 3-gram is a run of
three characters, such as "mik" in "Mike". `EqlMatch` also takes each
two-letter word as one more token, whole. Each token sets `k = 6`
positions in a 2048-bit filter. Words are split on space, comma, semicolon,
colon, and exclamation mark.

The word token lets you store and search a two-letter surname such as "Ng".
`@@` with "ng" finds "Ng" and "Mike Ng", and not "Nguyen". A query asks for
its two-letter words only when the whole query is one two-letter word. A
query of three characters or more asks for its 3-grams alone. So "Mike Ng"
finds "Mike Ng" and "Mike Nguyen", and "san fr" finds "San Francisco".

A query's filter is a `QueryBloomFilter`, with the same JSON as
`BloomFilter`. A query is not a plain substring test. The word token adds
one token for each two-letter word in a stored value. The token is unique
to the word, so someone can tell the rows that contain "Ng" from the rows
that contain "Nguyen".

The configuration is part of the stored
format, so changing it means a new domain or payload version. A filter can
match a row that does not contain the query, so re-check after decrypting
where that matters. Write the stored column on the left, `col @@ query`: the
other order finds nothing until #1171 is fixed. Text that cuts no token
(empty strings, one letter) cannot be stored in a `TextMatch` column, and a
`TextMatchQuery` for it is refused too: one filter type builds both, and an
empty filter as a query would match every row.
`TextSearch` stores all three terms (`TextEq`'s `hm`, `TextOrd`'s `op` and
`TextMatch`'s `bf`). Text that cuts no token is stored with the empty
filter (`"bf": []`, the `SearchBloomFilter` field type): `=` and `<` find it
through `hm` and `op`, and no `@@` query does, because a query's filter is
never empty. (A `@@` between two stored values, which no producer builds, is
not a query: two stored empty filters match each other there, as in v3.) Its query carries only the term its operator reads: build it
through `TextSearchEqualityQuery` (`=`, `<>`), `TextSearchOrderQuery` (`<`,
`<=`, `>`, `>=`) or `TextSearchMatchQuery` (`@@`) and convert into
`TextSearchQuery`, and the by-name dispatch picks the one for the index that
answers the operator. So `=` and `<` work on such text, a match query on it
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

`Json` (`public.eql_v4_json`) stores a JSON document as one ciphertext, with
no index. Its plaintext is `v4::plaintext::JsonPlaintext`, which holds a
`serde_json::Value` and wipes it when it is dropped. `c` holds the document's
JSON text, sealed as one text leaf: the text `serde_json` writes, with no
whitespace. So the stored value shows the size of the document and nothing
else, where a `JsonSearch` document shows which rows have which paths. Key
order, whitespace and the spelling of a number are not kept. On decrypt the
text is parsed by Stack Encrypt's rules (64-bit integers or doubles, no
repeated member, valid Unicode), and a `c` that opens but does not hold a
document is `Error::OpenedType`. Nothing inside a `Json` value can be
queried: use `JsonSearch` for a document that is searched.

```rust
use eql_bindings::v4::{json::Json, plaintext::JsonPlaintext};
use eql_bindings::Identifier;
use serde_json::json;
use stack_encrypt::{DecryptFrom, EncryptInto, StackCipher};
use stack_kms::FakeDataKeySource;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local example only: these keys are held in memory, not in ZeroKMS.
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;
    let keyset = cipher.default_keyset();

    let column = Identifier::for_column("users", "profile")?;
    let profile = JsonPlaintext::from(json!({"name": "Ada", "tags": ["maths"]}));
    let stored: Json = profile
        .encrypt_into_with_context(&keyset, column.clone())
        .await?;
    // INSERT ... VALUES ($1::public.eql_v4_json), binding sqlx::types::Json(&stored)

    let opened = JsonPlaintext::decrypt_from_with_context(stored, &keyset, column).await?;
    assert_eq!(opened.value()["tags"][0], "maths");
    Ok(())
}
```

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

A text column with an equality term, from cipher setup through decryption:

```rust
use eql_bindings::v4::text::{TextEq, TextEqQuery};
use eql_bindings::Identifier;
use stack_encrypt::{DecryptFrom, EncryptInto, StackCipher};
use stack_kms::FakeDataKeySource;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local example only: these keys are held in memory, not in ZeroKMS.
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;
    let keyset = cipher.default_keyset();

    let column = Identifier::for_column("users", "email")?;
    let stored: TextEq = "alice@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column.clone())
        .await?;
    // The query for the same text carries the stored equality term.
    let query: TextEqQuery = "alice@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column.clone())
        .await?;
    assert_eq!(query.hm, stored.hm);

    let opened = String::decrypt_from_with_context(stored, &keyset, column).await?;
    assert_eq!(opened, "alice@example.com");
    Ok(())
}
```

The generated API docs of the `eql_bindings::encryption` module show the same
steps. That example is a program of its own
([source](src/encryption/example.rs)), which the encryption test crate runs
too: `cargo test -p eql-encryption-tests --test text_eq_example`.

Both identifier components must be nonempty. Encryption stores the identifier
in `i`; its table and column supply the ciphertext AAD, term context, and ZeroKMS
descriptor. The storage field names `c` and `hm` add no further context.
Decryption validates `i` before retrieving keys. Passing an expected identifier,
as above, also checks the destination. `String::decrypt_from(stored, &keyset)`
uses the stored identifier alone, so moving a complete payload with its
original `i` still opens.

For a database NULL, use an `Option` of the type. `None::<String>` encrypts
into `None::<TextEq>`. Nothing is stored. No key is requested.

Some types also encrypt from an `Option` of their plaintext, and seal a `None`
as a stored null. These are the types whose terms a null has: a storage type,
or a type with only an equality term.

The two forms are not read as each other. A sealed null read through
`Option<TextEq>` into an `Option<String>` is refused as the wrong type. To read
a sealed null, read it through `TextEq` into an `Option<String>`.

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

A typed query starts from a field of a derived record. The record derive
gives each field a field reference, such as `EncryptedUser::EMAIL`, with a method for
each operator the field's EQL type answers. The term that comes back is the
type's query twin, the value the `eql_v4.query_*` domain takes:

```rust
use eql_bindings::v4::text::{TextEq, TextMatch};
use stack_encrypt::op::{Probabilistic, Stats};
use stack_encrypt::{EncryptInto, EncryptTarget, StackCipher};
use stack_kms::FakeDataKeySource;

#[derive(zeroize::Zeroize)]
struct User {
    email: String,
    name: String,
}

// The record's scope names the table, and each field's name is its column.
#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: TextEq,   // i = {"t": "users", "c": "email"}
    name: TextMatch, // i = {"t": "users", "c": "name"}
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local example only: these keys are held in memory, not in ZeroKMS.
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;
    let keyset = cipher.default_keyset();

    let user = User {
        email: "alice@example.com".into(),
        name: "Alice Nguyen".into(),
    };
    let stored: EncryptedUser = user.encrypt_into(&keyset).await?;

    // A `TextEqQuery`.
    let query = EncryptedUser::EMAIL
        .eq("alice@example.com")
        .encrypt(&keyset)
        .await?;
    // WHERE email = $1::eql_v4.query_text_eq, binding sqlx::types::Json(&query)
    assert_eq!(query.i.t, "users");
    assert_eq!(query.i.c, "email");
    assert_eq!(query.hm, stored.email.hm);

    // A `MatchTwin<TextMatchQuery>`.
    let query = EncryptedUser::NAME.matches("ali").encrypt(&keyset).await?;
    // How many rows to fetch to expect 10 real matches in a million.
    let fetch = query
        .target_limit(10, &Stats::declared(1_000_000))
        .fetch_or(50);
    assert!(fetch >= 10);
    // WHERE name @@ $1::eql_v4.query_text_match LIMIT $2, binding `fetch`.
    // Then keep the decrypted rows that verify.
    assert!(query.verify("Alice Nguyen"));
    assert!(!query.verify("Bob Li"));
    Ok(())
}
```

| v4 type | Field reference method | Operator | Query term |
| --- | --- | --- | --- |
| `TextEq` | `eq` | `op::Eq` | `TextEqQuery` |
| `SmallintEq`, `IntegerEq`, `BigintEq`, `RealEq`, `DoubleEq` | `eq` | `op::Eq` | `SmallintEqQuery`, `IntegerEqQuery`, `BigintEqQuery`, `RealEqQuery`, `DoubleEqQuery` |
| `DateEq`, `TimestampEq`, `NumericEq` | `eq` | `op::Eq` | `DateEqQuery`, `TimestampEqQuery`, `NumericEqQuery` (from `v4::plaintext::Date`, `Timestamp`, `Decimal`) |
| `TextMatch` | `matches` | `op::Matches` | `MatchTwin<TextMatchQuery>` |
| `SmallintOrd`, `IntegerOrd`, `BigintOrd`, `RealOrd`, `DoubleOrd`, `DateOrd`, `TimestampOrd`, `NumericOrd`, and each `…OrdOpe` and `…OrdOre` | `lt`, `lte`, `gt`, `gte` | `op::Lt`, `op::Lte`, `op::Gt`, `op::Gte` | the type's twin: `IntegerOrdQuery`, `IntegerOrdOreQuery`, … |
| `TextOrd`, `TextOrdOpe`, `TextOrdOre` | `eq`, `lt`, `lte`, `gt`, `gte` | `op::Eq` and the orderings | `TextOrdQuery`, `TextOrdOpeQuery`, `TextOrdOreQuery` |
| `TextSearch`, `TextSearchOre` | `eq`, `lt`, `lte`, `gt`, `gte`, `matches` | `op::Eq`, the orderings and `op::Matches` | `TextSearchQuery`, `TextSearchOreQuery`, and a `MatchTwin` of one for `matches` |

`MatchTwin` serializes as the twin and adds `verify` and `target_limit`
under `EqlMatch`: a filter can match a row that does not hold the query's
text, so keep only the decrypted rows that verify. An exact query has no
`verify`. An operator a type does not answer does not compile: `.lt(..)` on
a `TextEq` field, or `.matches(..)` on an `IntegerEq` field. A field reference names
its field's type and no index, so a query cannot send another index's term,
such as the bare `Equality` term, which the type's SQL does not take. No
type answers `between` from a field reference, as no data plan answers it
for an EQL type.

A twin carries what its query domain requires. The twin of an ordered
type other than text carries its one order term (`op` or `ob`). A
`TextOrd` twin carries both its `hm` and its order term whatever the
operator, because `eql_v4.query_text_ord` requires both, so a field query
derives the two terms for the one value. It is refused, before any key is
requested, for text either index refuses: `TextOrdOre.eq(..)` of text that
ends in NUL or is too long for block ORE, as the data path refuses it. A
text search twin's terms are optional, so its query carries only the term
of the index that answers the operator: `hm` for `eq`, `op` or `ob` for an
ordering, `bf` for `matches`.

The query is derived under the field reference's label: the record's scope, then the
field's name (or its `identity`). That is the column the field stores in
`i`, so the query finds the values the record wrote, and the values the
type wrote on its own with
`value.encrypt_into_with_context(&keyset, Identifier::for_column("users", "email")?)`.
A field reference's label always has those two segments, so it always names a
column. The derive accepts only plain label segments. So a column whose
table or column name is not one, which `Identifier::for_column` accepts,
cannot be a record field, and cannot be queried this way: for instance a
name that starts with a digit, `-` or `b64:`, or one holding `/`, `(`, `)`,
or a control or invisible format character.
A record that lists a scope, such as a tenant, takes it on the query with
`.scope(..)`: see [EQL types as record fields](#eql-types-as-record-fields).
The query is the same bytes the data path derives for a field that names the
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

### EQL types as record fields

An EQL type can be a field of a Stack Encrypt record. The record derive gives
each field the record's scope and the field's name, and the EQL type stores
that pair as its column in `i`:

```rust
use eql_bindings::v4::{integer::IntegerOrd, json_tree::JsonTreeDocument, text::TextEq};
use serde_json::json;
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::{DecryptFrom, DecryptSource, EncryptInto, EncryptTarget, StackCipher};
use stack_kms::FakeDataKeySource;

#[derive(zeroize::Zeroize)]
struct Member {
    id: u64,
    email: String,
    age: i32,
    profile: JsonPlaintext,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Member, scope = "members")]
struct EncryptedMember {
    #[stash(passthrough)]
    id: u64,
    email: TextEq,             // i = {"t": "members", "c": "email"}
    age: IntegerOrd,           // i = {"t": "members", "c": "age"}
    profile: JsonTreeDocument, // i = {"t": "members", "c": "profile"}
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local example only: these keys are held in memory, not in ZeroKMS.
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;
    let keyset = cipher.default_keyset();

    let member = Member {
        id: 7,
        email: "alice@example.com".into(),
        age: 36,
        profile: JsonPlaintext::from(json!({"name": "Alice"})),
    };
    let stored: EncryptedMember = member.encrypt_into(&keyset).await?;
    assert_eq!(stored.email.i.t, "members");
    assert_eq!(stored.email.i.c, "email");

    // A query from the field reference carries the stored equality term.
    let query = EncryptedMember::EMAIL
        .eq("alice@example.com")
        .encrypt(&keyset)
        .await?;
    assert_eq!(query.hm, stored.email.hm);

    // An order query: an `IntegerOrdQuery`, bound as
    // WHERE age > $1::eql_v4.query_integer_ord.
    let older = EncryptedMember::AGE.gt(30).encrypt(&keyset).await?;
    assert_eq!(older.i, stored.age.i);
    // Its order term sorts below the stored age of 36.
    assert!(older.op < stored.age.op);

    let opened = Member::decrypt_from(stored, &keyset).await?;
    assert_eq!(opened.email, "alice@example.com");
    Ok(())
}
```

Each field writes the terms its type writes on its own under
`Identifier::for_column("members", <field>)`, and the terms a data plan that
names the type writes. On decrypt, each field's stored `i` must be its own
column, checked before any key is requested. So a renamed field does not
read the rows written under its old name. Keep the old name with
`#[stash(identity = "email")]`, as for a field of any other type.

A record can also list a scope or a binding, such as a tenant or a row ID.
The caller passes them as `Scope::new(tenant).bind(row)`. This record has
one EQL field, to keep the example short:

```rust
use eql_bindings::v4::text::TextEq;
use stack_encrypt::target::Scope;
use stack_encrypt::{DecryptFrom, DecryptSource, EncryptInto, EncryptTarget, StackCipher};
use stack_kms::FakeDataKeySource;

#[derive(zeroize::Zeroize)]
struct Member {
    id: u64,
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Member, scope = "members", scope(tenant: u64), bind(row: u128))]
struct EncryptedMember {
    #[stash(passthrough)]
    id: u64,
    email: TextEq, // i = {"t": "members", "c": "email"}
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local example only: these keys are held in memory, not in ZeroKMS.
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;
    let keyset = cipher.default_keyset();
    let tenant = 42u64;
    let row = 9u128;

    let member = Member {
        id: 7,
        email: "alice@example.com".into(),
    };
    let stored: EncryptedMember = member
        .encrypt_into_with_context(&keyset, Scope::new(tenant).bind(row))
        .await?;
    // `i` stores the table and the column, and not the tenant or the row.
    assert_eq!(stored.email.i.t, "members");
    assert_eq!(stored.email.i.c, "email");

    // A query supplies the scope, and no binding.
    let query = EncryptedMember::EMAIL
        .eq("alice@example.com")
        .scope(Scope::new(tenant))
        .encrypt(&keyset)
        .await?;
    assert_eq!(query.hm, stored.email.hm);

    // The reader supplies the scope and the binding again.
    let opened =
        Member::decrypt_from_with_context(stored, &keyset, Scope::new(tenant).bind(row)).await?;
    assert_eq!(opened.email, "alice@example.com");
    Ok(())
}
```

`i` stores the table and the column, and nothing a caller supplies. A field
of any other type uses the scope and the binding in the same way:

- the terms of the field derive under the column, then the scope. So a
  query supplies the scope, and finds only the values stored under it;
- a binding is in no query, so it does not change the terms;
- the ciphertext is sealed under the column, then the scope, then the
  binding. So the reader supplies the scope and the binding again, and a
  value does not open without them.

An EQL field of a record nested in another stores its own column in the same
way. The outer record's names come after the column in the field's context.

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
Rust declaration — the same one the typed `encrypt_into::<TextEq>` runs, so
the two paths produce the same identifier and equality term and open each
other's values. An unproducible name is refused with the table's reason; an
unknown one with "no such EQL type". Every type in the table is producible
today. A type that stores a JSON document (`Json`, `JsonSearch`) takes the
plaintext kind `json`: the document's UTF-8 JSON text, in a text or bytes
value, and it opens back to its text.

```rust
// Needs the `targets` feature.
use eql_bindings::encryption::targets;
use eql_bindings::v4::text::{TextEq, TextEqQuery};
use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::target::IndexSpec;
use stack_encrypt::{Label, StackCipher};
use stack_kms::FakeDataKeySource;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Local example only: these keys are held in memory, not in ZeroKMS.
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;
    let keyset = cipher.default_keyset();

    // The field's context: the table, then the column.
    let column = Label::new(["users", "email"])?;
    // The plaintext, as its transport frame. A frame is moved into the call
    // that uses it, and is not `Clone`, so each call is given its own.
    let email = || ValueFrame::of("alice@example.com");

    // Each call names the type, and returns the EQL value as JSON bytes.
    let stored: Vec<u8> = targets::encrypt("TextEq", &keyset, &column, email()?)?.await?;
    // A query also names the index that answers its operator.
    let index = IndexSpec::Equality;
    let probe: Vec<u8> = targets::query("TextEq", &index, &keyset, &column, email()?)?.await?;
    let stored_value: TextEq = serde_json::from_slice(&stored)?;
    let query: TextEqQuery = serde_json::from_slice(&probe)?;
    assert_eq!(query.hm, stored_value.hm);

    let opened: ValueFrame = targets::decrypt("TextEq", &cipher, &column, &stored)?.await?;
    assert_eq!(opened, email()?);
    Ok(())
}
```

The table and the dispatch are generated into `src/v4/targets.rs` beside
the v4 family modules (`mise run types:generate`), gated to the `targets`
feature, and drift-gated by the same parity tests. The same generator writes
the Go package `languages/golang/encrypt/eql` from the same rows
(`eql-codegen go-eql`, also under `types:generate` / `types:check`). The
engine's `TargetResolver` (stack-encrypt's `dynamic` module) is implemented
over this module by `encryption::EqlTargets`. A program that runs data plans
with EQL types passes `&EqlTargets` wherever the dynamic interface takes a
resolver, as the Go guest's `eql` build does. A data plan's scopes and
bindings reach the type through `EqlTargets`: the type runs under the
field's label, then those parts, and the EQL value stores the column alone,
as it does for a [record field](#eql-types-as-record-fields). A type is producible exactly
when its generated struct carries the `stack-encrypt` derives
(`ENCRYPTION_DOMAINS` in `eql-codegen`), because the dispatch runs the derived
declaration; `targets::targets()` lists them, each with `producible` and, when it is
`false`, the reason.

### Features

- `stack-encrypt`: the EQL v4 types (`eql_bindings::v4`) with Stack
  Encrypt's `EncryptTarget` and `DecryptSource`, for a Rust program that
  encrypts through `encrypt_into`. It builds Stack Encrypt with no default
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
