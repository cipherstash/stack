# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The EQL v4 `json_tree` family's types, `v4::json_tree`** (`stack-encrypt`
  feature). `JsonTreeDocument` is `public.eql_v4_json_tree`, `{v, i, h, sv,
  q}`: the document's entries, one per JSON node, and `q`, its containment
  projection, which the server compares with a needle by native `jsonb @>`.
  `JsonTreeEntry` is one entry as `->` and the subtree reads return it,
  `{s, c, x, p?, op?}` with the extractors' grafted fields,
  `JsonTreeQuery` the containment needle and `JsonTreeLeafQuery` the
  ordering operand at a path. `JsonTreeSubtree` collects a read's rows
  (`eql_v4.json_tree_subtree(doc, key.tokens(), budget)`) and opens to the
  value at the path as a `Value`, to `Option<Value>` (`None` where the row
  has no node there) or to one value per concrete path as a `Vec<Value>`;
  past the read's budget the server returns the sealed root instead, which
  opens to the same answer under the read's key: the rows are built
  with `JsonTreeSubtree::from_key(&key, rows)`, and there is no
  constructor without the key.
  An entry `->` returned opens through the selector that asked for it,
  `JsonTreeExtracted::from_selector(&selector, entry)`, which refuses an
  entry carrying another selector (`stack_encrypt::Error::JsonWrongEntry`),
  and a read's rows through the key that keyed it, which checks each row
  against the path the same way; `JsonTreeEntry` does not open on its own.
  The document is an `EncryptFrom<Value>` and `DecryptInto<Value>` target,
  the extracted entry and the subtree open through `DecryptInto`, and the needle and
  the ordering operand convert from Stack Encrypt's `JsonQuery` and
  `JsonLeafQuery`. `JsonTree::new(options)` is the `json_tree` layout under
  index options other than the defaults (a `Layout<Value>`, so a program
  seals with `keyset.run(JsonTree::new(options).encryption(), ..)`), such
  as the paths that carry an ordering term. The wire fields are typed apart
  from the v3 hex terms, and each names its text encoding:
  `JsonTreeSelector` (`s`, and the pairs of `q`), `JsonTreeTag` (`x` and `p`),
  `JsonTreeOrderingTerm` (`op`) and `JsonTreeKeyHeader` (`h`) hold an
  `encoding::Base64Text`, padded standard base64, and `JsonTreeCiphertext`
  (`c`) an `encoding::Base85Text`, RFC 1924 base85. Each encoding newtype
  is a guarantee that its text is in that encoding: the string inside is
  private, and a value is made only by `encode`, from bytes, or by
  deserializing, which decodes the text and refuses text that is not in the
  encoding (base85 whose final group is not the one `encode` writes
  included), so `decode` cannot fail. Both serialize as the bare string and
  render as `string` in TypeScript and JSON Schema.
- **The date, timestamp and numeric ordered types are producible**
  (`stack-encrypt` feature, #1236): `DateOrd`, `DateOrdOpe`, `DateOrdOre`,
  `TimestampOrd`, `TimestampOrdOpe`, `TimestampOrdOre`, `NumericOrd`,
  `NumericOrdOpe` and `NumericOrdOre`. A date orders by its day, a
  timestamp by the microsecond (truncated, as its equality term is) and a
  decimal by value, so `1.5` and `1.50` order as equal. Block ORE puts a
  date through ore-rs's fixed-width engine and a timestamp or decimal
  through its chained one.

### Changed

- **A v4 order term is Stack Encrypt's own, typed by its plaintext**
  (`stack-encrypt` feature). An `ob` field is
  `stack_encrypt::sem::OreBlockTerm<T>` and an `op` field
  `stack_encrypt::sem::OpeTerm<T>`, over the type's plaintext:
  `DateOrdOre::ob` is an `OreBlockTerm<Date>`, `IntegerOrd::op` an
  `OpeTerm<i32>`. Each is one lowercase hex string on the wire (`ob` was a
  one-element array) and is decoded through `from_bytes` when a payload is
  read, so an EQL v3 term, a term of the other scheme or a malformed one is
  refused there. `v4::terms` no longer re-exports v3's `OreBlock256` and
  `OpeCllw`; the generated `v4::terms::OreBlockHex` and `OpeHex` describe
  the JSON to TypeScript and JSON Schema, with the pattern the domain CHECKs
  require.

- **`v4::plaintext::Date`, `Timestamp`, `Decimal` and `RangeError` are
  Stack Encrypt's** (`stack_encrypt::value`), re-exported at the same
  path: the engine orders them, which it can only do for types of its own.
  Nothing a caller writes changes. The `chrono` and `rust_decimal`
  features now turn on Stack Encrypt's features of those names, and the
  crate no longer depends on `vitaminc-aead` directly.

- **Range query operands for `eql_v4.between`** (`stack-encrypt` feature).
  Every ordered v4 family has two: `IntegerRangeOreQuery` and
  `IntegerRangeOpeQuery`, `TextRangeOreQuery` and `TextRangeOpeQuery`, and so
  on for `smallint`, `bigint`, `date`, `timestamp`, `numeric`, `real` and
  `double`, listed by `v4::all_range_query()`. Each holds both bounds of one
  `BETWEEN`: each bound is the single-bound domain's `ob` (ORE,
  `OreBlockTerm`) or `op` (OPE, `OpeTerm`) value, in a `{v, i, lo, hi}`
  envelope, so a range binds as one parameter. The parameter must be cast to
  its exact range domain (`$1::eql_v4.query_integer_range_ore`); anything else
  fails with SQLSTATE 42725. They bind the
  `eql_v4.query_<family>_range_<ore|ope>` domains in the v4 SQL bundle. No
  range type derives Stack Encrypt's traits yet, because the ordered types
  they range over are not producible. There are no v3 range types.
- **Rust queries an EQL v4 field through Stack Encrypt's typed query chain**
  (`stack-encrypt` feature, #1238). `cipher.query(op::Eq, v).on(&plan)` on a
  plan for `TextEq`, `SmallintEq`, `IntegerEq`, `BigintEq`, `RealEq`,
  `DoubleEq`, `DateEq`, `TimestampEq` or `NumericEq`
  (`Plan::value::<S>().context("table/column").encrypt_into::<T>()`)
  returns the type's query twin (`TextEqQuery`, …), and
  `cipher.query(op::Matches, text).on(&plan)` on a plan for `TextMatch`
  returns a `MatchTwin<TextMatchQuery>`: the twin, which it serializes as,
  with `verify` and `target_limit` under `EqlMatch`. The query is the bytes
  the data path (`stack_encrypt::dynamic::query_term`) derives for the same
  field, and `verify` and `target_limit` answer as the data path's do.
  eql-codegen writes the `op::Answers` impls into `v4::answers`, which needs
  no `dynamic` layer and so not the `targets` feature, from each type's
  indexes, by the rule the data path answers an EQL type's operators
  with. A producible type whose twin carries an order term (`IntegerOrd`,
  `TextOrd`, …) answers nothing in the typed chain yet: the chain sends one
  index's term as the twin, and those twins need an order term, or several
  terms at once. The encryption tests hold that gap to exactly the ordered
  types, so query them through the data path for now. An operator a type
  does not answer, or another index named with `.via(..)`, does not
  compile. Each answering type is an
  `op::LabelledTarget`. The label must name the column, table then column,
  and the query must not be extended, or the awaited query is refused
  before any keyset is resolved, with a `QueryLabelError` in
  `Error::Other`. `eql_bindings::encryption::query` holds `TwinIndex`
  (Stack Encrypt's index, its query sent as the twin, for the twin's own
  plaintext only), `MatchTwin`, `QueryTwin` and `QueryLabelError`.
  `Hmac256` and `BloomFilter` now declare their indexes (`EncryptFrom::indexes`),
  so a type holding one declares the equality or match index, and `EqlMatch`
  implements `op::MatchCase` (case-insensitive).
- **`eql_bindings::v4` needs the `stack-encrypt` feature.** Only Stack
  Encrypt produces an EQL v4 value (ADR-0002), so the module is compiled with
  that feature alone, and its producible types derive `EncryptFrom` and
  `DecryptInto` with no attribute of their own gated on it.
- **A `targets` feature for the by-name dispatch.** `encryption::targets` and
  `v4::targets`, which name an EQL type at run time and take a `ValueFrame`,
  need `targets`, which turns on `stack-encrypt` and Stack Encrypt's
  `dynamic` feature. `stack-encrypt` alone builds Stack Encrypt with no
  default features and no `dynamic` layer, so a Rust program that encrypts
  the v4 types through `encrypt_as` no longer compiles it.
- **`IntegerEq`, `BigintEq`, `RealEq` and `DoubleEq` are producible**
  (`stack-encrypt` feature), from `i32`, `i64`, `f32` and `f64`. Their equality term follows ADR-0002's semantic
  baseline, so `=` compares as PostgreSQL's own integer and `float8 =` do:
  one term per integer value whatever its width, `-0.0 = 0.0` and
  `NaN = NaN`. The ciphertext keeps the exact value.
- **`Smallint` and `SmallintEq` are producible** (`stack-encrypt` feature),
  from `i16`. `SmallintEq`'s equality term is the integer one: a smallint
  and an integer or bigint of the same value under one column share it.
  The `date`, `timestamp` and `numeric` families say why they are still
  unproducible: the engine has their kinds, and their Rust plaintext types
  are not chosen yet.
- **`Date`, `DateEq`, `Timestamp`, `TimestampEq`, `Numeric` and `NumericEq`
  are producible** (`stack-encrypt` feature), from the new
  `v4::plaintext::Date` (an `i32` of days since 1970-01-01),
  `v4::plaintext::Timestamp` (`i64` Unix seconds and `u32` nanoseconds,
  UTC) and `v4::plaintext::Decimal` (an `i128` mantissa and a `u8` scale).
  Each is built range checked against vitaminc's ranges, refused with a
  `v4::plaintext::RangeError` that does not show the value, wiped on drop
  (`Zeroize`, `ZeroizeOnDrop`), and not `Copy`: chrono's and
  rust_decimal's types cannot be wiped, so the by-name dispatch could not
  hold them. The `chrono` and `rust_decimal` features add conversions to
  and from `NaiveDate`, `DateTime<Utc>` and rust_decimal's `Decimal`; a
  leap second is refused. `NumericEq`'s `=` normalises the scale and
  `TimestampEq`'s compares to the microsecond, truncating (never
  rounding) the nanoseconds below it. Their ordered types follow (see
  "The date, timestamp and numeric ordered types are producible").
- **The OPE-ordered types are producible** (`stack-encrypt` feature):
  `IntegerOrd`, `IntegerOrdOpe`, `SmallintOrd`, `SmallintOrdOpe`,
  `BigintOrd`, `BigintOrdOpe`, `RealOrd`, `RealOrdOpe`, `DoubleOrd`,
  `DoubleOrdOpe`, `TextOrd` and `TextOrdOpe`, from `i32`, `i16`, `i64`,
  `f32`, `f64` and `String`. Their `op` term is Stack
  Encrypt's OPE term over ADR-0002's order key, hex encoded, which EQL
  compares as bytes: floats order as PostgreSQL's `float8` does, and text by
  its fold (case and accents folded), so text order types keep `TextEq`'s
  equality term for `=`. `OpeCllw` implements `EncryptFrom` for any
  orderable plaintext. Their query twins carry one bound, so the engine
  answers `<`, `<=`, `>` and `>=` (and `=` on text) through them, not
  `BETWEEN`.
- **`TextSearch` is producible** (`stack-encrypt` feature), from `String`.
  The stored value carries `TextEq`'s `hm`, `TextOrd`'s `op` and
  `TextMatch`'s `bf`. Text too short for a 3-gram (an empty string, a
  two-letter code) is stored with the empty filter, `"bf": []`, where
  `TextMatch` refuses it: `=` and `<` find the row through `hm` and `op`,
  and no `@@` query does (a `@@` between two stored values is not a query,
  and two stored empty filters match each other there, as in v3). Its `bf`
  field is the new
  `v4::terms::SearchBloomFilter` (as is `TextSearchOre`'s), whose JSON and
  JSON Schema are `BloomFilter`'s and which takes the empty filter;
  `TextMatch` and every query keep `BloomFilter`, which refuses it. Its
  query is built per index, through
  `TextSearchEqualityQuery`, `TextSearchOrderQuery` or
  `TextSearchMatchQuery` (each `EncryptFrom<String>` and
  `Into<TextSearchQuery>`), so it carries only the term its operator reads:
  `=` and `<` on two-letter text work, and a match query on it is refused.
  The by-name dispatch picks the projection for the index it is handed.
- **The block ORE types are producible** (`stack-encrypt` feature):
  `IntegerOrdOre`, `SmallintOrdOre`, `BigintOrdOre`, `RealOrdOre` and
  `DoubleOrdOre` from `i32`, `i16`, `i64`, `f32` and `f64`, and `TextOrdOre` and `TextSearchOre` from
  `String`. Their `ob` term is Stack Encrypt's block ORE term (ore-rs's
  6-bit fixed-width scheme for the numbers, its chained scheme for text):
  one element, the hex of the whole ciphertext. `OreBlock256` implements
  `EncryptFrom` for any orderable plaintext and never decrypts. This is not
  EQL v3's `ob` (cipherstash-client's 8-bit blocks, up to six per text
  value), and only EQL v4's comparator, `compare_ore_block_v2_term`, reads
  it. Every term carries a random nonce, so a query's `ob` never equals the
  stored one; the comparator orders them. A query carries the full
  ciphertext. `TextSearchOre` follows `TextSearch`: its query carries only
  the term its operator reads. Text whose fold is longer than 1023 bytes or
  ends in NUL has no block ORE term and is refused. In the target table an
  `ob` term is the index `ore_block`, not `ore`, which is CLLW ORE.
- **`encryption::targets::query` takes the index that answers the query's
  operator** (`targets` feature), an `&IndexSpec` after the name, as Stack
  Encrypt's `TargetResolver::query` hands it over. An index the type does
  not carry is refused with `TargetError::NoIndex`, before anything is
  derived.
- **`Target::match_options`** (`targets` feature): the options a type's
  match index is built under, `EqlMatch`'s, for a type that carries one
  (`TextMatch`), and `None` otherwise. Stack Encrypt answers `matches`
  through the type with them, cutting the query's tokens for `verify` as the
  stored filter was cut.
- **EQL types as plan field targets, by name** (`targets` feature).
  `eql_bindings::encryption::targets` holds a catalog-generated table
  (`targets()`) of every EQL type a Stack Encrypt data plan may name as a
  field target — name, family, suffix, plaintext `ValueKind`, SQL domain,
  indexes, query twin, and whether the engine can produce it today with the
  reason when not — serializable as the guest's `se_targets` export, and
  `encrypt` / `decrypt` / `query` entry points that dispatch on the name and
  run the type's own `EncryptFrom` / `DecryptInto` plan, resolving to the EQL
  value's JSON bytes through the engine's `Pending`. The plaintext crosses as
  Stack Encrypt's `dynamic::ValueFrame`, one value as its transport frame:
  `encrypt` and `query` take one, `decrypt` resolves to one, and the
  `Plaintext` trait reads a type's plaintext out of a frame (`from_frame`,
  which walks the frame into the type's own decrypt sink once its kind is
  checked) and writes it back (`into_frame`), so no value tree holds it.
  Both copies of the plaintext they make are wiped: the one read out of the
  frame when `encrypt` returns, and the opened text once `into_frame` has
  framed it (`eql-encryption-tests`' `heap_hygiene` holds every text type's
  encrypt, decrypt and query to that under an allocator that fails on an
  unwiped free). `Identifier::from_label`
  reads a two-segment plan label as the column identifier. `TextEq` is the
  one producible type; every other name is refused with its reason.

- **Scalar query-operand bindings.** Every term-bearing scalar
  domain now has a generated query twin — `IntegerEqQuery`, `IntegerOrdOpeQuery`,
  `TextSearchQuery`, … — the **enveloped term-only** operand `{v, i, <terms>}`
  (envelope minus the ciphertext `c`) for its `eql_v3.query_<name>` query
  domain, with matching TypeScript bindings (`bindings/v3/*Query.ts`) and JSON
  Schemas (`schema/v3/query_<name>.json`). Storage-only domains (no operators)
  get no twin. `QueryPayload` is now catalog-generated — a variant per query
  twin plus the SteVec containment needle — superseding the hand-written
  single-variant enum. A new `all_query()` inventory exposes the query twins
  separately from `all()` (which stays the stored + SteVec conversion-target
  inventory).

### Breaking

- **`v4::text::TextSearchQuery` and `TextSearchOreQuery` hold each term as
  an `Option`**, left out of the JSON when `None`, to match EQL v4's
  `query_text_search` and `query_text_search_ore`, which now take any one
  of their terms (ADR-0002, amended 2026-10-19). `pub hm: Hmac256` is now
  `pub hm: Option<Hmac256>`, and likewise `op`/`ob` and `bf`: code that
  builds one of these structs wraps each term in `Some`, code that reads
  one handles `None`, and a JSON operand missing a term now deserializes
  where it was refused. `TextSearch` and `TextSearchOre`'s `bf` is
  `SearchBloomFilter`, not `BloomFilter` (`.0` reaches the `BloomFilter`).
  No published release of this crate has the `v4` module (3.0.6 does not),
  so this breaks only code built against unreleased sources; the v3 twins
  are unchanged, as cipherstash-client's query carries every term.

### Changed

- **`TextEq` and `TextEqQuery` compare text in Unicode 16 NFC**
  (`stack-encrypt` feature). Their `hm` is Stack Encrypt's equality term,
  which now derives through `vitaminc-normalize`: `café` written with a
  precomposed `é` and with `e` and a combining accent is one value, and
  text holding a code point unassigned in Unicode 16 is refused, when it is
  stored as well as when it is queried. Case and
  whitespace are kept. Every `hm` changes bytes; no stored value existed to
  keep. `Hmac256` encrypts from any vitaminc `Encrypt` where it took a
  `PrfValue`, and the feature no longer depends on `vitaminc-prf`.

- **The `stack-encrypt` feature builds on vitaminc ADR 0001.**
  `encryption::targets` takes `ValueFrame` and `ValueKind` from
  `stack_encrypt::dynamic` (the `targets` feature turns on stack-encrypt's
  `dynamic` feature) in place of `vitaminc-aead-value`, which is gone, and the
  `Ciphertext` target takes any vitaminc `Encrypt` plaintext and opens into any
  `Decrypt + Send` type, as stack-encrypt's own targets do.

- **Query-operand domain names switched to the `query_<name>` prefix, homed
  in the `eql_v3` schema.** The SQL domain names carried by the
  query twins — in `DomainType::sql_domain`, the names `QueryPayload::parse`
  accepts, and the exported JSON Schema file names — are now `query_<name>` /
  `eql_v3.query_<name>` (e.g. `query_integer_eq`), and the SteVec containment
  needle is `eql_v3.query_jsonb` (was `public.jsonb_query`).
  `DomainType::domain` now strips whichever schema qualifies `sql_domain`
  (`public.` for column domains, `eql_v3.` for query operands) instead of
  assuming `public.`. Matches the renamed/relocated SQL surface — query
  operands are never column types, so they leave the `public` column-type
  namespace; supersedes the `public.<name>_query` naming shipped only in
  3.0.0 pre-releases.
- **`from_v2_query` / `from_v2_query_typed` now convert scalar query targets.**
  A term-bearing scalar target hoists the v2 payload's required terms into the
  `{v: 3, i, <terms>}` operand for its `query_<name>` domain (dropping the
  stored `c`/`k`; `bf` reinterpreted to signed `smallint[]`), validated through
  the generated `QueryPayload`. Storage-only scalar targets still return
  `UnsupportedQueryTarget`. Previously every scalar query target failed closed.

## [0.4.2] - 2026-07-03

### Fixed

- Compiling the crate no longer emits ts-rs's "failed to parse serde
  attribute" warning for `skip_serializing_if` on `SteVecEntry.a` (the
  `no-serde-warnings` feature is enabled). The attribute was always ignored
  by design — TS optionality is declared explicitly with
  `#[ts(optional = nullable)]` — and the emitted TS/JSON is byte-identical.

## [0.4.1] - 2026-07-03

### Fixed

- The `from_v2_query_typed` rustdoc links only public items, fixing the
  `private_intra_doc_links` lint on docs.rs builds. No API changes.

## [0.4.0] - 2026-07-03

### Added

- `QueryPayload` — a hand-written enum spanning every v3 QUERY payload shape.
  Today that is exactly one variant: `SteVec(SteVecQuery)`, the jsonb
  containment needle. The single-term scalar query variants (an Ore / Ope /
  Bloom / Hm term value) are deliberately absent until the eql-mapper
  redesign defines a v3 scalar-query wire shape — fail-closed, no invented
  shapes. Serialize-only (`#[serde(untagged)]` — the wire form is exactly the
  inner type's) and constructed only from a known domain
  (`QueryPayload::parse`), never inferred from bytes. No ts-rs/schemars
  derives: the enum adds no wire shape of its own, so the exported TS /
  JSON-Schema artifacts are unchanged.
- `from_v2_query_typed(&Value, TargetDomain) -> Result<QueryPayload,
  FromV2Error>` — the typed counterpart to `from_v2_query`, sharing its
  conversion core and performing the single strict parse as parse-and-keep
  instead of validate-and-discard. `from_v2_query -> Value` is unchanged, and
  scalar targets still fail with `UnsupportedQueryTarget` on both entry
  points.

## [0.3.0] - 2026-07-03

### Added

- `DomainPayload` — a catalog-generated enum spanning every stored-payload
  domain type (all scalar binding structs plus `SteVecDocument`), emitted by
  eql-codegen so it cannot drift when the catalog grows a domain.
  Serialize-only (`#[serde(untagged)]` — the wire form is exactly the inner
  struct's) and constructed only from a known `TargetDomain`, never inferred
  from bytes (cross-token payloads are byte-identical on the wire).
- `from_v2_typed(&Value, TargetDomain) -> Result<DomainPayload, FromV2Error>`
  — the typed counterpart to `from_v2`, sharing its conversion core and
  performing the single strict parse as parse-and-keep instead of
  validate-and-discard. `from_v2 -> Value` is unchanged.

## [0.2.0] - 2026-07-03

### Changed

- **BREAKING**: the EQL envelope version is now `v: 3` (was `v: 2`) —
  `EQL_SCHEMA_VERSION`, the `SchemaVersion` newtype, the emitted TypeScript
  alias, and the JSON Schema `const` accept exactly `3`, matching the
  `eql_v3` domain CHECKs.

### Added

- `from_v2` — EQL v2.3 → v3 wire payload conversion: `from_v2(&Value,
  TargetDomain)` for storage payloads (fail-closed on missing terms, drops
  the v2 `k` discriminator, strict-parses through the target binding type),
  `from_v2_query` for jsonb containment needles, and `is_v3_payload` for
  envelope sniffing. Zero cipherstash-client dependency.
- SteVec (encrypted JSONB) document surface: `SteVecDocument` (carrying the
  `k: "sv"` form discriminator), entry/query types, and the `OreCllw` /
  `Selector` term newtypes, with generated inventory, TypeScript bindings,
  and JSON Schemas.
- CLLW-OPE ordering term: the `OpeCllw` newtype (`op` wire key) and the
  `<T>OrdOpe` binding types for every ordered scalar family.
- `TargetDomain::parse` resolving domain names via the catalog-generated
  inventory; `term_json_keys` / `parse_value` threaded through `DomainType`.
