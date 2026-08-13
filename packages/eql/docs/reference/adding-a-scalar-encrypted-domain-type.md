# Adding a Scalar Encrypted-Domain Type

The one reference for adding a scalar encrypted-domain type (`integer`, `smallint`,
`bigint`, `date`, `timestamp`, `numeric`, `real`, `double`, and future
scalars). The **top half** (§§1–4) is the path you
follow to add a type; the **reference half** (§§5–8) is the detail behind it —
the generated surface, its invariants, and how the generator itself works.
Read top-down to ship a type; drop into the reference half when something
breaks or you need the *why*.

A scalar encrypted-domain type is a family of concrete `jsonb` domains in the
**`public`** schema (`public.<token>`, `public.<token>_eq`,
`public.<token>_ord`, …). The domains deliberately live in `public`, **not**
`eql_v3`, so that application columns typed as an encrypted domain survive an
uninstall: `DROP SCHEMA eql_v3 CASCADE` does **not** drop them. Their
extractors, comparison wrappers, and MIN/MAX
aggregates — the callable surface — do live in `eql_v3`; the searchable-encrypted-metadata (SEM)
index-term types they return (`eql_v3_internal.hmac_256`,
`eql_v3_internal.ore_block_256`, `eql_v3_internal.ope_cllw`) live in the
**`eql_v3_internal`** schema — hand-written under
`src/v3/sem/`. The whole v3 surface is self-contained: it owns every type it
needs and is fully self-contained (CI gates this via `mise run test:self_contained_v3`).

The whole SQL surface is **generated** from a single Rust source of truth: the
`CATALOG` const in [`crates/eql-domains/src/lib.rs`](../../crates/eql-domains/src/lib.rs),
rendered by the [`eql-codegen`](../../crates/eql-codegen/) crate. There is no
TOML manifest and no Python — adding a type is adding one `DomainFamily` row,
validated by the compiler plus catalog `#[test]`s. The reference type is
`public.eql_v3_integer`; `public.eql_v3_text` is the worked non-integer example (ordered +
equality + a `match` capability via the `Bloom` term); `public.eql_v3_boolean` is the
worked **storage-only / encryption-only** example (a single term-less domain, no
searchable surface — see §8). **`jsonb` is a mixed family**: its searchable
SteVec domains stay hand-written and out of scope, but its ciphertext-only
storage domain `public.eql_v3_json` **is** materialized here like any
storage-only scalar (see §7).

---

## 1. TL;DR — the one path

To add a scalar type `<T>` (e.g. a hypothetical `uuid`), with Rust type `<R>`
(e.g. `uuid::Uuid`):

1. **Add a `DomainFamily` row to `eql_domains::CATALOG`** — just `name` +
   `domains` — plus a matching `TypeFixtures` record (carrying the `kind` and the
   plaintext fixture `values`) in the `fixtures` module (§2). If the type needs a
   new scalar width, add a `ScalarKind` variant first; if it needs new term
   behaviour, that goes in the `Term` enum's `impl`, never in catalog data.
2. **Materialise the value list** — `int_values!(<T_UPPER>_VALUES, <R>, <T_UPPER>_FIXTURES);`
   next to `CATALOG`, pinned by a `values_tests` assertion (§2). This is the
   single source the SQLx matrix reads; there is no generated `<T>_values.rs`.
3. **Wire the SQLx matrix oracle** — for an integer type, copy the two small
   registrations from the `integer` reference; a non-integer (string-backed) type
   needs a third (`scalar_domains.rs`), and `date`/`text` are the references
   there (§3).
4. **Regenerate** — `cargo run -p eql-codegen` (or just `mise run build`, which
   runs the generator first). One run regenerates *every* catalog type; there is
   no per-type codegen task. The generated `*_{types,functions,operators,aggregates}.sql`
   are committed in place under `src/v3/scalars/<T>/` — regenerate and commit the
   SQL diff alongside the catalog change.
   - **Ordering is resolved by the codegen — you do nothing.** `eql-codegen order`
     walks the whole `src/v3` surface once and topologically sorts it from the
     `-- REQUIRE:` edges every file declares (name-sorted tie-break, cycle- and
     dangling-target-checked); `tasks/build.sh` concatenates the files in that
     order. Generated and hand-written files are ordered together — there is no
     separate generated block, so a generated file cannot fall between the two.
     Adding a catalog row needs no `-- REQUIRE:` edits to any generated file: the
     renderers emit each file's edges. Only hand-written files under `src/v3/`
     (SEM types, `jsonb/`, `schema.sql`, `crypto.sql`, `common.sql`,
     `scalars/functions.sql`, `lint/lints.sql`, `*_extensions.sql`) carry
     authored `-- REQUIRE:` edges.
   - The catalog row ALSO drives the **Rust payload bindings**: `eql-codegen
     bindings` (run first by `mise run types:generate`) regenerates the
     committed `crates/eql-bindings/src/v3/<family>.rs` struct + `DomainType`
     impl and its `inventory.rs`/`all()` entry (a two-line catalog-derived
     struct doc — a summary line plus an operators/required-keys detail line, no
     field docs), and the `ts-rs`/`schemars` derives then emit the committed
     `crates/eql-bindings/bindings/v3/*.ts` + `crates/eql-bindings/schema/v3/*.json`. Unlike the SQL these `.rs` ARE
     committed (`// @generated`), so run `mise run types:generate` and commit
     the result; `mise run types:check` is the drift gate. For a new *domain* in
     an existing family `mod.rs` is untouched, but a new *family* needs a
     one-line `pub mod <family>;` added to the hand-written `mod.rs` — and any
     non-derivable caller caveat (e.g. a security note) belongs in the `mod.rs`
     doc, never the generated family file.
5. **Snapshot the matrix inventory and commit the generated SQL files** —
   `mise run test:matrix:inventory` (§3), and commit the regenerated per-type SQL
   files under `src/v3/scalars/<T>/` (every catalog type must have them — §4).
6. **Verify** — `mise run test:codegen`, the relevant SQLx suites, and the
   PostgreSQL matrix (§4).

Things you do **not** do:

- **Don't hand-edit generated SQL.** `*_types.sql` / `*_functions.sql` /
  `*_operators.sql` / `*_aggregates.sql` are committed in place under
  `src/v3/scalars/<T>/`, but the catalog plus the renderers are the source of
  truth. Change the catalog and rebuild, then commit the regenerated SQL —
  never edit the generated files directly.
- **Don't edit `mise.toml`, the CI workflow, `pin_search_path_v3.sql`, or
  `splinter.sh`** for an ordinary type — they recognise the generated surface
  intrinsically (§5, §6). The exception is a brand-new *term* whose extractor
  has a new name (§5).

Hand-written SQL beyond the fixed surface goes in
`src/v3/scalars/<T>/<T>_extensions.sql` with explicit `-- REQUIRE:` edges
— and **that file IS committed** (§5).

---

## 2. The catalog row (`DomainFamily`)

A scalar type is one `DomainFamily` row in
[`crates/eql-domains/src/lib.rs`](../../crates/eql-domains/src/lib.rs), paired
with a `TypeFixtures` record in
[`crates/eql-domains/src/fixtures/record.rs`](../../crates/eql-domains/src/fixtures/record.rs):

```rust
// The structural catalog row — name + domains only:
const INTEGER: DomainFamily = DomainFamily {
    name: "integer",
    domains: ORDERED_INT_DOMAINS, // storage, _eq (hm), _ord_ore (ore), _ord (ope), _ord_ope (ope)
};

// The fixture-layer record — kind + plaintext values — joined back to the
// catalog row by `family.name`:
pub const INTEGER_FIXTURES: TypeFixtures = TypeFixtures {
    family: &crate::INTEGER,
    kind: ScalarKind::I32,
    values: fixtures!(int i32;
        Min, N(-100), N(-1), Zero, N(1), N(2), N(5), N(10), N(17), N(25),
        N(42), N(50), N(100), N(250), N(1000), N(9999), Max),
};
```

`DomainFamily` carries only **`name`** and **`domains`**; the **`kind`** and
plaintext **`values`** are a fixture-layer concern that lives on the paired
`TypeFixtures` record, not on `DomainFamily`. A compile-time `const _` parity
block in `record.rs` enforces the 1:1 — every `CATALOG` row has exactly one
`TypeFixtures` (same order) carrying the right `kind`. All are otherwise enforced
by the type system and the catalog `#[test]`s rather than a runtime validator:

- **`name`** (on `DomainFamily`) — the type name (`integer`); supplies `<T>`
  everywhere. Each domain's full name is the family `name` + `_` + the domain
  `name` (`DomainFamily::domain_name`); codegen owns the `_` join
  (`Domain::full_name`), and an empty domain `name` yields the bare family name.
  Pinned by `every_domain_name_starts_with_its_family_name`.
- **`domains`** (on `DomainFamily`) — a non-empty `&[Domain]` (pinned by
  `every_type_has_at_least_one_domain`), each a bare `name` + the fixed `&[Term]` it
  carries + a `shape` (always `Shape::Scalar` for a scalar family;
  `Shape::SteVec` exists only for the hand-written `json` document domains).
  The storage domain is `name: ""` with no terms. The **ordered-numeric** shape
  (`ORDERED_INT_DOMAINS`) is: `eq => [Term::Hm]`; `ord` and
  `ord_ope => [Term::Ope]`; `ord_ore => [Term::Ore]`. That
  ordering-term-only rule is admissible **iff ordering-term equality is
  lossless for the kind** — the term is deterministic *and* injective, so term
  equality exactly mirrors plaintext equality. That holds for every
  numeric/date/timestamp kind, which is why their generated `=` may inline to
  `ord_term(a) = ord_term(b)` (`integer_ord_functions.sql`). For a
  **non-lossless** kind — `text`, and any future string-like scalar — every
  eq-capable domain must **lead with `Hm`** (`TEXT_DOMAINS`: `ord` and
  `ord_ope => [Term::Hm, Term::Ope]`; `ord_ore => [Term::Hm, Term::Ore]`), so
  `=`/`<>` resolve through `eq_term` (exact HMAC, `text_ord_functions.sql`) and
  never the ordering term — otherwise the generated `=` silently returns wrong
  answers for plaintexts whose ordering terms don't faithfully mirror
  equality. A contributor adding a new string-like scalar must follow the
  `text` shape. A `Domain` declares nothing else — no
  extractor names, no operator lists, no REQUIRE edges. Every behavioural fact
  comes from the `Term` enum.
- **`kind`** (on the `TypeFixtures` record) — a `ScalarKind` (`I16` / `I32` /
  `I64` / `Numeric` / `Text` / `Jsonb` / `Date` / `Timestamp` / `Bool` / `F32` /
  `F64`), carrying the Rust type name. Only the
  integer kinds have an
  i128 range with `Min`/`Max`/`Zero` sentinels: those bounded accessors
  (`min_symbol`/`max_symbol`/`zero_symbol`/`min_value`/`max_value`) live on the
  total `BoundedIntKind` sub-enum, reached via `ScalarKind::as_bounded_int() ->
  Option<BoundedIntKind>`. Non-integer kinds
  (`Numeric`/`Text`/`Jsonb`/`Bool`/`F32`/`F64`/`Date`/`Timestamp`)
  return `None` and simply have no bounded accessor — misuse is a compile error,
  not a runtime panic. **If `<T>` needs a new fixed-width integer, add a
  `BoundedIntKind` variant** (rust-type name, `MIN`/`MAX`/zero symbols, bounds)
  plus its `ScalarKind` variant and `as_bounded_int` arm, with unit tests over
  the `impl` methods.
- **`values`** (on the `TypeFixtures` record) — the type's plaintext fixture
  list (see below).

**Terms** are fixed by the `Term` enum (declared in
`crates/eql-domains/src/lib.rs`; its `impl` methods live in
`crates/eql-domains/src/term.rs`). The
`json_key` / `extractor` / `ctor` values are the cross-schema SQL contract (the
Returns column below is `eql_v3_internal.` + `ctor` — SEM index-term types live
in the internal schema) — changing one is a generated-SQL
behaviour change, not a refactor:

| Term    | JSON key | Extractor      | Returns                          | Operators                  |
| ------- | -------- | -------------- | -------------------------------- | -------------------------- |
| `Hm`    | `hm`     | `eq_term`      | `eql_v3_internal.hmac_256`       | `=` `<>`                   |
| `Ore`   | `ob`     | `ord_term_ore`     | `eql_v3_internal.ore_block_256`  | `=` `<>` `<` `<=` `>` `>=` |
| `Bloom` | `bf`     | `match_term`   | `eql_v3_internal.bloom_filter`   | `@@`                       |
| `Ope`   | `op`     | `ord_term` | `eql_v3_internal.ope_cllw`       | `=` `<>` `<` `<=` `>` `>=` |

(`Ope` is the CLLW-OPE term: a hex-encoded, order-preserving ciphertext whose
SEM type reduces comparison to native bytea ordering after hex-decode — no
custom comparison protocol, unlike `Ore`'s N-block protocol. Its extractor is
deliberately NOT `ord_term_ore`: two terms sharing an extractor name collapse in
`dedupe_terms_by(Term::extractor)`, so a mixed `[Ore, Ope]` domain would lose
one extractor.)

A type that needs a non-ORE equality term on an ordered domain needs a **new
`Term`**, not a catalog flag. Adding a term is a code change to the `Term`
enum's `impl` methods in `crates/eql-domains/src/term.rs` (`json_key`,
`extractor`, `ctor`, `binding_newtype`, `role`,
`operators`, `requires`) with matching `#[test]`s (`term_tests` /
`term_helper_tests`) — never a free-form catalog field.

**Non-empty `ob` invariant (ORE-bearing domains).** Any domain whose terms
include `Term::Ore` (`_ord_ore`, and text `_search`) automatically
emits an extra `CHECK` requiring `ob` to be a non-empty array
(`jsonb_array_length(VALUE -> 'ob') > 0`). An empty ORE term (`ob: []`) is only
ever produced by encrypting the empty string into an ordered column, and is
rejected at the boundary rather than ordered (issue #262). This is emitted from
the catalog by the codegen renderer (the `nonempty_array_keys` field on
`DomainBlock` in `crates/eql-codegen/src/context.rs`, populated from
`Term::nonempty_array_keys`, which filters on the per-term
`Term::nonempty_array_key()` — `Some("ob")` only for `Term::Ore`), not
hand-added — a new ORE-bearing scalar gets it for free.

The invariant is ORE-specific. `Term::Ope` has no such failure mode: encrypting
`""` yields a well-formed one-byte `op` term that sorts before every non-empty
term, so the OPE-backed `_ord` / `_ord_ope` domains accept the empty string and
order it correctly. `Term::Ope.nonempty_array_key()` is `None`.

**Twins.** `integer_ord` and `integer_ord_ope` both carry `&[Term::Ope]`. The
generator emits them as independent domains with byte-identical SQL modulo type
name (`ordered_files_byte_identical_modulo_typename`). Twins let callers choose
a name that documents intent ("ordered, regardless of mechanism" vs "ordered via
CLLW-OPE") without committing to one term family in a future migration.
`integer_ord_ore` is NOT a twin of these — it carries `&[Term::Ore]`, so its
extractor, SEM type, and CHECK all differ.

**Order is significant.** The generator iterates `CATALOG` in order (driving
generation order), and iterates each spec's `domains` slice in order — that
order shows up in the generated `<token>_types.sql` `DO` block. Order the slice
the way you want the output to read.

### Fixtures — single-sourcing the value list

The `TypeFixtures` record's `values` field is an ordered `&[Fixture]` — the
single source of truth
for the type's plaintext list, consumed by both the SQLx fixture generator and
the matrix oracle. A `Fixture` is value-kind tagged: `Min` / `Max` / `Zero` (the
integer matrix pivots, resolved per-kind), `Int(i128)` (an integer literal), and
`Numeric` / `Text` / `Jsonb` / `Date` / `Timestamp` / `Float` string variants
(plus a `Bool` variant for the storage-only `boolean` scalar). The
`fixtures!` macro
range-checks each `Int` literal against the kind at compile time (`N(-40000)`
for an `i16` kind does not compile):

```rust
// the `values:` expression of INTEGER_FIXTURES (a `TypeFixtures`):
values: fixtures!(int i32;
    Min, N(-100), N(-1), Zero, N(1), N(2), N(5), N(10), N(17), N(25),
    N(42), N(50), N(100), N(250), N(1000), N(9999), Max),
```

Catalog `#[test]`s enforce a **distinct-plaintext contract** plus the
matrix-pivot requirement:

- `fixture_values_are_distinct_by_resolved_number` rejects duplicates against
  the *resolved* value, so both copy-paste dups and sentinel/literal aliases
  (`Min` alongside the same number) fail;
- `fixtures_include_min_max_and_zero` requires `Min`, `Max`, and zero for
  integer kinds — the matrix uses those three as comparison pivots and fetches
  each one's ciphertext from the fixture via `fetch_fixture_payload`, which fails
  loudly if the row is absent;
- `every_fixture_value_is_within_kind_bounds` keeps every resolved value in
  range.

These run at compile/test time rather than at generation time.
Beyond the pivots, choose values so range operators produce distinguishable
result counts, include useful boundaries, and cover omitted-term negative cases.

The plaintext list is **not** rendered to a generated file. The `int_values!`
macro (in `crates/eql-domains/src/fixtures/values.rs`) materialises a `Fixture` list into a typed `pub const
<T_UPPER>_VALUES: &[<rust_type>]` at compile time (`INTEGER_VALUES`, `SMALLINT_VALUES`):

```rust
int_values!(INTEGER_VALUES, i32, INTEGER_FIXTURES);
```

Both consumers reference that single symbol — the fixture generator
(`fixtures::eql_v3_<T>::spec`) and the matrix oracle's `fixture_values()` — so
the oracle cannot drift from the values the generator encrypts. There is no
committed `<T>_values.rs`: a Rust source of truth does not round-trip through
generated Rust. Pin the exact materialised list with a `values_tests` assertion.

The materialiser macro differs by kind: `int_values!` for integers, `text_values!`
for `text` (a `Fixture::Text(&'static str)` is already `const`, so it too
materialises a typed `&'static` slice), and **none** for the chrono-backed
temporal kinds (`date`/`timestamp`) — chrono constructors are not `const`, so
there is no `<T>_VALUES` const; the SQLx harness parses the catalog strings into a
`LazyLock<Vec<_>>` instead (§"Temporal kinds" and `scalar_domains.rs`).

### Temporal kinds — string-backed fixtures and the pivot trait

A **temporal** scalar (`date` is the *ordered* temporal reference) is *ordered
but non-integer*, so it diverges from the integer path in three places — all in
the catalog/harness, never the SQL codegen (domains stay jsonb-backed and
token-driven). **`timestamp` follows the same *ordered* temporal path as
`date`** — its catalog row carries the full ordered domain set (storage + `_eq` +
`_ord`/`_ord_ore`). cipherstash encrypts `Plaintext::Timestamp` at native
12-block ORE width, and the `eql_v3` comparator
(`eql_v3_internal.compare_ore_block_256_terms`) now derives its block count `N` from the
term length instead of assuming 8, so the 12-block ciphertexts order correctly
(see the N-block ORE comparator entry in the `CHANGELOG.md` and the catalog
comment on the `TIMESTAMP` spec). Its value-wiring is the temporal path below;
the only practical difference from `date` is that values are UTC-normalized. The
three divergences (for the ordered `date`):

- **String-backed fixtures.** `eql-domains` stays zero-dependency, so the
  catalog stores ISO strings (`Fixture::Date("1970-01-01")`), not `chrono`
  values. There is **no** `int_values!` / `<T>_VALUES` const for a temporal kind
  (chrono constructors are not `const`). The SQLx harness parses the catalog
  strings into a `LazyLock<Vec<chrono::NaiveDate>>` and exposes them via a
  `date_values()` accessor; `ScalarType::fixture_values()` returns a borrow of
  that. The fixtures must include the three pivot plaintexts verbatim — for
  `date`: `"1900-01-01"` (min), `"1970-01-01"` (mid = the epoch =
  `NaiveDate::default()` = `origin()`), `"2099-12-31"` (max) — guarded by
  `temporal_fixtures_include_pivot_plaintexts` (catalog) and the
  `temporal_values!`-generated `pivots_present_in_fixtures`.
- **The pivot traits, not `Self::MIN`/`MAX`.** `ScalarType::fixture_values()` is a
  method (not a `const`); the comparison pivots live on a small trait hierarchy
  over `ScalarType` (`scalar_domains.rs`): **`OrderedScalar`** carries the
  `min_pivot()` / `max_pivot()` boundaries and the interior `mid_pivot()` (default
  `Self::default()`); **`SignedScalar: OrderedScalar`** adds `origin()` (the
  numeric zero / sign boundary). `min_pivot()`/`max_pivot()` are **derived** for
  every kind — the trait default returns the smallest/largest `fixture_values()`
  entry (`ScalarType` already bounds `Ord + Clone`), so a boundary pivot is a
  fixture row by construction and cannot drift. **No impl overrides them.** Only
  `mid_pivot()` is ever overridden: it defaults to `Self::default()` (the numeric
  origin / epoch — a real fixture for the integer kinds, `date`, `timestamp`,
  and `numeric`), and `text` overrides it with a real median fixture because
  `String::default()` is the degenerate empty string (issue #262). The proc-macro
  and the `temporal_values!` macro therefore emit an empty `impl OrderedScalar`
  (defaults inherited) alongside the `SignedScalar { origin }` impl where the kind
  is signed. `date` is both `OrderedScalar` and
  `SignedScalar`; `text` is `OrderedScalar` only and **hand-written** in
  `scalar_domains.rs` (lexicographic order has no origin, so it overrides
  `mid_pivot()` with a real median fixture rather than the degenerate
  `String::default()` empty string — see issue #262). `to_sql_literal` is
  overridden to single-quote the value (`'1970-01-01'`), since a bare `Display`
  date is not a valid SQL literal.
- **The sqlx `chrono` feature.** The test crate enables sqlx's `chrono` feature
  (and depends on `chrono` directly) so `Encode`/`Decode`/`Type` resolve for
  `NaiveDate`. The integer-only fixture asserts (`<T>::MIN`, `contains(&0)`,
  `v < 0`) are stamped only for `int` entries; temporal entries stamp a
  pivot-presence assert instead (the `kind` discriminator on `scalar_fixture!`).

---

## 3. Wire the SQLx matrix oracle

The generated SQL is enough to *install* the domains, but the
`scalar_matrix!` suite only runs once the Rust harness knows about the
scalar. `<R>` is the scalar's Rust type (`i32` for `integer`, `i16` for `smallint`).
The registrations depend on whether `<R>` is an **integer** kind. For an
integer type (the `integer` reference) there are **two**; a **non-integer
(string-backed)** type — `date`, `timestamp`, `text` — needs a **third**
(`scalar_domains.rs`), because the proc-macro emits `impl ScalarType` only for
integer kinds:

| File | Add |
|------|-----|
| `tests/sqlx/src/scalar_types.rs` | One `<T> => <R>` line in the `scalar_types!` list (e.g. `uuid => uuid::Uuid,`). This single line drives the `impl ScalarType` **(integer kinds only)**, the `eql_v3_<T>` fixture module, the `scalar_matrix!` suite, and the `generate_for_token` arm — all generated by the `eql-tests-macros` proc-macros. |
| `tests/sqlx/src/fixtures/eql_plaintext.rs` | A sealed `EqlPlaintext` impl for `<R>`: `impl Sealed for <R> {}` and `impl EqlPlaintext for <R>` carrying just `const KIND: ScalarKind` plus the value-typed `to_plaintext` → the right `Plaintext` variant. `CAST` and `PLAINTEXT_SQL_TYPE` are **derived** from `KIND` via the `cast_for_kind` / `plaintext_sql_type_for_kind` `const fn` defaults, so a brand-new kind needs an arm in those two helpers — not a per-type const (see §3.1 for a non-integer kind's full wiring). Keep the three `#[test]`s (cast / sql-type / to_plaintext) mirroring the existing ones. |
| `tests/sqlx/src/scalar_domains.rs` **(non-integer only)** | The `impl ScalarType` the proc-macro skips for non-integer kinds. For a **chrono-backed** kind (`date`, `timestamp`) this is a `temporal_values!` invocation that materialises the catalog ISO/RFC3339 strings into a `LazyLock<Vec<_>>` and emits `impl ScalarType` + `OrderedScalar` (+ `SignedScalar` for `date` and `timestamp`). For **`text`** it is a hand-written `impl ScalarType` / `OrderedScalar` block (an overridden lexicographic-median `mid_pivot()` — `min`/`max` inherit the fixture-derived defaults — plus a `to_sql_literal` override) — `String` has no numeric origin, so it is deliberately **not** `SignedScalar`. |

The single `<T> => <R>` line in `scalar_types.rs` is the harness source of
truth. The four code-generators (`emit_scalar_type_impls`,
`emit_scalar_fixture_modules`, `emit_scalar_matrix_suites`,
`emit_fixture_dispatch`) are pure functions of that list, invoked at each call
site via `scalar_types!(<mode>)`; there are four because proc-macros emit into
the crate/module where they're invoked and the pieces span the `eql-tests` lib,
the `encrypted_domain` test binary, and the `generate_all_fixtures` test binary.
See the `scalar_types.rs` module docs and `crates/eql-tests-macros/src/lib.rs`.

Forget the harness line and the matrix simply does not run for the type — the
matrix inventory cross-check (below) surfaces it, because the catalog has the
type but the binary has no `scalars::<T>::` tests. A catalog token absent from
the `scalar_types!` list also fails the `generate_for_token` catch-all loudly
at fixture-generation time.

The coverage these registrations unlock comes from the `scalar_matrix!`
convention wrapper in `tests/sqlx/src/matrix.rs`: one `impl ScalarType` (plus
`OrderedScalar`, and `SignedScalar` for signed kinds) and a single invocation
taking `suite`, `scalar`, `eql_type`, and a `caps` capability marker. The matrix
derives its comparison pivots — the scalar's `min_pivot()`, `max_pivot()`, and
the interior `mid_pivot()` — from `OrderedScalar` rather than a hand-written
list, so the invocation carries no pivot argument. `caps = [eq, ord]` selects the
ordered-numeric shape (all four variants; `=`/`<>`/`<`/`<=`/`>`/`>=`; ORDER BY /
ORDER BY USING; ORE injectivity); `caps = [eq]` selects the equality-only shape
(storage + `_eq` only; the four ord operators are deliberate blockers);
`caps = [storage]` selects the storage-only / encryption-only shape (storage
domain only; *every* comparison/containment operator is a blocker — see §8).
All expand to the lower-level `scalar_domain_matrix!` **except `[storage]`**,
which has no comparison/index/order categories to thread, so it invokes only the
surface leaf drivers directly (§8). **You never write `caps`**: the
`scalar_matrix!` proc-macro derives it from the catalog row — `is_storage_only`
(no `_eq`/`_ord`) → `[storage]`, checked first; then `is_eq_only` (no `_ord`) →
`[eq]`; then `has_search` → `[eq, ord, search]`; else `[eq, ord]`. So the shape
is a pure function of which domain-suffix slice the catalog row uses —
`STORAGE_ONLY_DOMAINS` (→ `[storage]`, e.g. `boolean`), `EQ_ONLY_DOMAINS` (→ `[eq]`,
no live catalog type today) vs `ORDERED_INT_DOMAINS` (→ `[eq, ord]`). (`EQ_ONLY_DOMAINS`
is currently unused — `timestamp` was promoted to the ordered shape once the ORE
comparator generalized to N blocks.) The pivot *sweep* is uniform
across every ordered type (one canonical snapshot); the signed-only sign-boundary
test (`SignedScalar`, `smallint`/`integer`/`bigint`/`date`/`timestamp`/`real`/`double`) lives outside `scalars::` in
`encrypted_domain/signed.rs`, so a `text` instantiation of it is a compile error
and it never enters the inventory snapshot. The `matrix.rs` module header is the
canonical,
current list of the categories the matrix emits (sanity, correctness,
cross-shape, supported-NULL, blocker raises, index engagement, ORDER BY, ORDER
BY USING) — read it rather than duplicating a count here. For ordered `integer`,
keep the assertion that distinct plaintext values produce distinct ORE blocks;
do not add assertions for term behaviour the catalog does not promise.

### 3.1 Wiring a brand-new non-integer kind

The integer arms above suffice for a new *width* of an existing integer kind. A
brand-new **non-integer** kind (the way `Date`/`Timestamp`/`Text` were each
first added) also needs, in `tests/sqlx/src/fixtures/eql_plaintext.rs`:

- a `Cast` const + a `PlaintextSqlType` const (e.g. `Cast::DATE`,
  `PlaintextSqlType::TIMESTAMPTZ`) on those two newtypes;
- an arm in **`cast_for_kind`** and in **`plaintext_sql_type_for_kind`** mapping
  the new `ScalarKind` to those consts (a missing arm is a `panic!`, not a silent
  default);
- a `sealed::Sealed` impl for the Rust plaintext type (so the `EqlPlaintext` impl
  is admissible);
- an `impl EqlPlaintext` whose `to_plaintext` maps onto the correct
  `Plaintext::*` variant (`Plaintext::NaiveDate` / `Plaintext::Timestamp` /
  `Plaintext::Text`), plus the three mirrored `#[test]`s.

#### A fourth fixture shape: non-integer, non-chrono, non-text (`numeric` / `Decimal`)

`numeric` (backed by `rust_decimal::Decimal`, 14-block ORE — the first scalar
whose ORE term is wider than 8 blocks) is ordered but is **neither** the integer
materialiser, **nor** chrono (`temporal`), **nor** `text` (it owns a `Decimal`,
not a `String`, and has no `Match` index). It therefore introduces a **fourth
fixture discriminator**, which means touching the proc-macro routing, not just
the type list. Beyond the §3.1 `eql_plaintext.rs` wiring above (`Cast::DECIMAL`,
`PlaintextSqlType::NUMERIC`, the `cast_for_kind` / `plaintext_sql_type_for_kind`
arms, `Sealed for Decimal`, `EqlPlaintext for Decimal` → `Plaintext::Decimal`),
it also needs:

- an **`is_numeric_token`** arm in `crates/eql-tests-macros/src/lib.rs`'s
  fixture-module router — without it `scalar_types!(fixture_modules)` panics at
  compile time on the unrecognised kind (the router handled only `temporal` /
  `text` before);
- a **`numeric` arm** in the `scalar_fixture!` macro
  (`tests/sqlx/src/fixtures/scalar_fixture.rs`) — the temporal arm's twin
  (`[Unique, Ore]`, pivot-presence asserts via `OrderedScalar`), but no `Match`
  and no chrono;
- a hand-written **`numeric_values()`** accessor plus `impl ScalarType` /
  `OrderedScalar for Decimal` in `tests/sqlx/src/scalar_domains.rs` — parsing the
  catalog's `Fixture::Numeric` strings into a `LazyLock<Vec<Decimal>>` (the
  catalog stays zero-dep; the parse lives in the harness). `Decimal: Ord` supplies
  the expected sort order — `ore-rs` guarantees the ciphertext order agrees, and
  equivalent scales (`1` ≡ `1.0`) collide like `Decimal`'s own `Ord`. Add a
  **`fixtures_are_distinct_by_value`** guard (parse → `HashSet`): the zero-dep
  catalog only dedupes by literal string, so `"1"` / `"1.0"` would slip past it
  but collide in both the ORE ciphertext and the fixture table;
- the **`rust_decimal` dependency** + the sqlx **`rust_decimal` feature** in
  `tests/sqlx/Cargo.toml` (in `[dependencies]`, not `[dev-dependencies]` — the
  `Decimal` impls live in the crate's library code).

See the N-block ORE comparator entry in the `CHANGELOG.md` for the comparator
change the wide `numeric` / `timestamp` terms rely on.

### New-capability domains (e.g. `_match` / `Bloom`)

A domain carrying a capability the matrix does not model — `text`'s `_match`
(`Bloom`, `@@`) is the only example today — is **not** covered by the
auto-generated `scalar_matrix!`, which only understands the eq/ord caps. So for
such a domain you must, in addition to the catalog row:

- **write hand-written behavioural suites** — see
  `tests/sqlx/tests/encrypted_domain/text/text_match.rs` (fixture-backed bloom
  fuzzy match) and `text_smoke.rs` (literal-payload `@@` engages, `=`/`@>`/`<@`
  raise, `~~`/`~~*` absent, CHECK requires `bf`);
- **register them via `#[path]` mod declarations** in
  `tests/sqlx/tests/encrypted_domain.rs`, kept **outside** the `scalars::` module
  on purpose: the matrix-inventory gate treats every `scalars::<X>::` prefix as a
  scalar type, so a suite registered there would be mis-discovered as a phantom
  type (and would pollute the inventory snapshot).

### Matrix coverage inventory snapshot

The *set of test names* the matrix emits is guarded by **four** committed,
token-normalized **shape** snapshots under `tests/sqlx/snapshots/` — each the
sorted inventory of every `scalars::<T>::*` test name with the type token
replaced by the literal `<T>`. The canonical baseline is `matrix_tests.txt` (the
ordered `caps = [eq, ord]` shape); alongside it are `matrix_tests_eq_only.txt`
(the eq-only shape, *derived* from the baseline minus the `_ord`/`order_by`/
`routes_through_ob` lines), `matrix_tests_text.txt` (the text shape, a *superset*
of the baseline adding the `_search`/`_eqidx`/`_match` arms), and
`matrix_tests_storage_only.txt` (the storage-only shape, e.g. `boolean` — see §8).
(The per-type `<T>_matrix_tests.txt` files are
gone: they were byte-identical modulo the token, so the shape snapshots plus a
per-type normalize-and-compare carry the same signal at a fraction of the
committed surface.) These are the guard that catches a silently dropped, renamed,
or `#[cfg]`-gated matrix test — a behaviour the SQLx assertions cannot see (a
deleted test just stops running). The snapshots are committed test baselines,
**not** part of the generated SQL surface.

`mise run test:matrix:inventory` discovers the present scalar types from the
`encrypted_domain` binary's `--list`, normalizes each type's token to `<T>`, and
matches each discovered type against whichever shape applies — the canonical
ordered baseline, the derived eq-only subset, the text superset, or the
storage-only set — then cross-checks the discovered type set against
`cargo run -p eql-codegen -- list-types` (the catalog is the single source). You
do **not** edit a per-type snapshot or touch `mise.toml` / the CI workflow — you
regenerate the affected shape snapshots (all four atomically via
`mise run test:matrix:snapshots:regen`) only when the macro's emitted name set
itself changes. A catalog type missing its
matrix wiring fails the cross-check. The CI `matrix-coverage` job gates it.
**`tests/sqlx/snapshots/README.md` is the source of truth** for the mechanics
(pinned feature set, the catalog cross-check, the CI diff, and when to
regenerate).

---

## 4. Regenerate, snapshot & verify

Regeneration is deterministic: identical catalog + renderers produce
byte-identical SQL. If `mise run build` produces unexpected output, the change
is in `crates/eql-domains/src` (catalog/terms) or `crates/eql-codegen/src`
(renderers) — not run-to-run variation.

Run, in order:

- `cargo run -p eql-codegen` (optional; refreshes all generated SQL from the
  catalog before a full build)
- `mise run test:codegen` (`cargo test -p eql-domains -p eql-codegen`)
- `mise run test:matrix:inventory` (matrix inventory + catalog cross-check; no
  database)
- `mise run clean && mise run build` (regenerates every type's SQL from the
  catalog first, then builds the release artefacts — a bare build can leave
  stale `release/*.sql`)
- the relevant SQLx suites
- `mise run test` across supported PostgreSQL versions
- `mise run --output prefix test:splinter --postgres 17` after a PostgreSQL 17
  install has built EQL

The CI `codegen` job runs `mise run codegen:parity` as an independent required
check (feeding the final `ci-required` gate); it no longer blocks the PostgreSQL
test matrix from starting — the shards run after `build-archive` in parallel with
codegen.

**Commit the generated SQL in place.** Every catalog type **must** have its
generated SQL committed under `src/v3/scalars/<T>/` (regenerate with
`mise run build`, then commit the SQL diff). The generator is type-generic, but
per-type domain *shapes* differ — ordered types (including `timestamp`) carry
`_ord`/`_ord_ore` + aggregates, a hypothetical equality-only type
(`EQ_ONLY_DOMAINS`) would omit them, and the Bloom `text_match` domain renders
`@@` as the supported fuzzy-match operator no ordered type emits — so
committing every type catches a regression in any shape, not just the ordered
one. `committed_scalar_dirs_match_catalog_tokens` (in
`crates/eql-codegen/tests/parity.rs`) fails CI if a catalog row has no committed
scalar dir or a dir has no catalog row. Drift protection is further reinforced by the
catalog `values_tests` pinning the materialised `<T>_VALUES`, the
catalog/generator `#[test]`s, and the `scalar_matrix!` SQLx suite (behaviour, not
bytes).

---

## 5. The generated surface — what correct output looks like

This is the contract the generated SQL satisfies. You normally never read it to
*add* a type — read it when a test fails or you're extending the surface.

### Domains and CHECK constraints

The generator emits `src/v3/scalars/<T>/<T>_types.sql` (committed in place;
regenerated on every build) with one idempotent `DO $$ ... $$` block. Every
domain is a concrete domain over `jsonb` in the `public` schema — **never**
`CREATE DOMAIN a AS b` over another generated domain (PostgreSQL resolves
operators against the underlying base type, bypassing the fixed surface). Each
domain's `CHECK` requires:

- fixed envelope keys `v` and `i`;
- ciphertext key `c`;
- catalog JSON keys for the listed terms;
- the envelope version value `VALUE->>'v' = '3'` — the payload version pin
  enforced intrinsically by every `eql_v3` domain's `CHECK`.

So a domain with `&[Term::Ore]` requires `v`, `i`, `c`, and `ob` present, with
`v` pinned to `3`. Beyond key presence and the version value, a malformed term
can still fail later inside its extractor.

### Extractors, wrappers, and blockers

Extractor names and return types come from the `Term` enum. Generated extractors
and supported comparison wrappers are inline-friendly SQL functions:

```sql
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT ... $$;
```

They must **not** carry a pinned `search_path` — a `SET` clause disables
inlining and reverts index-backed queries to seq scans. The build tooling
recognises these functions structurally, so the generator emits no
`eql-inline-critical` markers. (Aggregate state functions are the one deliberate
exception — see below.)

Unsupported operators route to **blockers**, which are `LANGUAGE plpgsql`,
`IMMUTABLE`, `PARALLEL SAFE`, and intentionally **not `STRICT`**:

- **`plpgsql`, not `sql`.** A `LANGUAGE sql` body is inlinable, and the planner
  could elide the call when the result is provably unused (dead `CASE` branch,
  folded predicate), letting a blocked operator appear to succeed. `plpgsql` is
  opaque to the planner, so the call — and its `RAISE` — always survives.
- **Not `STRICT`.** A `STRICT` blocker lets PostgreSQL skip the body and return
  `NULL` on a `NULL` argument, silently bypassing the unsupported-operator
  exception.

### Operators

Every generated domain declares supported scalar comparison operators plus
blockers for the native `jsonb` operator surface PostgreSQL could otherwise
reach through domain-to-base-type fallback. The surface is a fixed 20 operators
(`crates/eql-codegen/src/operator_surface.rs`, `OPERATORS`), each with its
PostgreSQL-shaped signatures, summing to **47 `CREATE OPERATOR` statements per
domain**:

| Operators | Forms |
|---|---|
| `=` `<>` `<` `<=` `>` `>=` `@>` `<@` `@@` | `(domain, domain)` · `(domain, jsonb)` · `(jsonb, domain)` |
| `->` `->>` | `(domain, text)` · `(domain, integer)` · `(jsonb, domain)` |
| `?` | `(domain, text)` |
| `?\|` `?&` | `(domain, text[])` |
| `@?` | `(domain, jsonpath)` |
| `@@` | `(domain, jsonpath)` — **blocker-only** (the native-jsonb predicate guard; always raises, even on match domains where the symmetric `@@` overloads above are the supported fuzzy match) |
| `#>` `#>>` `#-` | `(domain, text[])` |
| `-` | `(domain, text)` · `(domain, integer)` · `(domain, text[])` |
| `\|\|` | `(domain, domain)` · `(domain, jsonb)` · `(jsonb, domain)` |

Whether an operator routes to a wrapper or a blocker is a per-domain decision
driven by the domain's terms (`Term::operators_for_terms`), not a property of
the operator. Supported operators are emitted with full planner metadata
(`COMMUTATOR`, `NEGATOR`, `RESTRICT`, `JOIN` selectivity estimators) backing
onto inlinable wrappers — except the directional `@@` fuzzy match, whose
`match_metadata()` deliberately carries no commutator or negator (there is no
reverse operator), only the containment selectivity estimators; everything
else carries minimal metadata backing onto
blockers. Path operators always back onto blockers — neither current term
enables them — and the native `jsonb` operators are blocker-only **except the
three symmetric `@@` overloads**, which back onto the inlinable bloom fuzzy-match
wrapper (`eql_v3.matches`) on any domain carrying the `Bloom` term — the
single-capability `_match` domain (e.g. `public.eql_v3_text_match`) **and** the combined
`_search` domain (`public.eql_v3_text_search`, `[Hm, Ope, Bloom]`) — and elsewhere stay
blockers — matching the per-domain table just below, where every `Bloom`-bearing
row carries three match wrappers. (`@>`/`<@` are **containment** operators,
distinct from the `@@` fuzzy-match operator, and are blocked on every scalar domain.)

The wrapper/blocker split per domain (the 47-operator total never moves). A
domain's wrappers are the **union** of its terms' operators
(`Term::operators_for_terms`), so a multi-term domain advertises every operator
any of its terms provides; the rest stay blockers. `Functions` =
`47 + <extractor count>` (one extractor function per distinct extractor):

| Domain terms      | Extractors | Wrappers | Blockers | Functions | Operators |
| ----------------- | ---------: | -------: | -------: | --------: | --------: |
| none              |          0 |        0 |       47 |        47 |        47 |
| `&[Term::Hm]`     |          1 (`eq_term`)    |  6 | 41 | 48 | 47 |
| `&[Term::Bloom]`  |          1 (`match_term`) |  3 | 44 | 48 | 47 |
| `&[Term::Ore]`    |          1 (`ord_term_ore`)   | 18 | 29 | 48 | 47 |
| `&[Term::Ope]`    |          1 (`ord_term`) | 18 | 29 | 48 | 47 |
| `&[Term::Hm, Term::Ore]` | 2 (`eq_term`, `ord_term_ore`) | 18 | 29 | 49 | 47 |
| `&[Term::Hm, Term::Ope]` | 2 (`eq_term`, `ord_term`) | 18 | 29 | 49 | 47 |
| `&[Term::Hm, Term::Ore, Term::Bloom]` | 3 (`eq_term`, `ord_term_ore`, `match_term`) | 21 | 26 | 50 | 47 |

Six wrappers for `Hm` = `=` and `<>` × three shapes; three for `Bloom` = `@@` ×
three shapes; eighteen for `Ore` = six operators × three shapes (`Ope`
mirrors `Ore`'s eighteen — same six operators through `ord_term`). For the
multi-term rows the wrapper set is the **deduplicated union**: `[Hm, Ore]` is
`{=, <>, <, <=, >, >=}` (Ore's `=`/`<>` collapse onto Hm's — only the *extractor*
differs, so the count stays 18, but `=`/`<>` now resolve through `eq_term`, exact
HMAC, not ORE); `[Hm, Ope]` (the `text_ord_ope` shape) collapses identically, so
`=`/`<>` stay exact HMAC while range operators route through `ord_term`;
`[Hm, Ore, Bloom]` adds `@@` for 21. The extra extractor
functions are the only thing that grows `Functions` past 47 — the operator total
is always 47.

**Untyped-literal resolver edge.** PostgreSQL's operator resolver still prefers
the built-in `jsonb` operator for untyped string literals in forms such as
`payload::public.eql_v3_integer ? 'c'`. Use typed parameters or explicit casts
(`? 'c'::text`, bound text parameters) to route those forms to the generated
blocker. A live-DB structural guard
(`tests/sqlx/tests/encrypted_domain/family/jsonb_operator_surface.rs`) queries
`pg_operator` for every operator with a `jsonb` argument and asserts the set is
a subset of the enumerated surface, so a future PostgreSQL version that adds a
`jsonb` operator nobody enumerated fails the test rather than silently routing an
encrypted column to native plaintext-`jsonb` semantics.

### Aggregates

Each ordered (ord-capable) domain additionally gets a generated
`<domain>_aggregates.sql`: two state functions (`eql_v3_internal.min_sfunc`,
`eql_v3_internal.max_sfunc`) and two aggregates (`eql_v3.min(<domain>)`,
`eql_v3.max(<domain>)`). Comparison routes through the domain's `<` / `>`
operator (the ORE block term — no decryption). The state functions are `LANGUAGE
plpgsql IMMUTABLE STRICT PARALLEL SAFE` **with** a pinned `SET search_path` —
the one place the "no pinned `search_path`" rule does not apply, because
aggregate transition functions are never index expressions. `STRICT` makes
PostgreSQL seed the running state with the first non-NULL value and skip NULLs,
so an all-NULL group returns NULL. Each `CREATE AGGREGATE` declares
`combinefunc = <sfunc>` and `parallel = safe`: min/max are associative, so the
state function doubles as the combine function, enabling partial and parallel
aggregation on large `GROUP BY` ORE workloads with no decryption. Storage-only
and equality-only domains have no comparator and emit no aggregate file.

### Indexing

Do not create operator classes on generated domains. Index through the
extractor, whose return type already carries a default opclass:

```sql
-- _ord / _ord_ope (CLLW-OPE); ope_cllw is a domain over bytea, default opclass
CREATE INDEX ... ON table_name USING btree (eql_v3.ord_term(col));
-- _ord_ore (block-ORE); needs the superuser-created ore_block_256 opclass
CREATE INDEX ... ON table_name USING btree (eql_v3.ord_term_ore(col));
CREATE INDEX ... ON table_name USING hash  (eql_v3.eq_term(col));
```

`ore` depends on `src/v3/sem/ore_block_256/functions.sql` and
`src/v3/sem/ore_block_256/operators.sql`; `hm` depends on
`src/v3/sem/hmac_256/functions.sql`; `op` depends on
`src/v3/sem/ope_cllw/functions.sql` only — `eql_v3_internal.ope_cllw` is a
domain over `bytea`, so it inherits the native comparison operators and DEFAULT
btree opclass with no hand-written operators file, and the whole comparison
chain stays inlinable SQL (the reason the `_ord_ope` functional index engages
structurally).

**Missing-term semantics differ between the two ordering extractors:**
`eql_v3_internal.ore_block_256(jsonb)` RAISEs on a missing `ob`, while
`eql_v3_internal.ope_cllw(jsonb)` returns SQL `NULL` on a missing `op` (its body
is a strict expression chain; a `RAISE` would force `plpgsql` and kill the
inlining the functional-index design depends on). Raw-`jsonb` callers therefore
get an error from the ORE path but silent NULL-filtering from the OPE path.

### Extension files

Optional hand-written SQL beyond the fixed surface belongs in
`src/v3/scalars/<T>/<T>_extensions.sql`. The generator never creates,
lists, headers, or cleans it; it must declare its own `-- REQUIRE:` edges
(usually to `<T>_types.sql` and whichever generated function or operator file it
extends). Use it for cross-domain casts, helper functions, or type-specific
constraints. Unlike the generated siblings, **`<T>_extensions.sql` IS
committed.** (Neither `integer` nor `smallint` ships one today.)

`tasks/pin_search_path_v3.sql` describes the fallback marker for inline-critical
extension functions that take no domain argument and so escape the structural
skip:

```sql
COMMENT ON FUNCTION eql_v3.my_helper(...) IS 'eql-inline-critical: ...';
```

The generator never emits this marker; every function it produces takes a domain
argument and is covered by the structural skip intrinsically.

### Invariants the generator enforces

The generator's job is partly to write SQL and partly to make incorrect SQL
unreachable. Invariants encoded in the renderers / templates and guarded by
`#[test]`s in `crates/eql-codegen/src/generate.rs`:

- **Blockers are never `STRICT` and always `plpgsql`** — the
  unsupported-operator template emits each blocker as `IMMUTABLE PARALLEL SAFE` /
  `LANGUAGE plpgsql` without `STRICT`
  (`blockers_are_never_strict_and_always_plpgsql`).
- **Wrappers and extractors are inlinable SQL** — `LANGUAGE sql IMMUTABLE STRICT
  PARALLEL SAFE`, single-statement `SELECT`, no `SET search_path`
  (`inlinable_functions_have_no_set_search_path`).
- **Aggregate state functions are the deliberate exception** — `plpgsql` *with*
  a pinned `SET search_path` (`aggregate_state_functions_are_plpgsql_not_inlinable`).
- **SQL-literal injection is structurally prevented** — every interpolated
  single-quoted literal passes through `sql_str`
  (`crates/eql-codegen/src/consts.rs`), which doubles embedded single quotes.
- **No domain-over-domain** — every domain is `CREATE DOMAIN public.<name> AS
  jsonb` (`types_file_has_all_five_domains`).
- **No operator class on a domain** — the generator emits operators, not
  operator classes.
- **Ownership boundary** — `is_generated` recognises owned files by their header
  marker; `ensure_generated_paths_writable` refuses to overwrite anything else,
  and `clean_generated_files` deletes only marked files
  (`crates/eql-codegen/src/writer.rs`). A hand-written file at a generated path
  is a hard error, not a silent clobber.

### Lint and test integration

Two pieces of build tooling recognise the generated output without per-type
edits:

- **`tasks/pin_search_path_v3.sql`** — structural skip identifies encrypted-domain
  functions by language (`sql`), volatility (`IMMUTABLE`), and a jsonb-backed
  `DOMAIN` argument in the `eql_v3` schema. New scalar types need no edit.
- **`tasks/test/splinter.sh`** — name-based allowlist. The converged wrapper /
  extractor names (`eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `eq_term`, `ord_term_ore`,
  `ord_term`, the `Bloom` term's `match_term` extractor and its `matches`
  fuzzy-match wrapper) plus the generated `min` / `max`
  aggregates are covered by `eql_v3`-schema entries, and the SEM
  `hmac_256` / `ore_block_256` / `bloom_filter` / `ope_cllw` constructors and
  comparators by `eql_v3_internal`-schema entries. A new scalar type inherits
  coverage; **a new term needs splinter entries for each new name it introduces
  — both its extractor and its comparison wrappers** (adding `Bloom` required
  `match_term`, `matches`, and the SEM `bloom_filter`; adding
  `Ope` required `ord_term` and the SEM `ope_cllw`).

---

## 6. Generator internals — the machine

You need this section only when **modifying the generator itself**, not when
adding a type.

### Why a generator

A single scalar type emits several hundred SQL declarations. For `integer`: twenty-five
files, five column domains plus four `eql_v3.query_*` operand domains, four
extractor functions, dozens of wrappers and blockers, 235
`CREATE OPERATOR` statements across the column domains (47 per domain), the
query-operand and `json_entry` cross surfaces, and MIN/MAX aggregates per ordered
domain. (The per-domain figure is fixed — 47 `CREATE OPERATOR` statements per
column domain, the file formula below — so a type with more domains, e.g. `text`'s eight, scales
those totals up.)
The shape is mechanical and the invariants are unforgiving — a `STRICT` blocker
silently bypasses its exception; a pinned `search_path` reverts queries to seq
scans. The generator exists so each new type adds one `CATALOG` row rather than
ninety hand-written declarations that must agree with each other and with
`pin_search_path_v3.sql`, `tasks/test/splinter.sh`, and
`src/v3/scalars/functions.sql`.

### Pipeline

`eql-codegen` is a small Rust crate with a binary entry point. The generator
runs as `cargo run -p eql-codegen` (no subcommand), which calls
`generate::generate_all` (`crates/eql-codegen/src/generate.rs`) over every row of
`eql_domains::CATALOG`, writing each type's SQL into
`src/v3/scalars/<token>/`. Five subcommands round out the surface:
`list-types` prints the catalog tokens one per line (consumed by the fixture
and matrix-inventory enumeration); `list-schemas` prints the schemas the
`eql_v3` surface owns (`eql_v3`, then `eql_v3_internal`; consumed by `mise run test:schemas:parity`);
`dump-catalog` prints the catalog surface
(types → domains → supported operators) as JSON (consumed by the
catalog-coverage / log-verification gates); `bindings` regenerates the
committed `eql-bindings` Rust payload types (the first step of `mise run
types:generate`); and `clean` removes the generated SQL surface (marker-aware).
`main` (`crates/eql-codegen/src/main.rs`) recognises exactly
these six forms (no-arg generate-all, `list-types`, `list-schemas`,
`dump-catalog`, `bindings`, `clean`); any other argument is a usage error.

The generator targets three schemas. The **domain families themselves are
created in `public`** (`CREATE DOMAIN public.<name> AS jsonb`) so application
columns survive an `eql_v3` uninstall. `SCHEMA = "eql_v3"`
(`crates/eql-codegen/src/consts.rs`) qualifies only the **callable surface** —
the extractors, comparison wrappers, and aggregates — while
`INTERNAL_SCHEMA = "eql_v3_internal"` qualifies
the SEM index-term types the extractors return (`eql_v3_internal.hmac_256`,
`eql_v3_internal.ore_block_256`, `eql_v3_internal.ope_cllw`), the aggregate
state functions, and every generated blocker function (e.g.
`eql_v3_internal."->"(...)` in `boolean_functions.sql`), so the generated SQL
is entirely self-contained within the two
EQL-owned schemas.

`tasks/build.sh` runs `cargo run -p eql-codegen` at the start of every `mise run
build`, regenerating the committed SQL under `src/v3/scalars/` in place. Orphan
removal lives inside codegen (`remove_generated_orphans`): after writing every
current file it prunes — marker-aware — any previously-generated `.sql` no
longer produced, so a type removed from `CATALOG` cannot leave orphans the
`src/**/*.sql` build glob would pick up; hand-written `*_extensions.sql`
carries no marker and always survives. `mise run codegen:parity` then asserts
the committed tree is unchanged by a regeneration (see "Generator tests and the
parity gate" below).

Stages, in order (`generate_all` → `generate_type`):

1. **Read the catalog.** `eql_domains::CATALOG` is the in-binary source of truth
   — a `&[DomainFamily]`. There is no parse/validate stage at generation time: the
   catalog is validated at compile time (an undefined `Term` or unknown
   `ScalarKind` does not compile) and by the catalog `#[test]`s, so the data is
   already well-formed by the time `generate_all` runs.
2. **Resolve terms.** For each `Domain`, the `Term` enum's `impl` methods
   supply the extractor name, return type, JSON envelope key, supported
   operators, and the SQL `-- REQUIRE:` edges those terms imply
   (`Term::operators_for_terms`, `term_json_keys`, `term_requires`,
   `extractor_for_operator`, `role_for_terms`).
3. **Render.** `render_types_file`, `render_functions_file`,
   `render_operators_file`, and `render_aggregates_file` (the last only for
   ordered domains) render the column-domain surface;
   `render_query_types_file`, `render_query_functions_file`, and
   `render_query_operators_file` render the query-operand surface (the
   `query_*` files, per term-bearing domain); and the `json_entry` cross
   renderers emit the `json_entry_<token>_{functions,operators}.sql` pair (all
   in `crates/eql-codegen/src/generate.rs`). They build the context structs in
   `crates/eql-codegen/src/context.rs` and render them through embedded
   **minijinja** templates (`crates/eql-codegen/templates/*.j2`, compiled in via
   `include_str!` — no runtime file IO). The structural shape of each declaration
   is split between the context builders (Rust) and the templates (Jinja).
4. **Write.** `ensure_generated_paths_writable` runs first and refuses to proceed
   if any target path is a hand-written file lacking the marker; `write_generated_file`
   then writes each rendered body verbatim; finally `remove_generated_orphans`
   prunes — marker-aware — any previously-generated `.sql` no longer produced, so an
   abandoned domain disappears on the next regeneration (a hand-written file with no
   marker always survives) (`crates/eql-codegen/src/writer.rs`). The template emits
   the `-- AUTOMATICALLY GENERATED FILE.` marker as its own first line, so the
   writer does not prepend a header — it only uses the marker to recognise files it
   owns.

There is no caching layer and no incremental mode. Each run regenerates every
output for every catalog type from scratch.

### Generated outputs

For a type with `D` domains, of which `A` are ordered and `Q` carry at least
one term, the generator writes `1 + 2D + A` **column-domain** SQL files, plus a
**query-operand** surface of `1 + 2Q` files, plus — for any family with an
`Ope`-bearing domain — two **`json_entry` cross** files, all into
`src/v3/scalars/<token>/`. For `integer` (`D = 5`, `A = 3`, `Q = 4`):
twenty-five SQL files (fourteen column-domain + nine query-operand + two
`json_entry`). The outputs are committed in place under
`src/v3/scalars/<token>/` and regenerated at the start of every build (commit the
regenerated SQL diff alongside any catalog change).

**Query-operand domains.** Every term-bearing column domain has a query twin,
`eql_v3.query_<token>_<domain>` (`Domain::query_name` in
`crates/eql-domains/src/spec.rs`): a term-only operand shape for typed query
parameters — the envelope `v`/`i` plus the domain's term keys, with **no**
ciphertext `c` (the `CHECK` requires `NOT (VALUE ? 'c')`). Query-operand
domains live in **`eql_v3`**, not `public`: they are never valid column types,
so dropping the EQL-owned schema can never drop an application column. The
`json_entry_<token>_*` pair is the cross-type surface comparing the extracted
SteVec leaf `public.eql_v3_json_entry` against the family's query operands —
ordering wrappers where the operand carries the deterministic `Ope` term,
blockers elsewhere.

| File                              | Content                                                                                  |
| --------------------------------- | ---------------------------------------------------------------------------------------- |
| `<token>_types.sql`               | Single idempotent `DO` block creating every domain; each `CHECK` pins the payload version (`VALUE->>'v' = '3'`) and required envelope/ciphertext/term keys; one `--! @brief` per domain |
| `<domain>_functions.sql`          | One extractor per unique term, then 47 wrappers-or-blockers covering the surface         |
| `<domain>_operators.sql`          | 47 `CREATE OPERATOR` statements with planner metadata on supported ops                   |
| `<domain>_aggregates.sql`         | MIN/MAX state functions + `CREATE AGGREGATE`; emitted only for ordered domains           |
| `query_<token>_types.sql`         | `DO` block creating the `eql_v3.query_*` operand domains (term-only `CHECK`: `v`, `i`, term keys, `NOT (VALUE ? 'c')`) |
| `query_<token>_<domain>_{functions,operators}.sql` | Wrappers/blockers and `CREATE OPERATOR` statements binding the column domain to its query-operand twin; one pair per term-bearing domain |
| `json_entry_<token>_{functions,operators}.sql` | The `public.eql_v3_json_entry` ↔ query-operand cross surface (ordering wrappers on `Ope`-bearing operands, blockers elsewhere) |

Every file opens with the `-- AUTOMATICALLY GENERATED FILE.` marker (the
project-wide marker `docs:validate` greps on to skip generated SQL —
`crates/eql-codegen/src/consts.rs`), declares its `-- REQUIRE:` edges in
dependency order (types files require `src/v3/schema.sql`; function files require
`src/v3/schema.sql`, the types file, and
`src/v3/scalars/functions.sql` plus each term's `requires` set; operator
files require `src/v3/schema.sql`, the types file, and their domain's function
file; aggregate files require `src/v3/schema.sql`, the types file, and their
domain's function and operator files), and carries Doxygen `--! @file` /
`--! @brief` headers.

### Generator tests and the parity gate

The generator's tests are Rust, run by `mise run test:codegen` (`cargo test -p
eql-domains -p eql-codegen`) — no database. `mise run test:crates` adds `cargo
clippy ... -D warnings`.

- **`eql-domains` unit tests** — `rust_tests`, `term_tests`,
  `term_helper_tests`, `fixture_tests`, `catalog_tests`, `invariant_tests`,
  `values_tests` over `CATALOG`, the `Term` / `ScalarKind` / `Fixture` impls, and
  the materialised `<T>_VALUES` consts.
- **`eql-codegen` unit tests** — file counts, language/volatility invariants,
  escaping guards, and twin byte-identity
  (`crates/eql-codegen/src/generate.rs` `#[cfg(test)]`).
- **The parity gate** — `mise run codegen:parity` (`tasks/codegen-parity.sh`).
  It is a regenerate-in-place + git-diff drift gate: it runs
  `cargo run -p eql-codegen` (regenerating the SQL into `src/v3/scalars/` in
  place), then `git diff --exit-code -- src/v3/scalars` (any drift from the
  committed surface fails), then a `git ls-files --others` untracked-file check
  (a newly generated file that was never committed fails). This is the **same
  pattern `mise run types:check` uses** for the committed Rust bindings — both
  generated targets (SQL + bindings) are committed in place and drift-gated by
  regenerate-and-git-diff. The in-crate assertions run as
  `crates/eql-codegen/tests/parity.rs`: `every_generated_sql_file_starts_with_marker`
  (every committed generated file opens with the marker),
  `generate_all_is_deterministic_across_runs` (two runs are byte-identical), and
  `committed_scalar_dirs_match_catalog_tokens` (committed scalar dirs == catalog
  tokens). The committed `src/v3/scalars/` SQL — not any Python oracle — is the
  sole contract that survives generator refactors.

CI runs these in three jobs in `.github/workflows/test-eql.yml`: `rust-crates`
(`Rust workspace crates`, runs `mise run test:crates`), `codegen`
(`Encrypted-domain codegen`, runs `mise run codegen:parity`), and
`matrix-coverage` (`Matrix coverage inventory`, runs `mise run
test:matrix:inventory`). These run as independent required checks feeding the
final `ci-required` gate; the `codegen` job no longer blocks the PostgreSQL test
matrix from starting (the gate was removed — shards start after `build-archive`).

Adding a new **term** is a bigger move than adding a type: edit the `Term` enum's
`impl` methods, add `#[test]`s, add a `splinter.sh` entry for **each new name the
term introduces** — its extractor *and* its comparison wrappers, plus any new SEM
constructor (adding `Bloom` required `match_term`, its `matches` fuzzy-match
wrapper, and the SEM `bloom_filter`; adding `Ope` required `ord_term` and the SEM
`ope_cllw`) — and, because it changes the generated surface,
regenerate and commit the affected SQL files under
`src/v3/scalars/<token>/`.

---

## 7. `text` (in scope) and `jsonb` (mixed: SteVec out of scope, storage domain in scope)

`text` **is** materialised through this generator. It is the worked example of
an ordered, non-integer, unbounded scalar: it hand-writes its `impl ScalarType`
+ `OrderedScalar` (its `text` shape is read from the catalog `ScalarKind`, like
`date`'s temporal shape — there is no dispatch-list marker); its boundary
pivots inherit the fixture-derived `min_pivot()`/`max_pivot()` defaults (§2 —
no impl overrides them), and it overrides only `mid_pivot()` with a real median
fixture. It is **`OrderedScalar` but not `SignedScalar`** —
lexicographic text has no numeric origin, so it does not get the signed-only
sign-boundary test, and the empty string is deliberately not a fixture (`""`
encrypts to an empty ORE term; issue #262). `text` is also the first type to add
a new index `Term` (`Bloom`) — giving it a `match` capability (`@@`
bloom-filter fuzzy match on the `public.eql_v3_text_match` domain) on top of equality
(`Hm`) and ordering (`Ore`). Match is deliberately **not** SQL `LIKE`: it is
probabilistic ngram-bloom matching, exposed only on `text_match`, and never
backs equality.

`jsonb` is a **mixed** family. Its **searchable** SteVec surface remains out of
scope for this materializer: the `public.eql_v3_json_search` document, `eql_v3_json_entry`,
and `eql_v3.query_json` domains carry `Shape::SteVec`, need a SQL design beyond
the ordered-scalar materializer, and stay hand-written under `src/v3/json/`.
But the family **also** carries one `Shape::Scalar` storage domain,
`public.eql_v3_json` — a bare ciphertext-only, storage-only encrypted-JSON blob
(the JSON analogue of `boolean` in §8), with no index terms and every native
jsonb operator blocked. That one domain **is** generated by this materializer,
into `src/v3/scalars/json/`, exactly like any storage-only scalar. The generator
picks it up because its SQL/bindings drivers iterate `families_with_scalar_domains()`
(any family with ≥1 scalar domain) and render each family's scalar domains only;
the family stays non-scalar (`is_scalar()` is `.all()`), so `scalar_families()` —
used by `list-types` and the SQLx matrix — still excludes it, keeping `jsonb` out
of the operator/coverage matrix. Use `public.eql_v3_json_search` when you need to search
encrypted JSON; `public.eql_v3_json` when you only need to store and round-trip
an encrypted JSON value.

---

## 8. `boolean` — the storage-only / encryption-only shape

`boolean` is the worked example of a **storage-only** (encryption-only) scalar: the
value is encrypted at rest and decrypted by the proxy, but is **never searchable
server-side**. It is the smallest shape — strictly below eq-only — because a
two-value column has so little cardinality that *any* searchable index (even
HMAC equality) would trivially leak the plaintext distribution. So `boolean`
deliberately offers no search surface at all.

What makes it storage-only:

- **One term-less domain.** Its catalog row uses `STORAGE_ONLY_DOMAINS` — a
  single `Domain { name: "", terms: &[] }`. No `_eq`, no `_ord`, no SEM
  index term. `DomainFamily::is_storage_only()` recognises this shape (a single
  term-less storage domain); it is *also* `is_eq_only()` (no `_ord`), so the
  harness checks storage-only **first**.
- **Generator: no changes needed.** The SQL generator already handles a
  zero-term, single-domain type — it emits exactly three files (`boolean_types.sql`,
  `boolean_functions.sql`, `boolean_operators.sql`; no `_aggregates.sql`, since no
  ordered domain). All 47 functions are `plpgsql` blockers, all 47 `CREATE OPERATOR` statements back
  onto them: every comparison/containment/path operator reachable through domain
  fallback raises. The domain `CHECK` still pins `{v,i,c}` + `VALUE->>'v' = '3'`.
- **Kind, not term.** Add a `ScalarKind` variant (`Bool`) with
  `rust_type() = "bool"`, `as_bounded_int() = None`,
  `is_int`/`is_temporal`/`is_text` all false. Add a `Fixture::Bool(bool)` variant
  and a `fixtures!(bool; …)` arm. No new `Term` — storage-only carries none.
- **Fixtures carry no index term.** The `Fixture` list is both boolean values;
  the fixture is generated with **zero** indexes (`FixtureSpec::storage_only()`),
  so the encrypted payload is `{v,i,c}` only — no `hm`/`ob`/`bf`. The
  `scalar_fixture!(storage, …)` arm stamps this and asserts both values are
  present and no index is declared.
- **Harness: hand-written `impl ScalarType`, NOT `OrderedScalar`.** The
  proc-macro emits `impl ScalarType` only for integer kinds, so `boolean` is
  hand-written in `scalar_domains.rs` (`PG_TYPE = "bool"`, `fixture_values()` =
  `[false, true]` from the catalog). It is deliberately **not** `OrderedScalar`,
  `SignedScalar`, or `MatchScalar` — it has no comparison pivots, sign boundary,
  or match capability, so any ordered/signed/match-bounded test instantiated for
  `boolean` is a compile error.
- **Matrix: `caps = [storage]`.** Because there are no comparison/index/order
  categories to run, the `[storage]` arm does **not** expand
  `scalar_domain_matrix!` (whose `+`-arity transcribers reject the empty
  `eq_domains`/`pivots`/`index_combos`, and which the other seven types depend
  on). Instead it invokes only the surface-agnostic leaf drivers directly:
  sanity, blocker-raises (every comparison + containment op), payload-check,
  path-op blockers, native-absent (`~~`/`~~*`), typed-column blockers, count,
  aggregate-typecheck (asserts `min`/`max` are *rejected*), and fixture-shape.
- **Inventory: a fourth snapshot.** The storage-only test-name set is neither a
  strip-filter subset of the ordered baseline nor a superset, so it is committed
  directly as `tests/sqlx/snapshots/matrix_tests_storage_only.txt`, and the
  `test:matrix:inventory` gate gains a fourth `cmp` branch
  (`shape="storage_only"`).

Everything else is the standard path: one catalog row, regenerate, commit the
generated `src/v3/scalars/boolean/` SQL (3 files), no edits to
`pin_search_path_v3.sql` or `splinter.sh` (a storage-only type emits only blockers
— no extractors/wrappers/aggregates, so no new inline-critical names).
