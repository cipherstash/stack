# Matrix coverage inventory snapshot

This directory holds the canonical committed snapshot, `matrix_tests.txt` — the
token-normalized list of every `scalars::<T>::*` test name in the
`encrypted_domain` SQLx binary, with each type token replaced by the literal
`<T>` — plus three shape variants derived from / committed alongside it
(`matrix_tests_eq_only.txt`, `matrix_tests_text.txt`,
`matrix_tests_storage_only.txt`; see below). They are
**committed test baselines**, not gitignored generated SQL — keep them in
version control.

**Regenerating: use the one atomic command.** The four scalar shapes are not
independent — eq-only is *derived* from the ordered baseline — so regenerating
them one at a time off stale inputs is how a shape silently drifts (see issue
#300). Regenerate all four at once with:

```bash
mise run test:matrix:snapshots:regen
```

It lists the `encrypted_domain` binary once and rewrites `matrix_tests.txt`,
`matrix_tests_eq_only.txt`, `matrix_tests_text.txt`, and
`matrix_tests_storage_only.txt` in dependency order, then validate with
`mise run test:matrix:inventory` and commit any changes. The per-shape `grep`/`sed`
recipes below document what that task does for each shape (and how the inventory
gate re-derives them); prefer the single command over running them by hand. The
two sibling snapshots (`matrix_jsonb_entry_tests.txt`, `v3_jsonb_tests.txt`) are
**not** covered by it — they have their own recipes lower down.

The per-type `<T>_matrix_tests.txt` files are gone. They were byte-identical
modulo the type token (the matrix tests are macro-generated from one
`scalar_matrix!` invocation per type with no per-type variation), so a
single canonical set plus a per-type normalize-and-compare carries the same
signal at a fraction of the committed surface.

For equality-only types there is a second committed snapshot,
`matrix_tests_eq_only.txt`. An eq-only scalar (`scalar_matrix! { caps = [eq] }`,
e.g. `timestamp`) emits exactly the ordered name set MINUS the ord-only lines,
so this file is **derived** from `matrix_tests.txt` (minus every line matching
`_ord` / `order_by`) — but it is committed and pinned: the
inventory gate re-derives the set at runtime and asserts it equals this
committed file, so a change to the ordered baseline or the strip filter that
alters the eq-only set fails until the snapshot is deliberately regenerated.
Eq-only types are then matched against the committed snapshot. The
`matrix_tests.txt` baseline itself is always the ordered (`caps = [eq, ord]`)
shape. Regenerate the eq-only snapshot with:

```bash
grep -vE '_ord|order_by' snapshots/matrix_tests.txt | LC_ALL=C sort -u > snapshots/matrix_tests_eq_only.txt
```

For the **text** shape there is a third committed snapshot,
`matrix_tests_text.txt`. A text scalar (`scalar_matrix! { caps = [eq, ord, search] }`)
runs the combined `_search` domain (equality + ordering + bloom match) through
the matrix in addition to the ordered shape, so its name set is a **superset**
of the ordered baseline: every ordered arm PLUS the text-only `_search` /
`_eqidx` (equality-via-`eq_term` index split) / `_match` (bloom `@>`/`<@`
containment) arms. Unlike eq-only this superset is **not** derivable by a strip
filter, so it is committed directly. The inventory gate pins it two ways: each
discovered type must match it exactly (after `<T>` normalization), and the gate
asserts it is a strict superset of the ordered baseline (no ordered arm may be
missing for text). Regenerate the text snapshot with:

```bash
cd tests/sqlx
cargo test --no-default-features --test encrypted_domain -- --list \
  | sed -n 's/: test$//p' | grep '^scalars::text::' \
  | sed -e 's/^scalars::text::/scalars::<T>::/' -e 's/_text_/_<T>_/g' | LC_ALL=C sort > snapshots/matrix_tests_text.txt
```

For the **storage-only / encryption-only** shape there is a fourth committed
snapshot, `matrix_tests_storage_only.txt`. A storage-only scalar
(`scalar_matrix! { caps = [storage] }`, e.g. `boolean`) has a single term-less
domain and **no** comparison/index/order capability, so its name set is neither
a strip-filter subset of the ordered baseline nor a superset — it is the
storage-domain surface arms only (sanity, blocker-raises for every comparison +
containment op, payload-check, path-op, native-absent, typed-column, count,
aggregate-typecheck, fixture-shape). It is committed directly and each
storage-only type must match it exactly (after `<T>` normalization). Regenerate
with:

```bash
cd tests/sqlx
cargo test --no-default-features --test encrypted_domain -- --list \
  | sed -n 's/: test$//p' | grep '^scalars::boolean::' \
  | sed -e 's/^scalars::boolean::/scalars::<T>::/' -e 's/_boolean_/_<T>_/g' | LC_ALL=C sort > snapshots/matrix_tests_storage_only.txt
```

The "no per-type variation" property is preserved by design: every ordered
scalar sweeps the same three `OrderedScalar` pivots (`min`/`mid`/`max`), so the
`_pivot_mid_*` arms are identical modulo token across `int`/`date`/`text`. The
**signed-only** sign-boundary test (`SignedScalar`, `int`/`date` only) lives
*outside* the `scalars::<T>::` namespace (in `encrypted_domain/signed.rs`,
mirroring the `text_match` suites), so it is deliberately invisible to this
inventory — keeping one canonical set rather than per-capability snapshots.

## What it guards

The SQLx assertions verify that the tests which run produce the right results.
They cannot see a test that *stops running* — a matrix test that is deleted,
renamed, or hidden behind a `#[cfg]` gate simply vanishes silently, quietly
shrinking coverage. This snapshot closes that gap: it pins the *set of test
names* so any such change shows up as an added/removed line in the PR diff.

## How it is generated / checked

Run:

```bash
mise run test:matrix:inventory
```

The task (`mise.toml`, `[tasks."test:matrix:inventory"]`):

1. Lists the `encrypted_domain` binary ONCE with
   `cargo test --no-default-features --test encrypted_domain -- --list`.
2. Discovers the set of scalar types present **from the binary's own output**
   (the `scalars::<X>::` prefixes) — never a directory glob.
3. Normalizes each type's token to `<T>` and asserts that type's set equals the
   canonical `matrix_tests.txt` (ordered shape), the derived eq-only subset
   (`matrix_tests.txt` minus `_ord`/`order_by`), the
   committed `matrix_tests_text.txt` superset (text shape), or the committed
   `matrix_tests_storage_only.txt` set (storage-only shape). Prints each type's
   resolved shape (`ordered` / `eq_only` / `text` / `storage_only`). Asserts at
   least one type is present.
4. **Completeness cross-check:** asserts the discovered type set equals
   `cargo run -p eql-codegen -- list-types` (the catalog is the single source).
   A catalog type added without its matrix wiring — no `scalars::<T>::` tests in
   the binary — fails here.

`LC_ALL=C sort` makes ordering byte-stable across locales. No database is
required — `--list` only enumerates; the suite uses runtime queries.

It pins `--no-default-features` so the inventory is deterministic regardless of
the caller's local flags. That deliberately excludes the `scale` feature arm
(`#[cfg(feature = "scale")]`) — a known blind spot of this inventory, covered
instead by the scale gate plus the `family::mutations` negative controls.

## CI enforcement

The `matrix-coverage` job in `.github/workflows/test-eql.yml` runs the same
task, then `git add -N tests/sqlx/snapshots` and
`git diff --exit-code -- tests/sqlx/snapshots`. The `git add -N` makes a
brand-new, never-committed snapshot trip the diff too. A divergence (or a failed
catalog cross-check) fails the job.

## When you must update this

- **Adding a new scalar type** → add the catalog row in
  `eql-domains::CATALOG`, wire the SQLx matrix oracle (see
  `docs/reference/adding-a-scalar-encrypted-domain-type.md` §3), then run
  `mise run test:matrix:inventory`. No snapshot edit is needed for an ordered
  (`caps = [eq, ord]`) type (matches the canonical baseline) or an equality-only
  (`caps = [eq]`) type (matches the derived eq-only subset). A **storage-only**
  (`caps = [storage]`) type matches `matrix_tests_storage_only.txt`; if it is the
  first such type, commit that snapshot. The cross-check confirms the type is wired.
- **Removing a scalar type** → remove the catalog row and its matrix wiring; the
  cross-check then sees the type gone from both sides.
- **Changing which matrix tests the macro emits** → regenerate and commit **all
  affected shape snapshots** in the same change. A macro change can touch more
  than one shape at once (issue #300: a dispatch arm that began emitting for the
  storage-only shape too), so regenerate them atomically rather than by hand:
  ```bash
  mise run test:matrix:snapshots:regen   # rewrites all four shapes from one listing
  mise run test:matrix:inventory         # validate, then commit any changed snapshot
  ```

See `docs/reference/adding-a-scalar-encrypted-domain-type.md` §3 (matrix oracle + inventory snapshot).

## matrix_jsonb_entry_tests.txt

`matrix_jsonb_entry_tests.txt` pins the test-name set for the jsonb SteVec-entry
behaviour matrix (`jsonb_entry_matrix!`), whose names live under
`jsonb_entry::…`. It is a deliberate **sibling** of the scalar matrix inventory
above, **not** folded into it: the driver type (`JsonbEntryInteger`) is intentionally
not an `eql-domains::CATALOG` type, so it has no `scalars::<T>::` tests and no
`eql-codegen list-types` row — hence this snapshot is checked on its own, with
**no catalog cross-check**. The matrix reuses the scalar matrix generators to
exercise `eql_v3.jsonb_entry` equality/order/aggregate behaviour. No database
is required (`--list` only enumerates).

Verify with `mise run test:matrix:inventory:jsonb_entry`. Regenerate with:

```bash
cd tests/sqlx
cargo test --no-default-features --test encrypted_domain -- --list \
  | sed -n 's/: test$//p' | grep '^jsonb_entry::.*jsonb_entry_integer' \
  | sed -E 's/_integer_/_<T>_/' | LC_ALL=C sort -u > snapshots/matrix_jsonb_entry_tests.txt
```

## ope_tests.txt

`ope_tests.txt` pins the test-name set for the nine CLLW-OPE suites
(`tests/encrypted_domain/ope/`) — the `<t>_ord_ope::…` modules covering every
catalog `_ord_ope` domain (literal-payload SQL-surface smoke tests plus the
real-ciphertext fixture tests). Like
`matrix_jsonb_entry_tests.txt` it is a deliberate **sibling** of the scalar
matrix inventory, **not** folded into it: the ope suites live as top-level
modules (outside `scalars::`, so the type-discovery step does not mis-read
them as scalar types), and their per-type name sets are not uniform — the
integer reference module carries the deeper single-type behaviour (prefix
order, blockers, ORDER BY forms, aggregates) and text pins its hm-routed
equality — so no single `<T>`-normalized baseline fits. The snapshot therefore
pins the **full un-normalized list**: every individual ope test name (the
per-test pinning deferred from #340 review). No database is required (`--list`
only enumerates).

Verify with `mise run test:matrix:inventory:ope`. Regenerate with:

```bash
cd tests/sqlx
cargo test --no-default-features --test encrypted_domain -- --list \
  | sed -n 's/: test$//p' | grep -E '^[a-z0-9_]+_ord_ope::' \
  | LC_ALL=C sort > snapshots/ope_tests.txt
```

## v3_jsonb_tests.txt

`v3_jsonb_tests.txt` pins the SQLx test-name set for the hand-written
`eql_v3.json` harness and its signature-aware operator-surface guard. It catches
silent coverage shrinkage in macro-generated blocker/NULL/path cases.

Regenerate with:

```bash
cd tests/sqlx
cargo test --test v3_jsonb_tests --test v3_jsonb_operator_surface_tests -- --list \
  | sed -n 's/: test$//p' \
  | LC_ALL=C sort > snapshots/v3_jsonb_tests.txt
```

CI verifies it with `mise run test:v3-jsonb:inventory`.

## Macro expansion body snapshots (`*_expanded.rs`)

`integer_expanded.rs`, `text_expanded.rs`, and `boolean_expanded.rs` are a **different
kind** of snapshot from the `matrix_tests*.txt` inventories above. The inventories
pin the *set of test names*; these pin the **generated bodies** — the actual
`cargo expand` output of the `scalar_matrix!` macro. The inventory catches a whole
arm being added or removed; the expansion snapshot catches a change *inside* a
generated body that leaves the name set unchanged.

One snapshot per **reachable** `scalar_matrix!` arm (`tests/sqlx/src/matrix.rs`),
because the arms emit structurally different bodies and none subsumes another:

| snapshot | type | arm | unique body surface |
|----------|------|-----|---------------------|
| `integer_expanded.rs` | `integer` | `caps = [eq, ord]` | the `ord`/`ord_ore` btree combo carries `=` **plus** the four ordering ops on one index — proves `=` rides the ORE ordered index (the path all eight integer/temporal/float types use) |
| `text_expanded.rs` | `text` | `caps = [eq, ord, search]` | `=` split into separate `*_eqidx` combos; `_match`/`_search` bloom (`@>`/`<@`) and GIN arms |
| `boolean_expanded.rs` | `boolean` | `caps = [storage]` | single term-less domain; bypasses `scalar_domain_matrix!`, calling the leaf drivers directly (every comparison/containment op is a blocker) |

`text` does **not** make `integer` redundant: its `ord` btree combo omits `=` (moved
to `_eqidx`), so the "`=` rides the ORE ordered index" body exists only in the
`integer` snapshot. The `caps = [eq]` arm has no consumer and is uncovered by design.

These are **committed** (tracked), unlike the gitignored generated SQL. They carry
`linguist-generated` via `.gitattributes` so GitHub collapses them in diffs.

### Regenerating

Requires the pinned nightly toolchain + `cargo-expand` (both single-sourced in
`mise.toml`); no database or CipherStash creds (expand-only, fixtures emptied):

```bash
mise run test:matrix:expand   # rewrites all three *_expanded.rs
```

Pinning another arm is one edit to the `TARGETS=(...)` list in the
`test:matrix:expand` task. The nightly lane in
`.github/workflows/macro-expand-eql.yml` regenerates and `git diff --exit-code`s
all three (non-blocking: nightly-only, off the PR critical path).

## `eql_v3` public-surface golden — `eql_v3_public_surface.txt`

Exhaustive snapshot of every object visible in the **public** `eql_v3` schema:
domains/composites/enums, functions, aggregates, operators, and casts, each
rendered as a normalized, schema-qualified line and `LC_ALL=C`-sorted. Owned by
`tests/sqlx/tests/v3_public_surface_tests.rs::eql_v3_public_surface_matches_golden`, it pins
*what the split puts in the public API* — the point of the `eql_v3` /
`eql_v3_internal` split is to keep index-term-only types out of what a Supabase
Studio user sees, and nothing else in the suite gates that. Any object
added/removed/renamed in `eql_v3` forces a conscious update here.

Unlike the matrix snapshots (regenerated DB-free via `--list`), this one is
**DB-backed** — the test reads `pg_catalog` from the installed schema, so a
running Postgres reachable via `DATABASE_URL` is required. It is **committed**
(tracked) and enforced by the normal SQLx suite: the test embeds the file via
`include_str!` and asserts against the live surface (no separate `git diff` gate
needed — a drift fails the test directly). Regenerate with:

```bash
mise run test:surface:snapshot:regen   # writes eql_v3_public_surface.txt
```

then re-run `mise run test:sqlx` to validate and commit. If an object should be
*internal*, create it in `eql_v3_internal` instead of regenerating the golden.
The companion placement invariants in the same test file (no naked
composite/enum types in `eql_v3`; every public type is a jsonb-backed domain;
every `eql_domains::CATALOG` domain landed in `eql_v3`) are structural and need
no snapshot.
