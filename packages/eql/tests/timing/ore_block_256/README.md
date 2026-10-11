# ORE comparator timing harness

Checks that `eql_v3_internal.compare_ore_block_256_terms`, the comparator
behind every ordered ORE operator and the ORE operator class, takes the same
time wherever its operands first differ.

## Why it matters

The comparator's inputs are ciphertexts, so the database operator learns
nothing from its timing: they can run the comparison themselves. The party
who gains is someone who can issue queries and time them without reading the
stored ciphertexts, such as an application user. Query results already tell
them the order of their value relative to stored ones. If the comparison time
depends on where the two values first differ, timing also tells them how long
a prefix they share. For text that was a large effect: about 11 µs per
comparison when the first of six terms differs, 47 µs when only the sixth
does.

PL/pgSQL is not a constant-time environment. What it can give is a constant
*operation count*: the same statements and function calls on every path, so
nothing at the scale of a statement (fractions of a microsecond) depends on
the data. C-level effects inside those statements (`memcmp` stopping early
within 16 bytes, the offset a `substr` reads at) remain, orders of magnitude
smaller. The Rust comparator in ore.rs is constant-time at the instruction
level; this is the PL/pgSQL counterpart.

## Running it

From `packages/eql`:

```sh
mise run build
# a scratch database with EQL installed, e.g.:
psql "$DATABASE_URL" -f release/cipherstash-encrypt.sql
DATABASE_URL=postgres://... tests/timing/ore_block_256/run.sh          # 200k samples, a few minutes
DATABASE_URL=postgres://... tests/timing/ore_block_256/run.sh 20000    # quick check
```

It needs `psql` and `cargo`, and no CipherStash credentials: `ctgen/` encrypts
with ore-rs under a random throwaway key. Run it on a quiet machine. It is not
a CI test, because timing on shared runners is too noisy to gate on.

Everything it creates lives in an `ore_timing` schema, dropped on exit. If that
schema already exists, it refuses to run rather than touch it.

## Method

`ctgen` produces real legacy ORE ciphertexts (the 8-bit block scheme, 408
bytes per u64 term) in two shapes, from which the harness builds two more,
plus a correctness set:

- **single term**: pairs differing in the first block against pairs differing
  only in the last (block 7);
- **six terms** (text-shaped values): pairs differing in the first term
  against pairs differing only in the sixth;
- **prefix**: five terms against six, where the five equal the first five of
  the six (the order is settled by the term counts), against five terms
  against six that differ in the first term;
- **NULL element**: five terms and a NULL against six, where the five equal
  the first five of the six (the order is settled by the NULL), against the
  same with a first-term difference;
- **checks**: 1,500 random pairs of 1 to 6 terms, with shared prefixes of
  every length, compared against plaintext order and for antisymmetry. The
  harness refuses to time a comparator that gets any of them wrong.

Sampling follows dudect, with three lessons from the ore.rs benches built in:

1. **Both classes share one table, in random order.** With separate storage
   per class, placement alone produced a timing difference.
2. **Several comparisons per sample** (16 single-term, 8 multi-term), so a
   sample spans many ticks of `clock_timestamp()`'s microsecond clock.
3. **The plain Welch t over every sample**, not a percentile-cropped maximum.
   Cropping turns a difference in spread into a large t with no difference in
   mean.

Classes are chosen at random per sample, so drift affects both equally.
`|t| < 5` over a few hundred thousand samples counts as no detectable
difference.

## Results

PostgreSQL 17.11, aarch64 (Docker on an Apple M1 Max). Welch t for two runs
each; the current comparator at 200,000 single-term samples of 16 comparisons
and 50,000 multi-term samples of 8 per class:

| comparator | single term | six terms | prefix | NULL element |
|---|---:|---:|---:|---:|
| original (term by term) | +4.9, +13.9 | −1552, −2575 | +517, +459 ¹ | +520, +682 ¹ |
| first constant-count version ² | +1.8, +1.1 | +4.5, +2.7 | −62, −69 ³ | −60, −70 ³ |
| current | +2.24, +0.15 | +1.03, −0.27 | −0.68, +0.18 | −0.57, +0.14 |

¹ 5,000 samples per run. ² It scanned every block of every term, and skipped
its hash when the term counts or a NULL settled the order. ³ 10,000 samples
per run.

Cost: the current comparator takes about 6% more than the original per
single-term comparison, and about 18 µs per six-term comparison whatever the
operands. The original took 11 µs when the first term differs and 47 µs when
only the sixth does; the first constant-count version took 31 µs.

The original's single-term figures are small only by coincidence. Each block
after the first difference ran extra statements, and the `OR` short-circuit
skipped a comparison on the same blocks; on this machine the two nearly
cancel. With the short-circuit removed, the same code gave t = +388, about
0.7 µs per comparison.
