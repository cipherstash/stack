# ORE comparator timing harness

Checks that `eql_v3_internal.compare_ore_block_256_terms`, the comparator
behind every ordered ORE operator and the ORE operator class, takes the same
time wherever its operands first differ, and whether they differ at all.

## Why it matters

The database operator gains nothing from the comparator's timing. They hold
the stored ciphertexts and can run the comparator on any two of them
directly, which tells them everything its timing could. The party who gains
is someone who can issue queries and time them without reading the
stored ciphertexts, such as an application user. Query results already tell
them the order of their value relative to stored ones. If the comparison time
depends on where the two values first differ, timing also tells them how long
a prefix they share. For text that was a large effect: about 11 µs per
comparison when the first of six terms differs, 47 µs when only the sixth
does.

PL/pgSQL is not a constant-time environment. What it can give is a constant
*operation count*: for operands of the same shape, the same statements and
function calls whatever their contents, so nothing at the scale of a
statement (fractions of a microsecond) depends on where or whether they
differ. The shape is the term count, the term width and the position of any
NULL element. It is public structure, and the comparator may branch on it:
a single term and a six-term value take different paths. C-level effects inside those statements (`memcmp` stopping early
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
- **equal term**: a single term against itself, against pairs differing in
  the first block;
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
   sample spans many ticks of `clock_timestamp()`'s microsecond clock. Each
   comparison's pair is drawn at random, with replacement, from that class.
3. **The plain Welch t over every sample**, not a percentile-cropped maximum.
   Cropping turns a difference in spread into a large t with no difference in
   mean.

Classes are chosen at random per sample, so drift affects both equally.
`|t| < 5` over a few hundred thousand samples counts as no detectable
difference.

## Results

PostgreSQL 17.11, aarch64 (Docker on an Apple M1 Max). Welch t for two runs
each; the current comparator at 200,000 samples of 16 comparisons for the
single-term kind and 50,000 samples of 8 for each multi-term kind, each split
at random between the kind's two classes:

| comparator | single term | equal term | six terms | prefix | NULL element |
|---|---:|---:|---:|---:|---:|
| original (term by term) | +4.9, +13.9 | | −1552, −2575 | +517, +459 ¹ | +520, +682 ¹ |
| first constant-count version ² | +1.8, +1.1 | | +4.5, +2.7 | −62, −69 ³ | −60, −70 ³ |
| current | +2.24, +0.15 | | +1.03, −0.27 | −0.68, +0.18 | −0.57, +0.14 |
| current, second machine ⁴ | +1.60, +0.71 | −2.49, −1.99 | −2.58, +1.33 | −4.96, −1.19, −2.56, −7.42, −5.14 | −3.82, −9.63, −2.23, −3.88, −2.88 |

¹ 5,000 samples per run. ² It scanned every block of every term, and skipped
its hash when the term counts or a NULL settled the order. ³ 10,000 samples
per run. ⁴ PostgreSQL 17.5 run natively on macOS, Apple silicon, at the same
sample counts, with three more runs of the prefix and NULL kinds.

On the second machine the prefix and NULL-element kinds come out negative on
every run, and three runs pass |t| = 5. Class 0, where the structure settles
the order, is faster by 0.1 to 0.2 µs per sample of eight comparisons: about
20 ns a comparison, or 0.2% of one. That is below the cost of a single
statement, so it is a C-level effect of the kind described above, not a
skipped statement; a skipped hash showed up as t = −60 to −70 at a tenth of
the samples. The equal-term class shows the same sign at about 6 ns a
comparison.

Cost: the current comparator takes about 6% more than the original per
single-term comparison when the terms differ, and about 36% more when they are
equal (3.6 µs against 2.7 µs on the second machine, calling
`compare_ore_block_256_term` directly), because equal terms now run the hash
too. Duplicates are common in index builds, `ORDER BY` ties and equality
probes on ORE columns, so expect ordered workloads with many ties to see the
larger figure. It takes about 18 µs per six-term comparison whatever the
operands. The original took 11 µs when the first term differs and 47 µs when
only the sixth does; the first constant-count version took 31 µs.

The original's single-term figures are small only by coincidence. Each block
after the first difference ran extra statements, and the `OR` short-circuit
skipped a comparison on the same blocks; on this machine the two nearly
cancel. With the short-circuit removed, the same code gave t = +388, about
0.7 µs per comparison.
