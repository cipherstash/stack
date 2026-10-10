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

## Method

`ctgen` produces real legacy ORE ciphertexts (the 8-bit block scheme, 408
bytes per u64 term) in two shapes, plus a correctness set:

- **single term**: pairs differing in the first block against pairs differing
  only in the last (block 7);
- **six terms** (text-shaped values): pairs differing in the first term
  against pairs differing only in the sixth;
- **checks**: 1,500 random pairs of 1 to 6 terms, with shared prefixes of
  every length, compared against plaintext order and for antisymmetry. The
  harness refuses to time a comparator that gets any of them wrong.

Sampling follows dudect, with three lessons from the ore.rs benches built in:

1. **Both classes share one table, in random order.** With separate storage
   per class, placement alone produced a timing difference.
2. **Several comparisons per sample** (16 single-term, 8 six-term), so a
   sample spans many ticks of `clock_timestamp()`'s microsecond clock.
3. **The plain Welch t over every sample**, not a percentile-cropped maximum.
   Cropping turns a difference in spread into a large t with no difference in
   mean.

Classes are chosen at random per sample, so drift affects both equally.
`|t| < 5` over a few hundred thousand samples counts as no detectable
difference.

## Results

PostgreSQL 17.11, aarch64 (Docker on an Apple M1 Max), 200,000 single-term
samples of 16 comparisons and 50,000 six-term samples of 8, two runs each:

| comparator | single term: t | six terms: t | cost |
|---|---:|---:|---|
| before | +4.9, +13.9 | −1552, −2575 | 155 µs per 16 single-term (median); 11 µs (first term differs) to 47 µs (sixth differs) per six-term comparison |
| after | +1.8, +1.1 | +4.5, +2.7 | about 3–8% more single-term; 31 µs per six-term comparison, either way |

The "before" single-term figures are small only by coincidence. Each block
after the first difference ran extra statements, and the `OR` short-circuit
skipped a comparison on the same blocks; on this machine the two nearly
cancel. With the short-circuit removed, the same code gave t = +388, about
0.7 µs per comparison.
