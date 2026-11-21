# EQL v4 block ORE comparator timing harness

Checks that `eql_v4_internal.compare_ore_block_v2_terms`, the comparator
behind every ordered block ORE operator and operator class in EQL v4, takes
the same time wherever its operands first differ, and whether they differ at
all. EQL v4 compares ore-rs's 6-bit block ORE (the fixed-width scheme and
the chained one), a different format from EQL v3's under the same `ob` key,
with a comparator of its own.

## Why it matters

The database operator gains nothing from the comparator's timing: they hold
the stored ciphertexts and can run the comparator on any two of them. The
party who gains is someone who can issue queries and time them without
reading the stored ciphertexts, such as an application user. Query results
already tell them the order of their value relative to stored ones. If the
comparison time depends on where the two values first differ, timing also
tells them how long a prefix they share.

PL/pgSQL is not a constant-time environment. What it can give is a constant
*operation count*: for operands of one shape, the same statements and
function calls whatever their contents. The shape is the scheme and the two
block counts, which a term's length reveals anyway, so the comparator may
branch on it. The v4 comparator runs one statement per compared block, which
evaluates both of the block's comparisons and latches the first difference
arithmetically, runs the hash exactly once on every path (equal terms
included), and selects its result arithmetically. C-level effects inside
those statements (`memcmp` stopping early within 16 bytes, the offset a
`substr` reads at) remain, orders of magnitude smaller.

## Running it

From `packages/eql`:

```sh
mise run build
# a scratch database with the EQL v4 bundle installed, e.g.:
psql "$DATABASE_URL" -f release/cipherstash-encrypt-v4.sql
DATABASE_URL=postgres://... tests/timing/ore_block_v2/run.sh          # 100k samples per kind
DATABASE_URL=postgres://... tests/timing/ore_block_v2/run.sh 20000    # quick check
```

It needs `psql` and `cargo`, and no CipherStash credentials: `ctgen/` encrypts
with ore-rs under a random throwaway key. Run it on a quiet machine. It is not
a CI test, because timing on shared runners is too noisy to gate on.

Everything it creates lives in an `ore_v2_timing` schema, dropped on exit. If
that schema already exists, it refuses to run rather than touch it.

## Method

`ctgen` produces real ore-rs ciphertexts, one term per side, in four kinds
of two classes each, plus a correctness set. It encrypts through ore-rs's
`BlockOre` and vitaminc-ore, as stack-encrypt does, so text is encoded as a
marker byte and then the text:

- **fixed**: `u64` terms of the fixed-width scheme (11 blocks), differing in
  the first block against differing only in the last;
- **equal**: a `u64` against a second encryption of the same value (a
  different nonce, no block differs), against a first-block difference;
- **chained**: 31-character text of the chained scheme (32 bytes encoded,
  a 32-byte bucket, 43 blocks), differing in the first character against
  only the last;
- **prefix**: 10-character text (11 bytes encoded, a 16-byte bucket, 22
  blocks) against 26 encoded bytes (a 32-byte bucket, 43 blocks) whose first
  22 blocks equal it, so the
  block counts settle the order, against the same shapes differing in the
  first block;
- **checks**: 1,500 random pairs of either scheme with shared prefixes of
  every length, whose expected sign is the plaintext order and, in `ctgen`,
  ore-rs's own comparator's. The harness refuses to time a comparator that
  gets any of them wrong, either way round.

Sampling follows dudect, with three lessons from the ore.rs benches built in:

1. **Both classes share one table, in random order.** With separate storage
   per class, placement alone produced a timing difference.
2. **Several comparisons per sample** (16 for the fixed-width kinds, 8 for
   the chained ones), so a sample spans many ticks of `clock_timestamp()`'s
   microsecond clock. Each comparison's pair is drawn at random, with
   replacement, from that class.
3. **The plain Welch t over every sample**, not a percentile-cropped maximum.
   Cropping turns a difference in spread into a large t with no difference in
   mean.

Classes are chosen at random per sample, so drift affects both equally. `|t| < 5` over a hundred thousand samples
counts as no detectable difference.

## Results

These were measured with ore-rs 0.9.0's ciphertexts, before `ctgen` moved to
0.10. The wire format the comparator reads (the headers, the block counts,
the halves) did not change, and the text shapes above give the same block
counts as they did.

PostgreSQL 17.5 run natively on macOS, Apple silicon, 100,000 samples per
kind, two runs. The machine was shared with other builds, which shows in
the difference between the runs' means; classes are drawn at random per
sample, so drift affects both equally.

| kind | run 1 t | run 2 t | mean µs per sample (run 2, class 0 / 1) |
|---|---:|---:|---|
| fixed, first vs last block | −1.22 | +0.33 | 192.3 / 191.4 |
| fixed, equal vs first block | −0.65 | −0.40 | 168.1 / 168.1 |
| chained, first vs last block | +0.74 | +0.09 | 204.5 / 204.5 |
| chained, prefix vs first block | −2.33 | −4.01 | 159.2 / 159.5 |

None passes |t| = 5. The prefix kind is negative on both runs: class 0,
where the block counts settle the order, is faster by about 0.3 µs per
sample of eight comparisons, some 40 ns a comparison, or 0.2% of one. That
is below the cost of a single statement, so it is a C-level effect of the
kind described above, not a skipped statement. A skipped hash or an early
exit would cost a statement or more per comparison.

Cost: about 10.5 µs per fixed-width comparison of 11 blocks and about
20 to 25 µs per chained comparison of 22 to 43 blocks, whatever the
operands.
