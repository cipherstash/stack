---
'@cipherstash/eql': minor
---

Security: the ORE block comparator (`eql_v3_internal.compare_ore_block_256_term`
and `compare_ore_block_256_terms`, behind every ordered ORE operator and the ORE
operator class) now runs a constant number of operations for operands of the
same shape (term count, term width, NULL positions), whether and wherever they
differ. Previously its run time depended on where two values first differ, so a
party able to time queries could learn how long a prefix their query value
shares with stored values. For text the effect was large: a comparison took
about 11 µs when the first term differs and 47 µs when only the sixth does.
Results are unchanged. Single-term comparisons cost about 6% more when the
terms differ and about 36% more (roughly 1 µs) when they are equal, since equal
terms now run the hash too; text comparisons now take about 18 µs whatever the
operands. Multi-term (text) values now check every paired term, so a
malformed or mismatched-width term after the first difference, or one paired
with a NULL element, raises instead of being skipped; see
[U-001](../../docs/upgrading/v3.1.md#u-001-block-ore-text-comparisons-check-every-term)
for how to find such rows before upgrading. A timing harness is in
`packages/eql/tests/timing/ore_block_256/`.
