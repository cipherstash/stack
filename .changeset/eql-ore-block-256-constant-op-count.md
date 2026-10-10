---
'@cipherstash/eql': patch
---

Security: the ORE block comparator (`eql_v3_internal.compare_ore_block_256_term`
and `compare_ore_block_256_terms`, behind every ordered ORE operator and the ORE
operator class) now runs a constant number of operations whatever its operands.
Previously its run time depended on where two values first differ, so a party
able to time queries could learn how long a prefix their query value shares with
stored values. For text the effect was large: a comparison took about 11 µs when
the first term differs and 47 µs when only the sixth does. Results are unchanged.
Single-term comparisons cost about 3-8% more; text comparisons now take about
31 µs whatever the operands. Multi-term (text) values now length-check every
paired term, so a malformed term after the first difference raises instead of
being skipped. A timing harness is in `packages/eql/tests/timing/ore_block_256/`.
