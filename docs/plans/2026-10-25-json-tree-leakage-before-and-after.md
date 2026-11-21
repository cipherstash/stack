# The json_tree leakage profile, before and after #1363

**Date:** 2026-10-25. **Pull request:** #1362 (branch `test/json-tree-leakage-profile`), now based on #1363 (`feat/json-tree-derivable-tokens`).

This note compares two versions of one test, and through them two versions of EQL v4's encrypted JSON column, `json_tree`. It is written for someone new to both.

## What the test is

A `json_tree` column stores each JSON document as a list of encrypted entries, one per node of the document, so PostgreSQL can answer queries over it without the key. The database cannot read a value, but it can see a great deal of structure, and `packages/eql/docs/reference/json-tree-leakage.md` (the **leakage page**) says in prose exactly what it learns.

PR #1362 turns that page into a test, in `packages/stack-encrypt/tests/json_leakage/`:

- The **profile**, `L` (`profile.rs`), is the page written as code: a function of the plaintext documents and queries alone that outputs what the page says the database learns. Every secret-derived value (a selector, a token, an ordering term) is replaced by an opaque integer that is equal exactly where the real bytes are equal. Each field of its output is one **clause** of the page.
- The **simulator** (`simulator.rs`) builds a fake column and a fake query log from `L`'s output and random bytes, with no plaintext and no key.
- The **distinguishers** (`distinguishers.rs`) are computations a curious database administrator could run on what the database holds and is sent: which entries share a selector, how long each ciphertext is, what a token finds when it walks the parent tags, and so on. Each returns an exact value, so a real world and a simulated one are compared for equality.
- The **positive control** runs every distinguisher on the real scheme (documents sealed by Stack Encrypt) and on the simulation. If any distinguisher tells them apart, the real scheme reveals something the profile, and so the page, does not state.
- The **calibration** checks the test can see anything at all. Each **mutant** (`mutants.rs`) is the profile with one clause dropped or coarsened; some distinguisher must tell each mutant's simulation from the real scheme. A clause no mutant tests is a clause nobody checked.

#1362 was written against the format as it stood before #1363. #1363 changed the format. This note records what the port of the test found, and how the leakage changed.

## The net, first

The tables below grow from the old profile to the new one: more clauses, more distinguishers, more mutants. That measures the test, not the scheme. A longer profile means more of what the database sees is written down and held by a test. Measured as leakage, the format after #1363 discloses less, and less where it matters:

- A read no longer sends any token above the node it asks for. Before, a read of `$.profile.address.city` sent `$.profile`'s token, a capability over that whole field in every row of the column, for the life of the column. Now it sends the leaf's token and nothing that covers a node above it. The `ancestor_links` distinguisher exists to hold this.
- The gates are gone. Each key step and array position below the head used to reach the server in the clear, as a selector or `#n:selector`.

What is new is small. The self tag `x` is a fresh unlinkable name per entry that at rest says only that entries are distinct, which the entry count already said; a token the client sends links it, as a token always linked the parent tag. At the nodes a walk reaches, the element index was already disclosed by the gated walk's ordinals. Whether a node is a member or an element was disclosed only where selectors showed it, in an array that has two elements in some row. It is new for a node that is an only child in every row: before #1363 every child's token took one rule, and an only child's ordinal is 0 either way. The page now says so. That walk also covers fewer nodes than the old one, because no read sends a token above the node it names. A wildcard read's token count, bound and probes are a smaller form of what the plaintext gates showed. The last two sections set each item out.

## The two formats, briefly

Terms used below: a **selector** `s` is a keyed hash of a node's path, the same in every row. A **token** is a 16-byte secret for one node that lets the database find that node and walk the nodes beneath it. A **parent tag** `p` on an entry is `H8("p" ‖ iv ‖ t(parent) ‖ LE32(o))`: eight bytes derived from the parent's token, the child's **ordinal** `o` (its index if it is an array element, a keyed rank if it is an object member) and the row's random `iv`. The database enumerates a node's children by computing the parent tag of ordinals 0, 1, 2, … until one is missing.

**Before #1363** (the format #1362 was written for, at `9a7ca372c`):

- Each entry was `{s, c, p?, op?}`: selector, ciphertext, parent tag (absent on the root and, under the sealed root, on the top-level fields), ordering term (only at ordered paths).
- Every child's token was `H16("t" ‖ t(parent) ‖ s(child) ‖ LE32(o))`. A member's ordinal is a rank among its siblings' keys, which the client does not know for a row it has not read, so the client could not derive the token of anything below a top-level field except through array positions.
- A subtree read therefore sent one **head token** (the top-level field's, or the root's with the root open), and one plaintext **gate** per remaining step: the step's selector, or `#n:<selector>` with the array position `n` in the clear. The database walked from the head token through the gates (`json_tree_subtree_at`). Reading `$.profile.address.city` handed the database `$.profile`'s token: a capability over that whole top-level field, in every row, for the life of the column (#1360).

**After #1363** (the format now, at `997c64b1e`):

- Each entry is `{s, c, x, p?, op?}`. The new **self tag** is `x = H8("x" ‖ iv ‖ t(self))`, on every entry, the root and the top-level fields included.
- A member's token is `H16("t" ‖ t(parent) ‖ s)`, with no ordinal. An element's is `H16("t" ‖ t(array) ‖ s ‖ LE32(i))`, `i` its index: this is the old rule, unchanged, since an element's ordinal always was its index. The parent tag is unchanged. So the client derives any node's token from its path alone.
- A read sends `json_tree_subtree(doc, tokens text[], budget)` with the tokens of exactly the nodes it names: one for a path with no wildcard. A wildcard is expanded by the client to positions `0 … N − 1` plus a **probe** for position `N` of every array it expands; the **bound** `N` defaults to 64, so one wildcard level sends 65 tokens and two send `N² + N + 1` = 4,161, and a read past 8,192 tokens is refused. A probe that finds an element means the array is longer than `N`, and the client fails the read rather than return part of it. Gates and `json_tree_subtree_at` are gone.
- The database finds a token's node by its self tag, probes the ordinals under it by parent tag, and for each child it finds derives the child's token by testing the child's `x` against the member rule first and then the element rule.
- Past the **budget** (default 64 rows) with the root sealed, the database returns the root entry alone, whose ciphertext is the whole document, and the client evaluates the read over it.

## Step 1: what failed when the old test met the new format

The test was run unchanged on the merge of #1363 into #1362 (`848940081`). The failures, in the order they appeared, were the first evidence of what changed.

1. **It did not compile.** Two `E0308` errors in `calibration.rs`, at lines 324 and 329: `JsonSubtreeKey::token_bytes()` now returns `Vec<[u8; 16]>`, and `JsonDocument::subtree` takes `&[Tag]`. *What it taught:* a read is no longer one token; it is a list.

2. **With a throwaway two-character fix to compile it, 1 test passed and 6 failed.** Five panicked in the parser (`observe.rs:126`, "a base64 field is a string") before any distinguisher ran: the read's wire form changed from `{"t": "<token>", "g": [gates]}` to `{"t": ["<token>", …]}`. The sixth, `chain_is_the_crates_chain`, compares the harness's own walk with the crate's. For `$.a` under the sealed root, the old harness found `[(6, 1), (2, 1)]` and the crate `[(1, 0), (6, 1), (2, 1), (3, 2), (4, 2), (5, 3)]` (pairs are entry position and depth). *What it taught:* the crate now returns the named node itself at depth 0, found by its self tag, which the old walk could not identify. The old harness still found `$.a`'s two children, because the parent tag and the head token are unchanged; it stopped there because both children are members and a member's token lost its ordinal. In the column-wide run below, the old harness did reach depth 2 under array elements, whose rule did not change. The one test that passed, `the_order_reveals_the_shape`, uses no query: the attack that reads each row's shape off the stored order works exactly as before.

3. **With the parser also patched to read the first token of the list, the positive control failed on exactly five distinguishers**, on the handcrafted "shapes, sealed root" column: `wire_fields`, `token_reach`, `token_derivability`, `gated_walk_results` and `transcripts`. The random-column run failed on `wire_fields` and `transcripts`, shrunk by proptest to two empty objects under an open root and four reads of `$.a`. *What it taught:* at rest, the only thing that changed is the new `x` field (`wire_fields`). Every other stored-form feature (ciphertext lengths, selector patterns, parent-tag presence, the stored order, projections, ordering terms, headers) still agreed with the old profile. Everything else that changed is in what a query sends and what a token reaches.

4. **The page-as-written test fired six distinguishers instead of one**: `gated_walk_results`, `ordering_term_lengths`, `token_derivability`, `token_reach`, `transcripts`, `wire_fields`, where it expected exactly `ordering_term_lengths`. The jsonb key-order test still passed.

5. **The calibration passed: all 34 mutants "caught".** *What it taught:* this is the most important lesson of the run. A calibration only means something once the positive control passes. If the profile is already told apart from the real scheme, every mutant of it is too, and "all caught" says nothing. `mod.rs` now says so under "Reading a failure".

## The clauses, before and after

The "before" column is the profile at `9a7ca372c`; the "after" column is the port at `839c0f6fd` (with `fa26cb540`, which only speeds one distinguisher up). A clause is a field of the profile's output, or a switch in `Clauses`.

"Not measured" in the before column means the old profile had no such clause, for one of two reasons, and the row says which: the old format had no such thing to state (`x`, the hit rule as a rule, probes), or the old format disclosed it and the old test did not model it, so no distinguisher could see it (string folding, whose corpus was lower-case ASCII, and the budget, which the old `json_tree_subtree` also had). The second kind is the method's limit: the calibration proves the page accounts for everything the distinguishers measure, not everything the database sees, and a clause both omit is invisible to it. Each new distinguisher is a way of finding one.

| clause | before (`9a7ca372c`) | after (port) | what changed and why |
|---|---|---|---|
| `EntryLeakage::selector` | which paths, how many nodes at each, equal across rows, elements share their array's | same | unchanged |
| `EntryLeakage::parent` | each node's parent, used to place the chain | same | unchanged |
| `EntryLeakage::step` | `Root`, `Member`, `Element(i)`: decides the ordinal, and in the old chain the token too | `Root`, `Member`, `Element(i)`: decides the ordinal (the `o` of the parent tag) only | the token rule moved to `rule` |
| `EntryLeakage::rule` | not measured (the old format had no such thing) | `Member` or `Element` for every entry that chains, `None` for the root and sealed-root top-level entries | new: the database tests each reached node against the member rule then the element rule, and learns which. Beyond the page as #1363 published it; this branch adds it |
| `EntryLeakage::head` | the head token an entry is (top-level fields under the sealed root, the root otherwise) | removed | a head is now named only inside a token name (`TokenName::head`); nothing at rest refers to it |
| `EntryLeakage::has_parent_tag` | absent on the root and, under the sealed root, the top-level fields | same | unchanged |
| `EntryLeakage::self_tag` | not measured (the old format had no such thing) | a fresh opaque name per entry | new: `x` on every entry. A fresh name per entry states that it is distinct within a row and unlinkable across rows; where a sent token links an entry the simulator writes its real self tag instead |
| `EntryLeakage::ciphertext_len` | AEAD overhead (29 bytes) + kind, child count, label, scalar | same | unchanged: `x` sits beside the ciphertext. It adds a fixed 12 base64 characters per entry, 19 with its key in compact JSON (`,"x":"…"`), 21 in PostgreSQL's `jsonb` text (`, "x": "…"`); #1363 measured +9.8% on a nested document and +9.4% on a flat one |
| `EntryLeakage::ordering` / `OrderingLeak::class` | equal values share a class, ordered by `ordering_ranks`; strings ordered by their bytes | equal values share a class; strings ordered by their folded encoding (Unicode 16 NFC, case and accents folded) | the code always folded; the old corpus held only lower-case ASCII, where the two agree. The page now says "folded", and the corpus holds `"Carol"`/`"carol"` and `"ál"`/`"al"` |
| `OrderingLeak::len` | **beyond the page**: 65 bytes for a number, `8 × (len + 1) + 1` for a string | on the page: 65 for a number, `8 × (n + 1) + 1` for a string of folded length `n` | #1363's page states it; it now counts the folded length |
| `Clauses::ordering_term_length` | on/off switch for the beyond-the-page length | removed | on the page now; its mutant (`ordering_term_length_constant`) still checks it |
| `Clauses::key_order` | a reading: UTF-8 byte order vs jsonb's length-first order | same | the page now says "byte order of their key names' UTF-8 encodings"; the reading test stays to keep that sentence load-bearing |
| `Clauses::string_order` | not measured (the old format had it; the old profile did not model it) | a reading: folded vs raw bytes | new, with a test that the raw-bytes reading is told apart |
| `Clauses::hit_rule` | not measured (the old format had no such thing) | on/off switch for the member-or-element rule | new, the one clause beyond the page as #1363 published it |
| `RowLeakage::{sealed_root, keyset, data_key, entries, projection}` | header flag, keyset, data key unique to the row, entries in depth-first order with members in UTF-8 key order, projection `q` | same | unchanged. `data_key` also names the `iv` that salts every `p` and `x` in the row |
| `GroupLeakage::{pairs, elements}` | `{s, vs}` pairs in walk order, nested by array element | same | unchanged |
| `QueryLeakage::Extract` | the selector of the path asked | same | unchanged |
| `QueryLeakage::Subtree` | `token: TokenName{head, positions}` (one head token, chained through leading array positions), `gates` (`Selector(s)` or `Slot(n, s)`, positions in the clear), `reach` (every descendant of the token's node, in every row), `named` | `reads: Vec<ReadLeak>` and `budget` | rewritten. See the next three rows |
| `ReadLeak::token` | (one per read, see above) | `TokenName{head, steps}`, each step `Member(s)` or `Element(s, i)`: one per concrete path, in the order the client sends them | the list is what the database receives; its length gives the bound away, its order places each token |
| `ReadLeak::probe` | not measured (the old format had no such thing) | whether the token is a probe | new; the database is not told, and can tell (see findings) |
| `ReadLeak::hits` / `ReadLeak::reach` | `reach`: descendants of the head's node; `named`: what the gates reached | `hits`: the entry the token names in each row, if any; `reach`: every descendant of it that chains from it, in each row | a token now names exactly its node; nothing above it. Under the sealed root the root's token reaches nothing below the root |
| `QueryLeakage::Subtree::budget` | not measured (the old read had a budget too; the old profile did not model it) | the `budget` argument | new; the fallback to the root entry is computed from it and the walk, so the database learns nothing new from it |
| `QueryLeakage::{Contains, Equals, Order}` | needle projection with `alt`; equality needle; selector and the bound's ordering term | same | unchanged |
| `Leakage::{key_tag_len, ordering_ranks}` | the key tag's length, the order of every ordering class | same | unchanged |

## The distinguishers, before and after

27 before, 35 after: 26 kept unchanged in meaning, 1 renamed, 1 removed (by the rename), 8 added. The walk-based ones were rewritten for the new chain, but what each measures is the same.

| distinguisher | status | what it measures |
|---|---|---|
| `wire_fields` | kept | the wire keys of every row and entry (now `{c, op?, p?, s, x}`) |
| `entry_counts` | kept | entries per row |
| `parent_tag_presence` | kept | which entries carry `p` |
| `ordering_term_presence` | kept | which entries carry `op` |
| `ciphertext_lengths` | kept | every ciphertext's length, by position |
| `ciphertext_length_multisets` | kept | the same, order removed |
| `ciphertext_framing` | kept | the ciphertexts' version bytes, and how many pairs are equal (a deterministic cipher) |
| `selector_pattern_within_rows` | kept | which entries of a row share a selector |
| `selector_pattern_across_rows` | kept | which entries of the column share a selector |
| `parent_tag_equalities` | kept | pairs of entries sharing a `p` (expected none) |
| `headers` | kept | header fields, and equality of keyset, `iv` and key tag across rows |
| `projections` | kept | each row's `q`: grouping, pair order, selector and value-selector equality |
| `value_selector_partitions` | kept | per path, the rows grouped by value |
| `chain_head_runs` | kept | the runs after each entry with no `p`: each top-level field's subtree size |
| `selector_precedence` | kept | which of two selectors comes first across rows: sibling key order |
| `depth_recovery` | kept | an attack that reconstructs every row's depth sequence from the stored order alone |
| `token_reach` | kept | per read, row and token: the node it finds and everything its walk links, with parents and depths |
| `ordinal_patterns` | replaced by `member_order_shared_across_rows` | whether one token's objects give their members one order of ordinals across rows, reported only below a `2⁻⁴⁰` chance bound: members' ordinals are now a random permutation per row |
| `member_ordinals_follow_key_order` | kept | whether members' ordinals follow key order, reported only below a `2⁻⁴⁰` chance bound |
| `token_derivability` | kept | which reads' tokens the database can derive from which others' (now by the member rule and by the element rule at an index below 4, from the tokens that find a node in some row) |
| `transcripts` | kept | every query term with its tags named: determinism, shared selectors, needles; a read is now its token list and budget instead of a token and gates |
| `extraction_matches` | kept | which entries each `->` selector matches |
| `containment_matches` | kept | which rows each needle matches |
| `ordering_term_order` | kept | every ordering term's rank, stored and sent |
| `ordering_term_lengths` | kept | every ordering term's length |
| `ordering_matches` | kept | which entries each ordering bound holds for |
| `gated_walk_results` → `subtree_results` | renamed | what a read returns from each row: before, the walk through the gates; after, every token's node and subtree, or the root entry alone past the budget under the sealed root |
| `stored_lengths` | added | each row's and each entry's length in characters: sees `x`'s fixed 19 characters |
| `self_tag_equalities` | added | pairs of entries whose `x` equals another `x` or a `p` anywhere (expected none) |
| `token_counts` | added | how many tokens each read sends |
| `bound_recovery` | added | the `(levels, N)` an observer recovers from the count: 65 is one level at 64 and nothing else; 4,161 is two levels at 64 or one at 4,160 |
| `token_hits` | added | per read and row, which tokens (by place in the list) find a node, and where |
| `wildcard_positions` | added | for a one-level wildcard read: per row, which positions below `N` hold the rest of the path, whether the probe found an element, and whether the probe's find carries a selector the others do not |
| `hit_rules` | added | for every node a walk reaches, which rule its `x` matched: member, element, or neither |
| `ancestor_links` | added | whether the database can link each node a read names to its parent with any token it holds: the "no ancestor capability" check |

## The mutants, before and after

34 before, 44 after: 28 kept unchanged, 4 redefined for token lists, 2 removed, 12 added.

| mutant | status | clause it drops |
|---|---|---|
| `selectors_all_distinct`, `selectors_per_row_only`, `positions_in_selectors` | kept | selector equality; column-wide; array positions folded |
| `entry_count_padded` | kept | the number of entries |
| `order_random_permutation`, `members_unsorted` | kept | the stored order; members in key order |
| `parent_tag_on_every_entry`, `parent_tag_on_no_entry` | kept | which entries lack `p` |
| `ciphertext_length_bucketed`, `sealed_root_length_hidden` | kept | ciphertext length |
| `value_selectors_all_distinct`, `value_selectors_path_only` | kept | value-selector equality |
| `projection_flat`, `projection_shuffled` | kept | element grouping and pair order in `q` |
| `ordering_terms_absent`, `ordering_terms_unordered`, `ordering_terms_all_distinct`, `ordering_term_length_constant`, `ordering_terms_per_path` | kept | `op` presence, order, equality, length, equality across paths |
| `member_ranks_follow_key_order` | kept | a member's ordinal is a keyed rank |
| `sealed_flag_flipped`, `data_key_shared`, `keyset_per_row` | kept | the header |
| `extraction_selector_fresh`, `queries_nondeterministic` | kept | `->` sends the stored selector; queries are deterministic |
| `needle_flat`, `needle_alt_dropped`, `bound_rank_random` | kept | needle grouping, `alt`, the ordering bound's rank |
| `tokens_per_row` | redefined | before: head tokens per row; after: a token finds its node in one row only |
| `parent_tags_unchained` → `tokens_find_nothing` | redefined | a token finds and links nothing |
| `token_reaches_named_nodes_only` → `token_reaches_its_node_only` | redefined | before: the head token reaches only the path asked (the narrower reach #1360 wanted); after: a token finds its node and links nothing below it |
| `position_tokens_unchained` → `tokens_not_chained` | redefined | a token with a step below its head is unrelated to its head's |
| `slot_positions_hidden`, `gates_dropped` | removed | gates no longer exist |
| `self_tags_absent`, `self_tags_linkable_across_rows`, `self_tags_per_selector` | added | `x` on every entry; salted by the row; distinct per entry |
| `hit_rule_uniform` | added | the member-or-element rule (the page fix) |
| `probe_reaches_nothing` | added | a probe that finds an element links its subtree (the page's exception) |
| `ancestor_token_sent` | added | no ancestor's token: the pre-#1363 read, which also sent the top-level field's token |
| `member_tokens_carry_ordinal` | added | a member's token has no ordinal: the pre-#1363 member rule, under which reads through a key step find nothing |
| `element_tokens_without_index` | added | an element's token carries its index |
| `probes_dropped`, `token_list_shuffled`, `token_list_padded` | added | a probe per expanded array; the list's order; the list's length |
| `budget_not_sent` | added | the budget, in the clear |

## Calibration, before and after

| | before (the profile at `9a7ca372c`, on the old format) | first run on the new format (step 1) | after the port (`839c0f6fd`, `fa26cb540`) |
|---|---|---|---|
| tests | 7, all passing, about 3 s (the PR measured 6.3 s for the binary) | did not compile; with throwaway patches 1 of 7 passing | 9, all passing, 11.3 s for the binary: the calibration 9.6 s, every other test under 0.5 s |
| positive control, handcrafted columns | 4 columns, no distinguisher separates | fails: 5 distinguishers separate | 4 columns, no distinguisher separates |
| positive control, random columns | 48 cases pass | fails on the first case (`wire_fields`, `transcripts`) | 48 cases pass |
| mutants caught | 34 of 34 | 34 of 34, meaningless (the control failed) | 44 of 44 |
| page-as-written test | exactly `ordering_term_lengths` separates | 6 separate | renamed `the_hit_rule_separates_it_from_the_real_scheme`: exactly `hit_rules`, `subtree_results`, `token_derivability`, `token_reach` |
| `member_ordinals_follow_key_order` | decided on the wide-objects column, `2⁻⁴⁰` bound | not reached | decided on the wide-objects column (`Some(false)`: members' ordinals do not follow key order), same bound |

The ported handcrafted columns exercise every new mechanism: one-level reads at the default bound (65 tokens) and at bounds the rows overflow, a two-level read (7 tokens at a bound of 2), probes that find elements in every column (3, 3, 1 and 1 probe hits), a probe whose element no other read names (so `probe_reaches_nothing` is load-bearing), `$` under both root options, a read below a key step (`$.nested.deep`, which before #1363 needed a gate), and a read past its budget under the sealed root (3 rows answered with the root alone). The random columns draw bounds from {1, 2, 3, 64} and budgets from {0, 2, 64}.

Two tests are new. `given_strings_ordered_by_their_bytes` holds the page's folding sentence: read as raw bytes, the profile is told apart by `ordering_term_lengths` and `ordering_term_order`. `a_read_gives_away_its_bound_and_its_probes` runs `$.items[*].price` and `$.items[*].tags[*]` on the real scheme over rows with 0, 3 and 70 items: the counts are 65 and 4,161, the bound is recovered, and in the 70-item row the database sees positions 0 and 2 … 63 holding a price, the probe finding an element, and the probe's find carrying a different selector from the others.

## What the port found

**One finding against the page as #1363 published it, fixed on this branch.** Nothing stored says whether a node is an object member or an array element (the design's decision 2, "no kind bit"). But to derive the token of each node it reaches, the database tests the node's self tag against the member rule and then the element rule, and the one that matches says which. So below any token it is sent, the database learns whether each node is a member or an element, and therefore whether each parent is an object or an array; for an element it also learns the index, which is the ordinal it was found at. Where selectors already show it (an array that has two elements in some row) this adds nothing; for a node that is an only child in every row, it does. The page said a token's holder can "see how the nodes beneath it nest, link each one to its parent, and derive the tokens of the nodes beneath". This branch adds: "It also learns whether each node beneath is an object member or an array element, and each element's index". `the_hit_rule_separates_it_from_the_real_scheme` shows the sentence is needed: without it, `hit_rules` separates the worlds, and so do the three features that break when a world tries to hide the rule while still matching the tokens a client sends (a read through a key step always sends a member-rule token).

**One inaccuracy in a SQL comment, reported, and corrected by #1363.** `json_tree_subtree`'s comment in `packages/eql/src/v3/json_tree/functions.sql` said "the server cannot tell a probe from any other token". It cannot from a token's bytes. But the probe is always the last token at its level, the count gives the bound away, and a probe that finds something finds the element, whose selector differs from that of the leaf the path's other tokens find. The leakage page does not repeat the claim. #1363 corrected the comment in `b2a20abb9`: it now says the server "can pick it out".

**One error in the old profile, which its corpus could not show.** It ordered strings by their raw bytes. The code folds case and accents before ordering, so `"Carol"` and `"carol"` share a term, and the term's length counts the folded form. The old corpus held only lower-case ASCII, where the two agree. The port models folding, the corpus now holds names that fold, and a test holds the page's sentence.

**The old page's three findings are closed.** The ordering term's length, equal values at two ordered paths sharing a term, and UTF-8 byte order of keys are all on the page now. Each keeps a mutant or a reading that the calibration catches.

**The tension stands.** #1358's read check, kept by #1363 (decision 8), refuses a subtree's rows unless they sit at consecutive positions `j`. That consecutiveness is what #1357 wants gone from the stored order. Both cannot hold as written; it is the owner's decision.

## What the database learns now that it did not before

- **The self tag, at rest: nothing.** Every entry carries 8 more bytes (12 base64 characters; 19 more characters per entry in compact JSON, 21 in `jsonb` text; about a tenth of a document's size). The tag is salted by the row's random `iv`, so no two are equal in a column (`self_tag_equalities` is empty in both worlds), and since every entry has one, its presence marks none.
- **The self tag, under a token: the named node itself.** Before, a head token let the database find the head's children, not the head; it never identified the node a token belonged to (the old walk recorded its children's parent as unknown). Now a token finds its node directly, by `x`, in every row that has it.
- **The token count, and with it the bound.** A read with no wildcard sends 1 token. One wildcard level sends `N + 1` (65 at the default), two send `N² + N + 1` (4,161), and 8,192 is the cap. 65 identifies `N = 64` uniquely; 4,161 is either two levels at 64 or one at 4,160, and which tokens find nodes settles it.
- **The probes.** Per row, whether each expanded array is longer than `N`, and, where a probe finds an element, that element's whole subtree, including the siblings of the path asked for, although the read then fails. The probe is identifiable by its place in the list and by what it finds.
- **Which elements hold the rest of the path.** For `$.items[*].price`, per row, which positions below `N` have a `price`. Before, the gated walk returned the same rows, so the result was visible; now each position also has its own token, column-wide.
- **Member or element, for every reached node** (the finding above).
- **The budget**, in the clear. The fallback to the root entry is computed by the database from the walk it already sees, so it learns nothing more from it; someone who sees only the results learns, from a row answered with its root alone, that the read found more than `budget` rows there.

## What the database no longer learns

- **An ancestor's capability in every row.** Before, any read below a top-level field sent that field's token, a capability over the whole field's structure in every row for the life of the column, and under an open root every read sent the root's token, the whole column's shape. Now no token over any node above the one read leaves the client unless that node is itself read. `ancestor_links` is the check: in the ported worlds a named node's parent is linked only where another read named one of its ancestors, and the mutant that sends the pre-#1363 head token is caught by it, by `token_reach` and by the token counts.
- **The gates.** Before, a read sent the selector of every step below the head, and every array position in plaintext (`#n:<selector>`), whether or not a row had the path. Now no selector is sent with a read: the database learns the selector of the node read only from the entries the token finds. Array positions travel only inside tokens; the database still infers a found node's position from the stored order (#1357), and, for a wildcard, from the token's place in the list.
- **The head token.** Reading `$.profile.address.city` sends the city leaf's token and nothing that covers `$.profile`. Under the sealed root the root's token, sent only for a read of `$`, finds the root entry and nothing beneath it, since the top-level fields carry no parent tag.

Everything at rest other than `x` is unchanged: shape through the stored order, parent structure, sibling key order, selector equality across rows, value-selector equality, ciphertext lengths, ordering terms with their lengths, their equality across ordered paths and their shared prefixes, and the header.

## After review

A review of the port (2026-10-25) found one disclosure that both profiles missed, and a set of gaps in the method. None of them changes the comparison above, since the missed disclosure is the same before and after #1363.

- **The ordering terms' shared prefixes.** A CLLW OPE term is a carry byte, then one byte per plaintext bit (the PRF of the bits before it, plus the bit at weight 128, plus a carry). So two terms agree to within one up to the first bit their values' encodings differ in, and differ by about 128 there. The database reads that bit off the stored terms exactly. For numbers it is their signs and binary exponents. The page stated the disclosure in bytes, and the profile had listed it as out of reach ("not an exact function of the plaintexts", which is true of the byte prefix and not of the bit). Its simulator drew terms with no prefix structure, so nothing could see the omission. It is now a clause (`Leakage::ordering_prefixes`), with a distinguisher (`ordering_term_prefixes`) and a mutant (`ordering_prefixes_hidden`), and the simulator builds CLLW-shaped terms. The page's sentence now says bits, and what they mean for a number and a string.
- **New checks on the method.** `cross_kind_equalities` compares values across kinds (a token equal to a selector, say), which every other feature names apart. `term_fields` checks the field names inside `q` and every query term, which the parser would otherwise drop unread. `token_derivability` tries the element rule up to index 64 or the longest token list, not only below 4.
- **Four clauses with no mutant** now have one: `key_tag_shortened`, `order_selector_fresh`, `element_ordinals_reversed`, `parents_lifted`.
- **The corpus.** The random columns hold big integers, floats, strings that fold, and non-scalars at ordered paths. They order numbers or strings, and run 256 cases instead of 48. A fifth handcrafted column orders numbers of both signs and many magnitudes, and holds two integers past 2⁵³ that share a term.
- **Decided by the owner, and now on the page and in the profile.** At a path ordered over numbers and strings both, the order between a number and a string depends on the column key and is not jsonb's; within each kind the order is the values'. The two kinds' terms are under different keys (the order space's salt names its domain), so they show which leaves are numbers and which are strings, and the strings sort as one block that the key places below the numbers, between the negative and non-negative ones, or above them. The profile states the kinds and the within-kind order and leaves the placement to the key; the calibration simulates each placement, and the mutant fixing jsonb's numbers-first order (`mixed_kinds_jsonb_order`) is caught. A number's equality under its term is as a 64-bit float, held by the reading `NumberOrder::Exact`. The shared prefix is CLLW's known profile, and a scheme that hides it is planned for a later version.

After the review and the owner's decisions: 38 distinguishers, 50 mutants, 12 tests.
