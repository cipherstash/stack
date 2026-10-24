//! An executable leakage profile for the JSON index, EQL v4's `json_tree`.
//!
//! `packages/eql/docs/reference/json-tree-leakage.md` says, in prose, what a
//! database holding a `json_tree` column learns from the stored rows and
//! from each query. This module turns that page into a checked claim. If the
//! real scheme reveals anything the claim leaves out, a test here fails and
//! names the observation that gave it away.
//!
//! # The pieces
//!
//! ```text
//!  documents, queries ──► profile::leak ──► Leakage ──► simulator::simulate ──► wire JSON ─┐
//!   (plaintext)              (L: no key)                 (+ seeded randomness)            │
//!                                                                                         ├─► observe ──► ObservedWorld ──► distinguishers
//!  documents, queries ──► real::world ─────────────────────────────────────────► wire JSON ─┘
//!                          (the crate, under the fake key source)
//! ```
//!
//! - [`profile`] is `L`, the claim: [`profile::l_store`] (what the stored
//!   rows reveal) and [`profile::l_query`] (what one query reveals), both
//!   functions of the plaintext alone. Every keyed value is an opaque integer
//!   that is equal exactly where the real values are equal. Each field of the
//!   leakage types is one clause, and its doc comment quotes the sentence of
//!   the page it encodes. The two take a shared [`profile::Ids`] beside the
//!   documents, so that a query's selector and a stored selector get the same
//!   name when the real bytes are equal.
//! - [`simulator`] builds a world in the wire form from a
//!   [`profile::Leakage`] and randomness, with no plaintext and no key:
//!   random bytes for every name, random ciphertexts of the stated length,
//!   ordering terms laid out in the stated order, and parent tags chained with
//!   the real hash below every token a query sends, as far as the profile
//!   says the token reaches.
//! - [`real`] seals the same documents and derives the same query terms
//!   through the crate's public API, and serializes them.
//! - [`observe`] parses either world's wire JSON into one
//!   [`observe::ObservedWorld`].
//! - [`distinguishers`] are pure functions of an observed world: what an
//!   observer holding the column and the query terms could compute. Each
//!   feature is exact (byte strings renamed to integers in order of first
//!   appearance), so a real and a simulated world are compared for equality,
//!   with no statistics. One feature needs a probability bound and carries it
//!   in its doc comment ([`distinguishers::member_ordinals_follow_key_order`]).
//! - [`mutants`] are profiles with one clause dropped or coarsened.
//! - [`corpus`] holds the handcrafted columns and a proptest generator of
//!   random ones over a shared key vocabulary.
//! - [`chain`] is the token chain's two public hash functions, the only part
//!   of the real scheme the harness evaluates itself.
//!
//! # The checks ([`calibration`])
//!
//! - **The positive control.** The simulator, run from the full profile, is
//!   told from the real scheme by no distinguisher, on the handcrafted
//!   columns and on 48 random ones. If this fails, the real scheme reveals
//!   something `L` does not state: that is a finding against the page (or
//!   against the code), and the failure names the distinguisher and prints
//!   both features.
//! - **The page as written.** `L` carries one clause the page does not state,
//!   marked **beyond the page** in [`profile::Clauses`].
//!   [`profile::Clauses::page_only`] turns it off, and a test holds that the
//!   result is then told from the real scheme, by exactly the distinguisher
//!   that sees it.
//! - **The calibration.** Each mutant profile drops one clause. The test
//!   expects some distinguisher to tell each mutant's world from the real
//!   one, and prints a table of which (run with `--no-capture`). A mutant
//!   nothing notices goes in its `UNNOTICED` list with the reason; there is
//!   none today. This is what shows the distinguishers can see what the
//!   clauses describe, so that the positive control passing means something.
//! - **The harness itself.** The chain functions agree with the crate's own
//!   walk (`JsonDocument::subtree`), and the order-only attack in
//!   [`distinguishers::depth_recovery`] recovers every row's depth sequence
//!   on a column whose rows vary, which is the page's claim that the stored
//!   order reveals each row's shape.
//!
//! # What the profile found against the page
//!
//! 1. **The ordering term's length is not on the page.** A CLLW OPE term is
//!    `8 × n + 1` bytes for an `n`-byte encoding: every number's term is 65
//!    bytes, and a string's is `8 × (len + 1) + 1`. So at an ordered path
//!    the term says which of number or string the leaf is (the page says
//!    only that its presence says "a number or a string"), and repeats the
//!    string's length. `the_ordering_term_length_separates_it_from_the_real_scheme`.
//! 2. **The page contradicts itself on equal values at two paths.** "Not
//!    revealed at rest: […] whether two different paths hold the same value"
//!    is false once two paths are ordered: the `op` row's "leaves at two
//!    ordered paths compare with each other too" includes equality, and the
//!    real terms of equal values at two ordered paths are equal. `L` follows
//!    the `op` row; the mutant that follows the summary sentence
//!    (`ordering_terms_per_path`) is told apart by `ordering_term_order`.
//! 3. **"The sorted order of their key names" is the keys' UTF-8 byte
//!    order.** `jsonb` sorts shorter keys first; read that way, the profile
//!    is told apart (`given_the_jsonb_reading_of_the_key_order`). A reader
//!    inferring key names from the order needs the byte order.
//!
//! Where the page is vague and `L` is as precise as the code forces, the
//! clause says so: what a token's holder sees in the ordinals it probes
//! ([`profile::EntryLeakage::step`]), the needle's `alt`
//! ([`profile::QueryLeakage::Contains`]), and the fixed parts of a
//! ciphertext's length ([`profile::ciphertext_len`]).
//!
//! The two issues the profile was built to check come out as the page
//! states them. The stored order reveals each row's shape (#1357): the order
//! clause is load-bearing (`order_random_permutation`, `members_unsorted`),
//! and the depth attack works. And a subtree read's token reaches its whole
//! top-level field in every row, not only the path asked (#1360): the
//! mutant that narrows the reach to the path (`token_reaches_named_nodes_only`)
//! is told apart by `token_reach`, which walks the real parent tags from the
//! real token.
//!
//! # When the format changes
//!
//! The format is about to change (`docs/plans/2026-10-17-json-tree-index.md`,
//! "Design change (2026-10-24)"): member tokens lose their ordinal, every
//! entry gains a self tag `x`, the client expands wildcards and gates go
//! away. `L` and the real-side adapter are expected to change with it, and
//! with the leakage page; the distinguishers should mostly not. To add or
//! change a clause:
//!
//! 1. Change the page first, or at least decide what it will say.
//! 2. Change [`profile`]: a field on the leakage type, with the page's
//!    sentence quoted in its doc comment, computed from the plaintext.
//! 3. Make the [`simulator`] produce it from that field and randomness only.
//!    For `x`, that is `H8("x" ‖ iv ‖ t(node))` on every entry whose token
//!    some query's reach covers, and random bytes elsewhere, exactly as `p`
//!    is handled now.
//! 4. Teach [`observe`] the new wire field, and [`real`] any new API.
//! 5. Add a distinguisher if no existing one would see the clause, and a
//!    mutant that drops the clause, and check the calibration catches it.
//!
//! # Reading a failure
//!
//! - **Positive control fails.** The real scheme shows something the profile
//!   does not state, or states differently. The message names each
//!   distinguisher that separated the worlds, with the real and the
//!   simulated feature. Decide whether the page or the code is wrong. Never
//!   widen `L` silently to make it pass: a clause the page does not state
//!   goes in as **beyond the page** ([`profile::Clauses`]), with a test like
//!   the one for the ordering term's length, so the gap stays visible until
//!   the page closes it.
//! - **Calibration fails for a mutant nothing noticed.** Either the clause
//!   is not load-bearing on the calibration columns (add a column that
//!   exercises it, as the wide-objects column does for member ranks), or no
//!   distinguisher can see it (write one). If neither is possible, list the
//!   mutant in `UNNOTICED` with the reason. Do not delete the clause.
//! - **Calibration fails for a listed mutant that is now noticed.** Remove it
//!   from the list: something got sharper.
//!
//! # A tension this module states and does not resolve
//!
//! PR #1358's read check (`JsonSubtreeKey::open`) refuses a walk's rows
//! unless each subtree's rows sit at consecutive positions `j` in `sv`, which
//! is what a subtree is in a depth-first stored order, and `j` is bound into
//! every ciphertext's AAD. That consecutiveness is exactly the property
//! #1357 wants gone: a stored order independent of the shape (a keyed
//! permutation of `sv`, say) would scatter a subtree's rows. The check and
//! "order independent of shape" cannot both hold as written: one of them
//! has to give, and which is the owner's decision. The design change's
//! first open question discusses the same check from the other side.
//!
//! # Out of reach
//!
//! - **The inside of an ordering term.** CLLW OPE terms share leading bytes
//!   when the encoded values do (the page says so), with a carry that can
//!   move a byte by one. The simulator reproduces a term's presence, length,
//!   equality and order, not its prefix structure, and no distinguisher
//!   looks at it: the prefix a pair of terms shares is not an exact function
//!   of the plaintexts, so it is a statistical question.
//! - **The keyed member rank as a permutation.** Under a token, a member's
//!   ordinal is a keyed rank. Its relation to the stored (key) order is a
//!   random permutation, decidable exactly only where enough wide objects sit
//!   under the tokens sent; elsewhere the feature reports nothing. For the
//!   same reason, which descendants of a token share a derived token across
//!   rows depends on the ranks, so no feature compares it.
//! - **The primitives.** Ciphertexts beyond their length, selectors, value
//!   selectors and head tokens beyond their equality patterns: the profile
//!   assumes AES-GCM and the PRFs do their job, and the simulator draws
//!   random bytes for them.
//! - **The database's side channels.** Timing, which rows a query touches
//!   beyond its result, the walk's budget fallback, and the `i` and `v`
//!   envelope fields the SQL adds. One column at a time; no cross-column
//!   linkage is modelled.
//! - **The key service.** The fake key source mints 32-byte tags; ZeroKMS's
//!   tag length is its own, and a column constant either way.
//!
//! # Determinism
//!
//! Every simulation and every mutant draws from one seeded generator, and
//! the random columns come from a seeded proptest runner. The real side
//! draws data keys and nonces from the operating system; those reach a
//! feature only through equality patterns, which change only on a collision
//! of random bytes, below `n² / 2^64` for `n` eight-byte tags in a column
//! (about `10^-13` here). The fake key source's index key is fixed, so the
//! real member ranks are too.
//!
//! The profile sorts members itself rather than trusting `serde_json`'s
//! iteration order, so a build that unified serde_json's `preserve_order`
//! feature on (which would store the application's field order, #1357) fails
//! the positive control on the handcrafted rows whose keys are written out
//! of order.

pub mod calibration;
pub mod chain;
pub mod corpus;
pub mod distinguishers;
pub mod mutants;
pub mod observe;
pub mod profile;
pub mod real;
pub mod simulator;
