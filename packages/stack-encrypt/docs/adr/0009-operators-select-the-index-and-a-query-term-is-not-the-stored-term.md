---
status: proposed
date: 2026-10-13
supersedes: ADR-0004 (decision 5)
extends: ADR-0003, ADR-0007
---

# Operators select the index, and a query term is not the stored term

[ADR-0004](0004-one-context-per-target-threaded-through-the-declaration-tree.md)
decision 5 kept the standalone term methods as the query path on the grounds
that "a probe and a stored term are the same bytes, and the term methods
cannot tell which they are producing". That premise is wrong, and the API
built on it has the caller name an *index* when what they mean is an
*operator*.

This ADR records the query-side model for the Rust Stack Encrypt library:
what a caller asks for, how the library chooses the index that answers it,
what it hands back, and how far that answer can be trusted. It is a design
record. No code changes with it.

Scope is the Rust library. The decisions bind the Rust API; the bindings and
the language SDKs are governed by ADR-0007, which will need an amendment once
this ADR is accepted, because the data grammar a binding lowers has no
operator in it today. [Appendix B](#appendix-b-the-model-in-go-and-typescript)
sketches what that amendment would carry, so the model can be checked against
two more languages before it is built.

Two words, so they are not re-litigated. The value a caller sends to the
server to be compared against stored values is a **query term**, or a query.
ADR-0004 called it a probe; "probe" is not used below except when quoting
that ADR. The value a write puts in the column is the **stored term**.

## The problem

### A query term and a stored term are not the same bytes

Decision 5 of ADR-0004 assumed they were. In general they are not:

| index | stored term | query term |
| --- | --- | --- |
| HMAC | the HMAC | the same HMAC |
| ORE | left and right ciphertext | the left ciphertext only |
| OPE | the OPE value of the order key | the same value; equal terms mean equal order keys, which is plaintext equality only when the key is lossless (it is for integers, and not for text after the column's declared transform) |
| Bloom match | one filter over every n-gram of the value | a filter over the n-grams of the needle: a subset, or bits the stored filter lacks |
| Bloom prefix (planned) | an HMAC per edge n-gram | one HMAC |
| JSON path | a selector and, per leaf, that leaf's term | a selector, or a selector plus a leaf query term |
| similarity (research preview) | `[u64; BANDS]` tokens per row | a query set of `BANDS × PROBES` tokens |

HMAC equality is the one index whose query term is byte-for-byte the stored
term, and whose comparison means plaintext equality. OPE comes close only when
its order key is lossless, as it is for integers. The others differ in kind.
The order key is `orderable-bytes`' order-preserving encoding of the value,
applied after whatever transform the column declares for the kind (the
system
[ADR-0002](../../../../docs/adr/0002-one-value-model-three-encodings-and-eql-v4-by-producer.md),
not this directory's, defines a text fold; the encoding is pluggable, and
what the term means follows it). The Rust library does not use cllw-ore's
`orderize_string`, which an earlier draft of this ADR named.

The term is a function of the index *and the operator*, not of the index
alone. An ORE index answers `=`, `<` and a range with different query shapes;
a Bloom index answers `Matches` and (if used for ranked search) `Nearest` with
the same stored filter and different queries.

### The caller names an index, not what they want

Today the query chain is
`cipher.query(value).using(&plan).index(Match(..))`: the caller picks the
index, and the operator is implied. That has three costs.

- A domain type with two indexes that both answer an operator leaves the choice
  to the caller, who has to know that HMAC is the better equality than ORE.
  The original CipherStash client made the choice for them, by operator — and
  took the *first* index after an alphabetical sort, so `Eq` went to ORE when
  both were present.
- An operator an index cannot answer is not a compile error. Nothing in the
  types says which operators `Match(..)` supports.
- There is no place to put operator-specific input. `Between` takes two
  values; `Nearest` takes an embedding and a fetch size; a JSON path operator
  takes a path.

### The server's answer is sometimes approximate, and the library says nothing

A Bloom filter is probabilistic. A row whose filter happens to contain every
bit of the query passes `@@` without containing the needle. A similarity index
returns candidates by construction.

The library has never said which terms are exact. A caller who wants ten real
matches has no way to know how many rows to fetch, and no help deciding, after
decrypting, which rows to keep. "We have never implemented client-side
filtering for Bloom filters" is a gap the API should at least leave room for.

### What the library is

Stack Encrypt is not a query interface. It produces query terms that a caller
binds into SQL through sqlx, Diesel or (through the bindings) Drizzle and
Prisma, and it decrypts what comes back. It never runs a query. Every decision
below respects that line: the library can tell you how many rows to ask for
and whether a decrypted row is a real match, but the SQL, the `LIMIT` and the
loop are yours.

## Decision

### 1. The caller names an operator; the operator is a type

```rust
use stack_encrypt::op;

let term = cipher.query(op::Eq, "bob@example.com").on(&users::email).await?;
let term = cipher.query(op::Lt, 40).on(&users::age).await?;
let term = cipher.query(op::Between, (18, 65)).on(&users::age).await?;
let term = cipher.query(op::Matches, "ali").on(&users::name).await?;
let term = cipher.query(op::AtPath(op::Eq), ("$.address.city", "Sydney")).on(&users::profile).await?;
```

Operators are unit types, as in the original client, not a runtime enum, and
a query passes one by value, as a plan passes an index (`.via(Ore)`). They are
used by path (`op::Eq`), because an imported `Eq` would shadow the prelude's
`Eq` trait. An operator carries its own input type: `Eq` takes one value,
`Between` a pair, `Nearest` an embedding, `AtPath<Op>` a path and `Op`'s
input. The query is awaited because deriving the term can retrieve a key.

Operators come in three kinds. A **predicate** (`Eq`, `Lt`, `Lte`, `Gt`,
`Gte`, `Between`, `Matches`, `StartsWith`, JSON `Contains`, `ContainedBy`)
filters rows. An **accessor** (`AtPath<Op>`) applies another operator at a
JSON path. A **ranking** (`Nearest`) orders rows and takes a fetch size
rather than filtering.

Two naming points, so they are not re-litigated. `Contains` and `ContainedBy`
are JSON containment (`@>` / `<@`); text search is `Matches`, because a Bloom
match is not a containment. The accessor is `AtPath`, not `At`, because `At`
alone does not say what it is at.

Case is a parameter of the text operators, defaulting to the common case:
`Matches<C = CaseInsensitive>`, `StartsWith<C = CaseInsensitive>`, with
`op::Matches.case_sensitive()` for the other. A Bloom index implements the
variant its configuration fixes (`downcase` on or off), so a case-sensitive
query against a case-folding index is a type error, not an empty result.

### 2. An index declares the operators it supports, and the query term for each

```rust
pub trait Operator: Copy + 'static { type Arity: Arity; }   // `One` plaintext, or a `Pair`

pub trait Supports<Op: Operator, In: Input<Op::Arity>>: Index<In::Plaintext> {
    type Query: TermFor<Op>;                            // what this index sends for `Op`
    type Verifier;                                      // what the query keeps to check a row
    fn check(&self, input: &In) -> Result<(), Error>;   // a refusal, before any term exists
    fn verifier(&self, input: &In) -> Self::Verifier;
    fn query(verifier: Self::Verifier, terms: In::Terms<Self::Term>, token: QueryToken) -> Self::Query;
}
```

`In::Plaintext` is the plaintext type the index is over, and its
`Index::Term` is the stored term it derives. `Query` is the query term, and
`query` makes it from the verifier and the terms the index derived for the
query's input. `QueryToken` can be made only inside the crate, so only a
query chain calls `query`, and no caller can turn a stored term into a query
term by hand.

`QueryTerm` and the two traits that refine it are defined in decision 4.
`Query` is not `Term`. An ORE index's `Supports<Lt, S>::Query` is the left
ciphertext; its `Term` is left and right. (This crate's ORE is CLLW today,
whose ciphertext has no left half to send alone, so until block ORE lands,
#1140, the query term is the ciphertext itself, as an HMAC's is; `Supports`
is where the left-only term goes when it arrives.) A Bloom index's
`Supports<Matches, S>::Query` is a filter over the query's value
(`MatchQuery`); its `Term` is a filter over the value (`MatchTerms`). There is
no other path from a derived term to the server:
`cipher.query_index(index, v).on(&plan)`, which returned an index's own term,
went with the ordering operators (#1186).

An operator says what a query takes through its arity. `Eq`, the orderings
and `Matches` take the plaintext the index is declared over
(`Supports<Lt, S>`); `Between` takes a pair of them
(`Supports<Between, (S, S)>`); `Input` relates the input to that plaintext,
so the plan is checked against `S` either way, and the chain derives one
term per plaintext under the one label. `check` is where a query is refused
before any term exists: a match index whose declared case disagrees with its
`downcase` option, a `Between` whose bounds are the wrong way round, a match
query with no tokens. `AtPath<Op>` takes a path and `Op`'s input, and gains
its shape with the JSON index.

The bound tightens per operator, through `TermFor<Op>`: any `QueryTerm`
answers `Eq`, but only a `Probabilistic` one answers `Matches`, and only a
`Ranked` one will answer `Nearest`. None of this crate's indexes can claim
an inexact operator without saying how its answer is checked. The rule binds
this crate's terms through blanket impls; a term in another crate can opt
into `TermFor` by hand, so there it is a guide rather than a proof.

`Verifier` is what the query term keeps of the query's plaintext so it can
check a decrypted row later, and `verifier` takes it before the plaintext is
consumed. An exact term checks nothing, so an equality index's verifier is
`()`. A match index's is the query's tokens (`QueryTokens`), which `verify`
needs and the filter cannot give back:

```rust
impl<S: AsRef<str>, O: MatchCase> Supports<Matches<O::Case>, S> for Match<O> {
    type Query = MatchQuery<O>;
    type Verifier = QueryTokens;     // "alice" -> ali, lic, ice
    fn verifier(&self, value: &S) -> QueryTokens { QueryTokens::of::<O>(value.as_ref()) }
    fn query(tokens: QueryTokens, term: MatchTerms<O>, _: QueryToken) -> MatchQuery<O> {
        MatchQuery::new(term, tokens)  // filter for the server, tokens for verify
    }
    // check elided
}
```

A row the server returns for `alice` passes `verify` only if its decrypted
text holds `ali`, `lic` and `ice`, so a Bloom false positive never reaches
the caller.

### 3. The domain type chooses the best index for an operator

```rust
pub trait Answers<Op: Operator, S> {
    type Via: Supports<Op, S> + Default;   // an index is a unit type, so its Default is the index
}

impl Answers<op::Eq, String>      for TextSearch { type Via = Equality; }
impl Answers<op::Lt, String>      for TextSearch { type Via = Ore; }
impl Answers<op::Matches, String> for TextSearch { type Via = Match<EqlMatch>; }
```

"Best" is defined per domain type, by hand, and means the most efficient or
the most secure index that answers the operator, as the index types in play
dictate. A domain with both HMAC and ORE answers `Eq` with HMAC: cheaper to
compare, and the ORE term reveals order. This is the decision the original
client made by accident (first after a sort) and this ADR makes on purpose.

A domain that does not answer an operator has no `Answers<Op, S>` impl, and
the query is a compile error.

A plan that declares its indexes rather than a domain type (a field of a
fields plan, or a one-value plan built `with` indexes) has no type to hold
`Answers`, so the operator names its own default, and a plan that declared
another index for it names that one with `.via(index)`:

```rust
pub trait DefaultIndex<S>: Operator {
    type Via: Supports<Self, S> + Default;
}
```

### 4. A query term is one of three things, and the trait it implements is its fidelity

```rust
pub trait QueryTerm {}

pub trait Probabilistic: QueryTerm {
    type Plaintext;
    fn verify(&self, value: &Self::Plaintext) -> bool;
    fn target_limit(&self, want: u64, stats: &Stats) -> Limit;
}

pub trait Ranked: QueryTerm {
    type Plaintext;
    fn score(&self, value: &Self::Plaintext) -> Score;
    fn target_limit(&self, want: u64) -> u64;
}
```

- A term that implements `QueryTerm` only is **exact**. The server's answer
  is the answer. HMAC `Eq`, ORE and OPE (`Lt`, `Between`) on numbers, JSON
  `AtPath<Eq>`, and ORE and OPE on text if the catalog keeps text ordering
  (see "Text ordering" below).
- A `Probabilistic` term can return **false positives and no false
  negatives**. `verify` is the operator's own meaning, run on a decrypted
  value: it decides whether a row the server returned is a real match. Bloom
  `Matches` and `StartsWith`. Bloom filters are the only index this applies
  to today, and the trait is not a home for an order term: an order term
  over text compares order keys, and two values with one key tie by the
  term's definition, not by error, so there is nothing a decrypted value
  could be checked against.
- A `Ranked` term returns **candidates in approximate order**. `score` is the
  exact score on a decrypted value, for re-ranking. `Nearest` over a
  similarity index, and `Nearest` over a Bloom index if used for ranked text
  search.

`target_limit` has one meaning on both traits: *fetch this many candidate
rows so that, at the stated confidence, `want` of them survive*. On a
`Probabilistic` term the survivors are the rows `verify` keeps, and the
number depends on the table, so it takes `Stats` and may answer
`Limit::Unbounded`. On a `Ranked` term the survivors are the top `want` after
`score` re-ranks, and the number is the index's configured recall factor
times `want`, so it takes nothing else.

`verify` is infallible. It runs on a value that is already decrypted and
already the type the index was declared over, so the only question it can
answer is "does this row match", and every other outcome is "no": a JSON
path absent from the document, text too short to hold the query's tokens.
A `bool` is what `Iterator::filter` takes; an error would have no recovery
except dropping the row, which is `false` by another name. The one input the
library refuses, a query value too short to tokenise, is refused when the query
is awaited, before a term exists. The stored side refuses nothing: a value
too short to tokenise is stored as the empty filter, which no query matches,
so a two-letter name is a valid value in a match column and `verify` is
never asked about it. The empty filter is visible to anyone who can read the
column: it tells them the value is empty, separator-only or shorter than the
n-gram length. A filter's fill already leaks its value's approximate length;
this is an exact class, and the price of storing such values at all.

`Plaintext` is the decrypted value the term is defined over, and that
is not always the value the user wrote. For `Matches` it is the text. For
`Nearest` over a similarity index it is the stored embedding, or the LSH
sketch when only the sketch is stored; `score` is exact with respect to what
was stored, not to a document the row never held. For `AtPath<Op>` it is the
JSON document, and `verify` applies `Op` at the path. A query has to select
whatever `Plaintext` is, which decision 5 and the consequences return to.

There is no `Fidelity` enum and no `verify` on exact terms. A caller cannot
write `term.verify(..)` for an HMAC term: verification would pass for every
row the server returned, so the method would say nothing, and the compiler
says so.

`AtPath<Op>` inherits the fidelity of `Op` on the leaf: `AtPath<Eq>` and
`AtPath<Lt>` are exact, as `Eq` and `Lt` are, and an accessor over a
probabilistic leaf operator, should one be added, is `Probabilistic`.

`QueryTerm` is a marker today, and the two refinements are added to it as
the indexes that need them land. A term serialises to the JSON its query
domain takes (decision 8), which is a property of each term type rather than
of the trait.

### 5. Verification is the caller's, after decrypt; the library supplies the predicate and the bound

The library never runs a query, so it cannot filter the result. What it gives
a caller of a `Probabilistic` term is two things.

`verify` is the predicate. For `Matches<CaseInsensitive>`, it folds case,
tokenises both sides with the index's own tokenizer and checks that the
needle's n-grams occur in the value. Whether that check is n-gram containment
or a substring test (they differ once the query is longer than one n-gram)
is the implementation's choice; both are sound against a Bloom match, and
the ADR fixes neither. It lives on the term because the term already carries
the operator's input and the index's configuration, so it cannot disagree
with what was stored.

`target_limit` is how many rows to ask for to expect `want` real matches.
For a Bloom filter it is computable from what the client knows, plus what
the server has to tell it:

- `m` bits and `k` hashes: the index configuration.
- `b`: the distinct bits set in the *query* filter. The client built it, so
  this is exact, not `k × n-grams`.
- `f_i`: the fill of the stored filter in row `i`, `1 − e^(−k·n_i/m)` for
  `n_i` stored tokens. It is per row, because values differ in length.
- `N`: the rows the predicate scans.

A non-matching row `i` passes when every one of the `b` query bits is set in
its filter, with probability about `f_i^b`. Over the table the pass rate is
the *mean of* `f_i^b`, which is not the mean fill raised to `b`: for `b > 1`
the mean of a power exceeds the power of the mean, and a column of mixed
lengths makes the gap large. Half a million rows of 20 tokens and half a
million of 200, with `b = 6`, pass at a mean rate of 3.8e-3 (3,800 false
positives); the mean fill, 0.25, raised to 6 predicts 245. The number the
bound needs is therefore `p = mean(f_i^b)`, and the statistics the client
holds must let it compute that for the `b` of each query.

The model assumes a non-matching row shares no token with the query. The
same token sets the same bits in every filter, so a row holding part of the
query has fewer bits left to chance: "police" already holds two of
"alice"'s three 3-grams, and passes at `f^6` rather than `f^18`. On natural
text the stated confidence is therefore nominal, and a measured histogram
cannot correct it, because it measures fill, not overlap. Correctness does
not depend on it: `verify` decides every row, and the candidate count says
whether a fetch was complete.

False positives are then `Poisson(λ = p·N)`, and the worst case that still
satisfies the caller is exactly `want` true matches preceded by every false
positive, so

```
target_limit(want, N) = want + Poisson_quantile(λ = p·N, confidence)
```

This is a probabilistic bound, and the ADR does not pretend otherwise. At 99%
confidence one query in a hundred draws more false positives than the
quantile, and if those rows sort before a real match under the query's
`ORDER BY`, the fetch holds fewer than `want` real rows while more exist. The
caller can tell the two apart from one number it already has: if the server
returned *fewer candidates than the limit*, the predicate is exhausted, and
fewer than `want` verified rows means there were fewer than `want` matches.
If it returned exactly the limit, the result is a page, not an answer, and
the cursor loop in decision 6 continues from it. `verify` makes every
returned row correct; only the candidate count makes the result complete.

#### Declared and measured statistics

Measured statistics come from the server; the declared prior comes from the
index declaration. The library takes either as numbers in `Stats` and does
not care which it was given. A column has the prior from the day it is
declared.

**Declared.** A match configuration declares `expected_tokens()`, the typical
token count of the values it will hold, beside the `m` and `k` of its
options: 20 for a name column, 200 for a notes column. It is not part of the
index's identity and changes no term. From it `Stats::declared(rows)` takes
`f = 1 − e^(−k·expected_tokens/m)` and `p = f^b`. This is a prior, and
`rows` is a planning estimate too. It is enough to warn before a query runs
(a three-letter needle against a notes column) and to size a first fetch; it
knows nothing about the spread of lengths, so it carries the mean-fill error
above.

**Measured.** The fill of a stored filter is `cardinality(bf) / m`, and `bf`
is the set-bit positions, so a histogram of set-bit counts is a histogram of
fills. One aggregate gives it, at most `m` buckets:

```sql
SELECT cardinality(eql_v4.match_term(name)) AS bits, count(*)
FROM users TABLESAMPLE SYSTEM (1)
WHERE name IS NOT NULL
GROUP BY 1
```

`Stats::measured(rows, histogram)` keeps the buckets, and `target_limit`
computes `p = Σ count_i · (bits_i / m)^b / Σ count_i` for whatever `b` the
query has. The sample bounds the cost on a large table; `TABLESAMPLE` is a
page sample, which is fine for a distribution and unsuited to an exact count.
It is also a sample of pages, so on a table of a few thousand rows a 1%
sample can select none; below that size the clause is dropped and the whole
table is read, which costs nothing worth saving. `rows` counts the rows the
predicate can match, the non-NULL ones, since the histogram's pass rate is
over those and a NULL never passes. One catalog read gives it:

```sql
SELECT (c.reltuples * (1 - coalesce(s.null_frac, 0)))::bigint
FROM pg_class c
LEFT JOIN pg_stats s
  ON s.schemaname = 'public' AND s.tablename = 'users' AND s.attname = 'name'
WHERE c.oid = 'users'::regclass AND c.reltuples >= 0
```

`reltuples` is −1 for a table that has never been vacuumed or analysed,
such as one just bulk-loaded. That is an unknown count, not an empty
table, so the statement returns no row and the application builds no
`Stats`: it pages with a cursor, as for `Unbounded`, or runs `ANALYZE`.
Clamping −1 to 0 would give λ = 0 and a confident fetch of exactly `want`.
A `Limit` never exceeds `i64::MAX`, the largest `LIMIT` PostgreSQL takes.
An empty histogram falls back to the declared prior.

`target_limit` returns a `Limit`: `Rows(n)`, or `Unbounded` when the
statistics say nothing about the stored filters (no prior and no
histogram) or the confidence is not below 1. A `want` of 0 is `Rows(0)`.
`fetch_or(page)` reads either as a fetch size, for a caller that pages
anyway, and cuts `page` to `i64::MAX`. Past ten million expected false
positives the quantile is the conservative `λ + 8√λ`, since the query is
hopeless at that point; it covers a confidence up to `1 − 1e-15`, and a
higher one there is `Unbounded`.

Where the numbers live and who keeps them in step was asked on the review,
so it is written down. They are read from the server by the application, at
startup or on a timer, and cached in the client as plain numbers. Nothing
about them is secret: the set-bit count of a stored filter is visible to the
server already, since the server holds the filter, and the row count is in
the catalog. Several clients of one database each read the same table and
need no coordination; two that disagree are both approximately right. A
stale `Stats` moves the confidence, never the correctness, because `verify`
still decides every row. A column that has never been measured uses the
declared prior.

A third statistic answers a different question. `SELECT count(*) FROM users
WHERE name @@ $1` is the candidate count `C = T + FP`, index-only. `C` is the
true minimum: fetch `C` rows and every real match is among them. It is a
count per query rather than a cached statistic, and `p·N` then says how much
of `C` is noise.

#### Worked numbers

With the EQL v4 defaults (3-grams, `k = 6`, `m = 2048`), a million rows, every
row at the stated length and 99% confidence:

| stored tokens | needle | `b` | `p` | `λ` | `LIMIT` |
| --- | --- | --- | --- | --- | --- |
| 20 (a name) | `ali` | 6 | 3.4e-8 | 0.03 | `want + 1` |
| 200 (a paragraph) | `ali` | 6 | 7.6e-3 | 7,600 | `want + ~7,800` |
| 200 | `alice` | 18 | 4.4e-7 | 0.44 | `want + 3` |

The bad case is a short needle against long stored text, and the library can
say so before the query runs. `λ` is also the number of decrypts a query will
waste, which gives the Bloom parameters a number to be tuned against. Taking
the bad row: a needle one character longer (`alic`, two 3-grams, `b = 12`)
brings `λ` to 58; doubling `m` to 4,096 brings it to 268 at `b = 6`, and
`m = 8,192` to 6. A smaller `k` makes it worse, not better: at `k = 3` the
needle `ali` sets 3 bits, so `b = 3`, and although the fill falls to
`1 − e^(−3·200/2048) = 0.254`, `p = 0.254³ = 0.016` and `λ` is about 16,400,
twice the `k = 6` figure. For one-gram needles the best `k` is near
`(m/n)·ln 2 ≈ 7`, so `k = 6` is close to it already. The cheapest lever is
often a minimum needle length for long-text columns, which a `Probabilistic`
term can report from `target_limit` alone.

#### Text ordering

`Lt` on text is exact, decision 4, so none of the above applies to it: no `p`,
no `verify`, no `target_limit`. The term is an order term over the column's
order key, which is `orderable-bytes`' encoding of the value after the text
transform the column declares (the system ADR-0002's fold, or another, since
the encoding is pluggable), and the server compares keys. Two values with one
key tie; that is what the column declared, and an earlier draft of this ADR
was wrong to call it a false positive and put the term under `Probabilistic`.
Its use is ordering and cursor paging on names (`ORDER BY name`, "the page
after Nguyen"), and EQL v4 carries `query_text_ord` and `query_text_ord_ore`
for it. Whether the Rust library produces the term is a catalog question
(`TextOrdOre` is unproducible today, pending the system ADR-0002); nothing
else in this ADR depends on it, and if text ordering is dropped this paragraph
goes with it.

A `Ranked` term's `target_limit` applies the index's configured recall
factor and needs no `Stats`.

### 6. The loop is a documented pattern, not a library helper

A `Probabilistic` term composes with the caller's query library like this. One
shot, with a bound, and the completeness check from decision 5:

```rust
let term  = cipher.query(op::Matches, "ali").on(&users::name).await?;
let fetch = term.target_limit(10, &stats).fetch_or(50);

let rows: Vec<UserRow> = sqlx::query_as(
    "SELECT id, name FROM users WHERE name @@ $1 ORDER BY id LIMIT $2",
)
.bind(sqlx::types::Json(&term))
.bind(fetch as i64)
.fetch_all(&pool).await?;

let exhausted = (rows.len() as u64) < fetch;
let users = cipher.open(rows).using(&users_plan).await?;
let hits: Vec<User> = users.into_iter().filter(|u| term.verify(&u.name)).take(10).collect();
// hits.len() < 10 && exhausted: there are no more matches.
// hits.len() < 10 && !exhausted: page on from the last id.
```

Cursor paging, which needs no `Stats`, works for `Limit::Unbounded`, and is
the form that is complete by construction. A cursor is the last row's value of
an exactly ordered column, carried into the next page as `WHERE id > $cursor`
instead of an `OFFSET`:

```rust
let term = cipher.query(op::Matches, "ali").on(&users::name).await?;
let (mut hits, mut after, page) = (Vec::new(), 0_i64, 50_i64);

while hits.len() < 10 {
    let rows: Vec<UserRow> = sqlx::query_as(
        "SELECT id, name FROM users WHERE name @@ $1 AND id > $2 ORDER BY id LIMIT $3",
    )
    .bind(sqlx::types::Json(&term)).bind(after).bind(page)
    .fetch_all(&pool).await?;
    if rows.is_empty() { break; }
    after = rows.last().unwrap().id;
    hits.extend(cipher.open(rows).using(&users_plan).await?.into_iter().filter(|u| term.verify(&u.name)));
}
hits.truncate(10);
```

On paging generally. `LIMIT` and `OFFSET` are not going anywhere: every SQL
library emits them and legacy applications page with them. The one that is
unsound over a `Probabilistic` predicate is `OFFSET`, because the false
positives shift it, and a page of real rows is not a fixed distance into the
candidates. `LIMIT` with the bound is sound for one page; a cursor is sound
for every page. Two further options are on the EQL side and listed under
deferred: ordering candidates by fill, so the least likely false positives
come first, and the candidate count `C`, which turns "how far through" into
a number.

The library ships `verify` and `target_limit`. It does not ship the loop,
because the loop runs queries. That may change when Stack Similarity lands and
the ranked loop is worth packaging; it is deferred, not refused.

### 7. `Between` is one term and one operand

`cipher.query(op::Between, &(lo, hi)).on(&plan)` produces one term,
`sem::RangeQuery`, carrying the index's term for each bound (the ORE left
ciphertexts, once block ORE lands), inclusive at both ends, and the client
refuses `lo > hi` (`TermError::InvertedRange`) before either term is
derived; `(v, v)` is one value. One call derives both bounds, under one
context, so a caller cannot pair a bound from one column with a bound from
another. The ordering operators are answered over the integer types
(`op::Ordered`), by the ORE index by default and by OPE through `.via(Ope)`.

In SQL the term stays one operand. EQL v4 gains a function that takes the
column and the range, and a range query domain beside each ordered query
domain to carry it, for OPE as well as ORE: `query_integer_ord_ore` gains
`query_integer_range_ore` and `query_integer_ord_ope` gains
`query_integer_range_ope`, one per (family, term) as decision 8 has it. The
example uses the ORE one; the catalog names them:

```sql
WHERE eql_v4.between(age, $1::eql_v4.query_integer_range_ore)
```

The term is as indivisible in SQL as it is in Rust: one placeholder, so no
statement can bind the low bound of one term with the high bound of another
or bind them in the wrong order, and a binding hands back one value for the
term as it does for every other (appendix B). An earlier draft spelled the
range as the native `BETWEEN` with the term's two halves as two parameters;
this one withdraws it, because it split in SQL the one thing the Rust side
had just joined, and every SDK had to grow a `bounds()` to feed it.

What the one-operand form asks of EQL is that the planner still see a range.
`eql_v4.between` must be a SQL function PostgreSQL inlines at planning time
(`LANGUAGE sql`, one expression, `$1 >= lo($2) AND $1 <= hi($2)` with
immutable accessors, and not `STRICT`), so that a btree over the ORE term
serves it as one range scan. `STRICT` matters: PostgreSQL inlines a `STRICT`
SQL function only when its body is strict too, and `a >= x AND b <= y` is not
(`NULL AND false` is `false`), so a `STRICT` declaration would pass a test
that only calls the function and then not be inlined. A function the planner cannot inline is a call per row on a
sequential scan, which no index can rescue. That is an EQL-side requirement
with an EQL-side test, and it is why the function and the domain arrive
together.

### 8. One query operand domain per (family, term) in EQL v4

The EQL v4 side carries one query domain per (type family, term), such as
`eql_v4.query_text_match` and `eql_v4.query_integer_ord_ore`, rather than one
per operator or one per stored domain. This is the "option B" of the design
discussion and is recorded here so the Rust side's `Supports<Op, S>::Query`
has a fixed target: the query term for an (index, operator) serialises to
exactly one of those domains. `Between` serialises to one value of the
family's range domain, which carries both bounds (decision 7).

## Considered options

**Keep the index as the thing the caller names** (status quo). Rejected for
the three costs in the problem statement. It is also what the review of
#1164 ran into: storing short `TextMatch` text needs the stored term and the
query term for a Bloom filter to differ, and the API had no place to say so.

**Operators as a runtime enum**, as `cipherstash-client` did. Rejected: an
unsupported operator becomes a runtime error, and operator-specific input has
to be a tagged union. Rust can carry both in the type.

**First index that supports the operator**, as `cipherstash-client` did.
Rejected: the choice is per domain type and must be deliberate, because it
decides what the query term reveals.

**A `Fidelity` enum on every term, and `verify` that returns `true` for exact
terms**. Considered and dropped: a method that is a no-op on most terms is
noise, and a runtime enum says at runtime what the trait says at compile
time.

**A fallible `verify`.** Considered and dropped, decision 4: every failure
is a non-match.

**The library returns candidates and verifies them itself**
(`cipher.query(..).fetch(&pool)`). Rejected: the library would run queries,
own `LIMIT` and paging, and need a driver. That is a query interface, which
this library is not.

**A range as two terms**, `query(op::Gte, lo)` and `query(op::Lte, hi)` bound
as two predicates. Rejected in favour of one `Between` term, decision 7. `Gte`
and `Lte` themselves stay; they are the open-ended comparisons, and a range
is not two of them.

**Native `BETWEEN` with the term's halves as two parameters.** The previous
draft of decision 7. Dropped: it splits one operand across two placeholders,
and every binding has to hand back halves to feed it.

**`expected_tokens` deferred until the stats query exists.** Dropped: the
declared prior is what makes `target_limit` usable on a column nobody has
measured, and it costs one number in the index declaration. Decision 5.

## Consequences

ADR-0004 decision 5 is superseded. Its rule — a stored term goes through a
target, a query term comes from the query path — stands, but its
justification was wrong and is replaced: the two differ for every index but
HMAC and lossless OPE, and the query path is `cipher.query(op, ..)`, which
produces a term the stored side never would.

ADR-0007 needs an amendment once this ADR is accepted. The plan a binding
lowers names a field and, for a query, an index; it has no operator and no
operator input, and the generated code of a language SDK has no `verify`.
Appendix B is the sketch to amend from.

A caller who wants a real-match count or offset paging on a `Probabilistic`
term cannot have either from the server. `COUNT(*)` is an upper bound, and
`OFFSET` shifts with the false positives. Cursor paging only. This is the
most visible change for users and is the reason to settle it now.

Only the inexact terms in a `WHERE` need verifying. `age > $2 AND name @@ $1`
verifies `name` and not `age`.

Verification costs decrypts, not database work, and tells the server nothing
it does not already know. The cost is `λ` wasted rows per query: `λ` more
rows on the wire and `λ` more entries in the batched key retrieval the real
rows ride in anyway, one request per 500 values per keyset. The network call
count is set by the batch size and the number of keysets, not by `λ`; the
decrypt work and the wire bytes are. That is the number the Bloom parameters
are tuned against.

A verified row needs its `Plaintext`, which decision 4 says is not always
the user's value. EQL v4 values carry `c` beside their terms, so a text or
JSON column's query already selects it. A similarity index stores its vector
separately, so a `Nearest` query must select the embedding, or the sketch,
as well.

Text ordering, if the catalog keeps it, needs no special case: `Lt` on text
is an exact term over the order key, and what that key folds is the system
ADR-0002's decision (the value model, linked above), which keeps equality off
the order term for the same reason.

EQL v4 gains `eql_v4.between(column, range)` and a range query domain per
ordered query domain, ORE and OPE, under the inlining requirement of decision 7. That is
EQL-side work this ADR asks for, not a deferral.

It is a breaking change to the query chain. `cipher.query(v).using(&plan)`
with `.equality()` becomes `cipher.query(op::Eq, v).on(&plan)`: the operator
first, and `on` for a query where a write says `using`.
`cipher.query_index(index, v).on(&plan)`, the index's own term, is gone:
every index a plan can declare is reachable through an operator, ORE and OPE
through the ordering operators (#1186). The write side (`encrypt`, targets,
plans) does not change.

## Deferred

- Whether `Nearest` is `cipher.query(op::Nearest, ..)` or a separate
  `cipher.nearest(..)` entry, and whether a ranked query can carry further
  predicates. The latter is possible only when the server can join candidates
  to rows (the `ByRow` similarity mode), not in the per-band pseudonymous mode.
- `ORDER BY cardinality(eql_v4.match_term(col))` on the EQL side, so
  low-fill rows — the least likely false positives — come first. It reveals
  nothing `bf` does not.
- Whether `Nearest` over Bloom scores by bit overlap or needs token-level
  terms. An index-design question, not an API one.
- Packaging the cursor and ranked loops once Stack Similarity exists.

## Appendix A: the terms in sqlx

Each operator below is shown as the Rust call that produces the term, the
SQL it binds into, and what the caller does with the rows. The casts name
EQL v4's query domains (decision 8), as the v4 tests bind them today:
`$1::eql_v4.query_text_eq`, with the JSON text of the term as the parameter.
The JSON operators are spelled as EQL v3 ships them, since v4 does not carry
`json` yet. `UserRow` is the row as the driver returns it, with the EQL
columns as `sqlx::types::Json<EqlValue>`, and `cipher.open(rows).using(&users_plan)`
opens every row under the plan the table was written with, in one key
request, and yields `User`s.

**`Eq`, exact.** The term is an HMAC; the operator is `=`. Nothing to verify.

```rust
let term = cipher.query(op::Eq, "bob@example.com").on(&users::email).await?;

let rows: Vec<UserRow> = sqlx::query_as(
    "SELECT id, email, name FROM users WHERE email = $1::eql_v4.query_text_eq",
)
.bind(sqlx::types::Json(&term))
.fetch_all(&pool).await?;
let users = cipher.open(rows).using(&users_plan).await?;
```

**`Lt` on an integer, exact.** The term is the ORE left ciphertext; the
operator is `<`. `Lte`, `Gt` and `Gte` are the same shape.

```rust
let term = cipher.query(op::Lt, 40).on(&users::age).await?;

let rows: Vec<UserRow> = sqlx::query_as(
    "SELECT id, email, name, age FROM users WHERE age < $1::eql_v4.query_integer_ord_ore ORDER BY age",
)
.bind(sqlx::types::Json(&term))
.fetch_all(&pool).await?;
```

**`Between`, exact, one term and one parameter** (decision 7).

```rust
let term = cipher.query(op::Between, (18, 65)).on(&users::age).await?;

let rows: Vec<UserRow> = sqlx::query_as(
    "SELECT id, email, name, age FROM users
     WHERE eql_v4.between(age, $1::eql_v4.query_integer_range_ore)",
)
.bind(sqlx::types::Json(&term))
.fetch_all(&pool).await?;
```

**`Matches`, probabilistic.** The term is a Bloom filter over the needle's
3-grams, as `{"bf": [59, 96, …]}` in the fixture the Go SDK tests against;
the operator is `@@`, column on the left. The query selects the ciphertext
(`name` carries `c`) because `verify` needs the decrypted text, and the
`LIMIT` comes from `target_limit`:

```rust
let term  = cipher.query(op::Matches, "ali").on(&users::name).await?;
let fetch = term.target_limit(10, &stats).fetch_or(50);

let rows: Vec<UserRow> = sqlx::query_as(
    "SELECT id, name FROM users WHERE name @@ $1::eql_v4.query_text_match ORDER BY id LIMIT $2",
)
.bind(sqlx::types::Json(&term))
.bind(fetch as i64)
.fetch_all(&pool).await?;

let exhausted = (rows.len() as u64) < fetch;
let hits: Vec<User> = cipher.open(rows).using(&users_plan).await?
    .into_iter()
    .filter(|u| term.verify(&u.name))
    .take(10)
    .collect();
```

The `Stats` it used were read once, at startup, by the application:

```rust
// No row while `users` has never been analysed: the count is unknown.
let rows: Option<i64> = sqlx::query_scalar(
    "SELECT (c.reltuples * (1 - coalesce(s.null_frac, 0)))::bigint
     FROM pg_class c
     LEFT JOIN pg_stats s
       ON s.schemaname = 'public' AND s.tablename = 'users' AND s.attname = 'name'
     WHERE c.oid = 'users'::regclass AND c.reltuples >= 0",
)
.fetch_optional(&pool).await?;
let histogram: Vec<(i32, i64)> = sqlx::query_as(
    "SELECT cardinality(eql_v4.match_term(name)) AS bits, count(*)
     FROM users TABLESAMPLE SYSTEM (1) WHERE name IS NOT NULL GROUP BY 1",
)
.fetch_all(&pool).await?;
let stats = rows.map(|rows| {
    Stats::measured(rows as u64, histogram.into_iter().map(|(b, n)| (b as u32, n as u64)))
});
```

or, before anyone has measured, `Stats::declared(1_000_000)`, which uses the
`expected_tokens` the index declares.

**`Matches` with another predicate.** Only the probabilistic term is
verified; `age` is exact and the server's answer stands:

```rust
let name = cipher.query(op::Matches, "ali").on(&users::name).await?;
let age  = cipher.query(op::Gt, 30).on(&users::age).await?;

let rows: Vec<UserRow> = sqlx::query_as(
    "SELECT id, name, age FROM users
     WHERE name @@ $1::eql_v4.query_text_match AND age > $2::eql_v4.query_integer_ord_ore
     ORDER BY id LIMIT $3",
)
.bind(sqlx::types::Json(&name))
.bind(sqlx::types::Json(&age))
.bind(name.target_limit(10, &stats).fetch_or(50) as i64)
.fetch_all(&pool).await?;
let hits: Vec<User> = cipher.open(rows).using(&users_plan).await?
    .into_iter().filter(|u| name.verify(&u.name)).take(10).collect();
```

**`AtPath<Eq>`, exact.** The term is a value-selector: the MAC of the path
and the leaf's equality term, as one `query_json` operand; the operator is
containment, `@>`, which a GIN index serves. The row is a match when the
document holds that value at that path, and nothing is verified.

```rust
let term = cipher.query(op::AtPath(op::Eq), ("$.address.city", "Sydney")).on(&users::profile).await?;

let rows: Vec<UserRow> = sqlx::query_as(
    "SELECT id, profile FROM users WHERE profile @> $1::eql_v3.query_json",
)
.bind(sqlx::types::Json(&term))
.fetch_all(&pool).await?;
```

**`AtPath<Gte>` on a number, exact.** Ordering at a path takes two parts, a
selector and a leaf term, because the SQL is `col -> selector >= term`. The
accessor term exposes both:

```rust
let term = cipher.query(op::AtPath(op::Gte), ("$.score", 80)).on(&users::profile).await?;

let rows: Vec<UserRow> = sqlx::query_as(
    "SELECT id, profile FROM users WHERE profile -> $1::text >= $2::eql_v3.query_double_ord",
)
.bind(term.selector())
.bind(sqlx::types::Json(term.leaf()))
.fetch_all(&pool).await?;
```

`AtPath<Lt>` on a text leaf, if the catalog keeps text ordering, is exact,
as `Lt` on a text column would be: the leaf's order term compares order
keys, and there is nothing to verify.

**`Nearest`, ranked.** Stack Similarity has no EQL spelling yet, so this is
the shape and not a statement that runs. The term is a set of band tokens;
the server returns candidates by token overlap; `score` re-ranks on the
decrypted embedding, which the query must select:

```rust
let term  = cipher.query(op::Nearest, embedding).on(&docs::vector).await?;
let fetch = term.target_limit(10);

let rows: Vec<DocRow> = sqlx::query_as(
    "SELECT id, vector FROM docs WHERE vector ~~ $1 LIMIT $2",   // operator not yet defined
)
.bind(sqlx::types::Json(&term)).bind(fetch as i64)
.fetch_all(&pool).await?;

let mut docs = cipher.open(rows).using(&docs_plan).await?;
docs.sort_by_key(|d| std::cmp::Reverse(term.score(&d.vector)));
docs.truncate(10);
```

What the appendix shows, read across: an exact term is one `bind` and
nothing after the query; a probabilistic term is one `bind`, a `LIMIT` from
the term, and a `filter` after decrypt; a ranked term is one `bind`, a
`LIMIT` from the term, and a sort after decrypt. No SQL library has to know
which is which, and the Rust types make it impossible to forget.

## Appendix B: the model in Go and TypeScript

ADR-0007 says a binding reaches the engine through a plan lowered from data,
and ADR-0008 says a language SDK is what users of that language touch, which
is never the plan. This appendix asks what each of those gains from the
model above, in two languages: Go, which has a Stack Encrypt SDK today, and
TypeScript, which does not. The TypeScript half is a sketch of a binding and
an SDK built on Stack Encrypt and EQL v4, written to check that the Rust
model will support them well. That SDK will be the next major version of
`@cipherstash/stack`; the current major runs on cipherstash-client through
`@cipherstash/protect-ffi` and writes EQL v3, and nothing below describes
it. It is a check on the model, not a decision; the decisions for the
bindings come with the ADR-0007 amendment.

### What crosses the binding

Today the Go guest has one query export: `Cipher.Query(plan, field, value)`
returns the JSON of the field's query operand, and the engine picks the term
by the field's EQL type. The existing TypeScript binding, for comparison,
has `encryptQuery(value, { table, column, queryType })`, where `queryType`
names an index flavour (`equality`, `freeTextSearch`, `orderAndRange`). Both
name an index, which is the problem statement.

A Stack Encrypt binding for TypeScript would be the guest the Go SDK embeds,
or a napi build of the same crate, and would take the same plan the Go SDK
lowers (ADR-0007). Under this ADR four more things cross it, all as data,
and each is a capability the data grammar does not have yet, added once
(ADR-0007, last bullet of the decision):

1. **An operator name with its input**, in place of the index:
   `{"op": "matches", "input": "ali"}`, `{"op": "between", "input": [18, 65]}`,
   `{"op": "at_path", "path": "$.score", "inner": {"op": "gte", "input": 80}}`.
   The engine resolves `Answers<Op, S>` for the field's type and refuses an
   operator the type does not answer, with the same shape of error a
   mistyped field gets today.
2. **The term back**, as the JSON its query domain takes, plus which domain
   that is. A `Between` term is one value like any other.
3. **`verify`** as an export: `(term, decrypted value) → bool`, batched as
   `(term, [values]) → [bool]` so a page costs one crossing. The value has
   already come out of the guest as a decrypt, so sending it back in is no
   new exposure. The alternative, a tokenizer in each language, is the
   "lives twice" cost ADR-0007 accepts only for an encoder, and a tokenizer
   that drifts from the one that stored the filter verifies the wrong thing.
4. **`target_limit`** as an export, `(term, want, stats) → limit`, for the
   same reason: the arithmetic is small, but `b` is a property of the term the
   engine built, and the fill formula belongs beside the index configuration.

What does *not* cross is the fidelity as a runtime value. Something on the
language side asks the engine, before the program runs, which operators each
EQL type answers and whether each is exact, probabilistic or ranked, the way
`stashgen` already asks `eql.Types` whether a type is producible. In Go that
something is the generator; in TypeScript it can be the type system, as the
TypeScript section shows. Either way the code a user writes has `verify`
only where there is something to verify, which is the compile-time property
decision 4 wants, reconstructed in a language without traits.

### Go

The generated field surface grows from one `Query` to one method per
operator the type answers, with the operator's input in the signature:

```go
q, err := users.Fields.Email.Eq(ctx, cipher, "bob@example.com")   // eql.TextEqQuery
q, err := users.Fields.Age.Lt(ctx, cipher, int32(40))              // eql.IntegerOrdOreQuery
q, err := users.Fields.Age.Between(ctx, cipher, int32(18), int32(65)) // eql.IntegerRangeOreQuery, one value
q, err := users.Fields.Name.Matches(ctx, cipher, "ali")            // eql.TextMatchQuery
```

A field whose type does not answer an operator has no such method, so the
call does not compile. `eql.TextMatchQuery` carries `Verify(value string)
bool` and `TargetLimit(want uint64, stats eql.Stats) eql.Limit`;
`eql.TextEqQuery` carries neither. Each query type keeps `driver.Valuer`, so
it binds as a parameter in any library built on `database/sql` or pgx:

```go
q, _ := users.Fields.Name.Matches(ctx, cipher, "ali")
limit := q.TargetLimit(10, stats).FetchOr(50)

rows, err := db.QueryContext(ctx,
    `SELECT id, name FROM users WHERE name @@ $1::eql_v4.query_text_match ORDER BY id LIMIT $2`,
    q, limit)
// scan into []users.Encrypted, then
people, err := users.Decrypt(ctx, cipher, encrypted)
hits := people[:0]
for _, p := range people {
    if q.Verify(p.Name) {
        hits = append(hits, p)
    }
}
```

The same statement in the libraries Go programs use:

- **sqlc** keeps the SQL in a `.sql` file with the cast written out, and a
  type override maps `eql_v4.query_text_match` to `eql.TextMatchQuery`, so
  the generated `ListUsersByName(ctx, q, limit)` takes the term as a typed
  argument.
- **pgx** binds it the same way as `database/sql`; `pgx.CollectRows` into
  the generated struct, then `Decrypt` and `Verify`.
- **GORM**: `db.Where("name @@ ?::eql_v4.query_text_match", q).Order("id").Limit(limit).Find(&encrypted)`.
- **Bun** and **sqlx** (the Go one): the same `?` placeholder with the cast.

`Verify` runs in the guest, batched. A page of fifty rows is one call after
the one `Decrypt` call, which is in keeping with the batching the Go SDK
already does for seal and open. The cursor loop is the Rust one with
`WHERE id > $2`, and `TargetLimit` is read once per query. The width rules
hold: `Age.Lt` takes an `int32` because `Integer` does, so a widened `int`
is refused at compile time, as it is at generate time for the field.

### TypeScript

Go needs a generator because its type system cannot derive a field's
methods from a declaration. TypeScript can, so the sketch below has no
generate step: the schema is a value, its type is the plan, and the
operators a column answers are read off that type. The function and type
names are illustrative; the package is `@cipherstash/stack` at its next
major, and the shapes are the point.

**The schema is the plan.** A table is declared with the EQL v4 types, which
is the data grammar of ADR-0007 written as TypeScript, and the match index
carries its `expectedTokens` prior from decision 5:

```ts
import { table, passthrough, eql } from '@cipherstash/stack'   // the next major

const users = table('users', {
  id:      passthrough<number>(),
  email:   eql.TextEq(),
  name:    eql.TextMatch({ expectedTokens: 20 }),
  age:     eql.IntegerOrdOre(),
  profile: eql.Json(),
})

const client = await Encryption.connect()            // the Stack Encrypt guest, through napi or wasm
const cipher = client.keyset('tenant-42')
```

**An operator is a method on the column, and only the answered ones exist.**
`cipher.query(column)` returns an object whose methods are the operators the
column's EQL type answers, each taking that operator's input:

```ts
const email = await cipher.query(users.email).eq('bob@example.com')      // EqTerm
const age   = await cipher.query(users.age).lt(40)                        // LtTerm
const range = await cipher.query(users.age).between(18, 65)               // BetweenTerm, one value
const name  = await cipher.query(users.name).matches('ali')               // MatchesTerm
const city  = await cipher.query(users.profile).atPath('$.address.city').eq('Sydney')

cipher.query(users.email).matches('bob')   // type error: TextEq answers eq and neq
cipher.query(users.age).lt('40')           // type error: IntegerOrdOre takes a number
```

The type behind it is the `Answers<Op, S>` table of decision 3, as a mapped
type over the column's EQL type:

```ts
type Query<C extends EqlColumn> = {
  [Op in AnswersOf<C>]: (input: InputOf<C, Op>) => Promise<TermOf<C, Op>>
}
```

and `TermOf` carries the fidelity of decision 4 as the presence of methods,
not as a flag:

```ts
interface Term<P>          { readonly domain: string; toJSON(): unknown }   // exact: nothing else
interface Probabilistic<P> extends Term<P> { verify(value: P): boolean; targetLimit(want: number, stats: Stats): Limit }
interface Ranked<P>        extends Term<P> { score(value: P): number;   targetLimit(want: number): number }
```

`name.verify('Alice')` type-checks; `email.verify(..)` does not exist. The
engine does the verifying through the binding, batched per page, for the
reason given above; the method on the term is a thin call. `verify` returns
`boolean`, never throws, as decision 4 says.

**The term binds as a parameter, and the cast is in the SQL.** A term
serialises to the JSON its query domain takes (`toJSON`), so every PostgreSQL
driver binds it unchanged. The statement from decision 6, in the drivers
TypeScript programs use:

```ts
// pg
const limit = name.targetLimit(10, stats).fetchOr(50)
const { rows } = await pool.query(
  'SELECT id, name FROM users WHERE name @@ $1::eql_v4.query_text_match ORDER BY id LIMIT $2',
  [name, limit],
)

// postgres.js
const rows = await sql`
  SELECT id, name FROM users
  WHERE name @@ ${name}::eql_v4.query_text_match ORDER BY id LIMIT ${limit}`

// Kysely
const rows = await db.selectFrom('users').select(['id', 'name'])
  .where(sql`name @@ ${name}::eql_v4.query_text_match`)
  .orderBy('id').limit(limit).execute()
```

Decrypt and verify are the same two steps in each:

```ts
const people = await cipher.decrypt(users, rows)        // typed by the schema: name is a string
const hits = people.filter((p) => name.verify(p.name)).slice(0, 10)
const exhausted = rows.length < limit
```

`Between` is one call and one parameter, like every other term:

```ts
await pool.query(
  'SELECT id, age FROM users WHERE eql_v4.between(age, $1::eql_v4.query_integer_range_ore)',
  [range],
)
```

**The ORM integrations are the same terms with the SQL written for them.**
A Drizzle integration maps the schema to `customType` columns and gives each
operator a helper that returns the SQL fragment and the term together, so the
application never handles the term itself:

```ts
const q = await ops.matches(users.name, 'ali')          // { sql, verify, targetLimit }
const rows = await db.select().from(users)
  .where(q.sql)                                         // name @@ '…'::eql_v4.query_text_match
  .orderBy(users.id)
  .limit(q.targetLimit(10, stats).fetchOr(50))
const hits = (await cipher.decrypt(users, rows)).filter((u) => q.verify(u.name)).slice(0, 10)
```

`ops.eq` returns `{ sql }` and no `verify`, by the same types. A Prisma
integration spells the operator on the field (`u.name.eqlMatches('ali')`)
and returns the term beside the query the same way. In both, `between` is
one helper that binds one parameter.

**Stats** come from the two statements of decision 5, run by the
application, or from the declared prior:

```ts
// ROWS_SQL is decision 5's rows statement: no row while the count is unknown
const [count] = (await pool.query(ROWS_SQL)).rows
const stats = count && Stats.measured(
  count.rows,
  (await pool.query('SELECT cardinality(eql_v4.match_term(name)) AS bits, count(*) FROM users TABLESAMPLE SYSTEM (1) WHERE name IS NOT NULL GROUP BY 1')).rows,
)
const prior = Stats.declared(1_000_000)   // uses users.name's expectedTokens
```

**The runtime-schema case.** The `wasm-inline` path today takes a schema
loaded at runtime, with no TypeScript type behind it. There `cipher.query`
cannot narrow, every operator method exists, and the engine's refusal of an
unsupported operator is the check, on the first query rather than at build
time. That is where the Go SDK was before `stashgen`, and the same fix
applies if it matters: a generator that reads the schema and emits the
declaration above.

### What the two languages say about the model

Four things survive the translation, and one does not.

The operator-not-index call survives, and the existing TypeScript SDK
already spells its queries that way (`ops.matches`, `eqlBetween`,
`eqlJsonPathGte`): the Rust API is catching up to its own bindings.

The split between an exact and a probabilistic term survives as the presence
or absence of `verify`, decided by a generator in Go and by a mapped type in
TypeScript, both fed by the engine's catalog. Neither language needs a
`Fidelity` enum either.

The one-operand `Between` survives unchanged: one term, one placeholder, in
every driver and every ORM.

The declared prior survives as one field in the schema (`expectedTokens`),
which is where a TypeScript user would expect to write it.

What does not translate is the compile error for an unsupported operator
when the schema is only known at runtime. There the engine's refusal is the
check, and nothing about the Rust model makes it fire earlier; only a
generator does.
