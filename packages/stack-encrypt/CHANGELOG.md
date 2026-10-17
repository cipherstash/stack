# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A binding queries by operator** (`dynamic` feature; ADR-0009, ADR-0007
  amended 2026-10-16). `dynamic::query_term(keyset, &plan, field, op,
  input, &resolver)` derives the query term for a field of a data plan, an
  operator (`dynamic::OpSpec`, named `eq`, `lt`, `lte`, `gt`, `gte`,
  `between` or `matches`) and its input, reading the input as the field's
  declared type first. The index that answers is the typed path's default
  (`OpSpec::answered_by`), and the term is the bytes the typed query chain
  derives for the same query. A field that names an EQL type answers through
  the type's query twin. An operator the field does not answer is refused
  as a mistyped value is, `dynamic::Error::Source` naming the field with
  `Reason::OperatorNotAnswered`; `check_query` refuses the same without a
  cipher. `dynamic::verify` checks a page of decrypted values against a
  probabilistic query and `dynamic::target_limit` sizes its fetch from the
  term's bytes and `Stats` (`Stats::from_value` reads their wire form), by
  the code the typed `MatchQuery` runs, with the field's own match options;
  neither uses a key. The catalog entry of an EQL type
  (`TargetDescriptor::to_value`) lists the operators the engine answers for
  it, each with its fidelity (`dynamic::Fidelity`), arity and index
  (`TargetDescriptor::operators`).
- **An EQL type with a match index answers `matches` through its twin.**
  `TargetDescriptor::with_match_options` gives the engine the options a
  type's match index is built under (`TargetDescriptor::match_options`, not
  on the wire), and such a type answers `matches` (probabilistic) as well as
  its exact operators: `query_term` derives the type's query twin, and
  `verify` and `target_limit` run under the type's options, the latter
  reading the twin's `bf`. A type with a match index and no options still
  answers no probabilistic operator. The Go guest gives `TextMatch` EQL's
  match options, so it answers `matches` through `TextMatchQuery`.
- **A binding asks which operators a field answers.**
  `dynamic::field_operators(&plan, field, &resolver)` lists the operators a
  field of a data plan answers, each with the index that answers it: what
  `query_term` derives a term for on that field and nothing else, for a
  field declared with indexes as for one that names an EQL type.
  `dynamic::operator_to_value` writes one entry in the catalog's wire form.
  A generator asks this before the program runs, so it writes one query
  method per operator and holds no copy of the table.
- **A query names an operator, not an index.**
  `cipher.query(op::Eq, "bob@example.com").on(&plan)` and
  `cipher.query(op::Matches, "ali").on(&plan)`: the operator comes first, as
  a value, and the plan named by `on` finds the index that answers it
  (ADR-0009). An index declares the operators it answers (`op::Supports`), a
  target type names the index that answers each one for it (`op::Answers`),
  and a plan that declares indexes uses the operator's default index
  (`op::DefaultIndex`); both name the index by its type, whose `Default` is
  the index. `.via(index)` before `.on(&plan)` names another index the plan
  declares, such as a match index with its own configuration.
  `op::Matches` is the case-insensitive operator, as a value;
  `op::Matches.case_sensitive()` is the other, and the case types are
  `op::CaseInsensitive` and `op::CaseSensitive`. What the plan's type shows
  is checked at compile time: a match query on an integer, an operator a
  target does not answer, and on a one-value plan an index it does not hold
  or a case-sensitive `Matches` against a case-folding index. On a field of
  a fields plan those are refused when the query is awaited, before any key
  is requested, as is a match configuration whose `op::MatchCase` disagrees
  with its options (`PlanError::MatchCase`).
- **A match query has its own type, `sem::MatchQuery`.** It is the filter over
  the query's value; test a stored filter against it with
  `MatchTerms::matches(&query)`. It comes only from a query chain:
  `op::Supports::query` takes an `op::QueryToken` that only this crate can
  make.
- **`Match` is a value.** `.with((Equality, Match))` declares the match index
  under the default configuration, as `Equality` declares equality;
  `Match::<MyConfig>::new()` is another configuration.
- **`verify` drops a match query's false positives after decrypt.** A
  `MatchQuery` is `op::Probabilistic`: `query.verify(&value)` is `true` when
  every token of the query's value, cut by the index's own tokenizer and
  case folding, is a token of the decrypted value. Filter decrypted rows
  with it. The query keeps its value's tokens to do this; they are zeroized
  on drop and never shown by `Debug`, and the tokenizer now zeroizes its own
  copies of the text. An exact term has no `verify`, and none of this
  crate's indexes can answer `op::Matches` but with a probabilistic term
  (`op::TermFor`).
- **The ordering operators, and `Between` as one term.** `op::Lt`, `Lte`,
  `Gt` and `Gte` take one value and `op::Between` a pair of bounds,
  `cipher.query(op::Between, &(18, 65)).on(&age_plan)`, inclusive at both
  ends. They are answered over the integer types (`op::Ordered`) by the
  `Ore` index by default and by `Ope` through `.via(Ope)`; an ordering on
  text does not compile. A comparison's query term is the index's own term
  for the value (`OreTerm`, `OpeTerm`); a range's is one `sem::RangeQuery`
  carrying both bounds' terms, read with `lo()` and `hi()`, so no statement
  can pair the low bound of one query with the high bound of another. A
  range whose low bound is above its high bound is refused when the query
  is awaited, before either term is derived (`TermError::InvertedRange`).
  What a query takes is the operator's `op::Arity` (`op::One` or
  `op::Pair`), and `op::Input` relates the value given to the plaintext the
  plan is checked against (ADR-0009, decision 7).
- **The JSON operators are declared.** `op::Contains` and `op::ContainedBy`
  (`@>` and `<@`) and the accessor `op::AtPath<Op>`, `op::AtPath(op::Eq)`,
  which applies another operator at a JSON path and inherits its fidelity
  (`op::TermFor`): `AtPath<Eq>` and `AtPath<Lt>` are exact. No index
  answers them yet, since this crate has no JSON index, so a query with
  them does not compile until one exists. `AtPath<Op>` takes a leaf
  operator (`op::Leaf`: `Eq`, `Lt`, `Lte`, `Gt`, `Gte`, `Between`,
  `Matches`), so `AtPath<Contains>` and a nested `AtPath<AtPath<_>>` do not
  compile, and its arity, `op::Pathed<A>`, carries the leaf's (`Pathed<One>`
  for `AtPath<Eq>`, `Pathed<Pair>` for `AtPath<Between>`); it has no
  `op::Input` until the JSON index exists (ADR-0009, decision 1).
- **`target_limit` says how many rows a match query should fetch.**
  `query.target_limit(want, &stats)` is `want` plus the false positives
  expected at the confidence `stats` names (99% by default), as an
  `op::Limit`. `op::Stats::declared(rows)` uses the new
  `MatchConfig::expected_tokens()` prior; `op::Stats::measured(rows,
  histogram)` uses a histogram of the stored filters' set-bit counts. With
  neither, the limit is `Limit::Unbounded`, and the caller pages with a
  cursor. A `want` of 0 is `Limit::Rows(0)`. A limit, and `fetch_or`'s
  page, never exceeds `op::MAX_ROWS` (`i64::MAX`), the largest SQL `LIMIT`.
  `rows` counts the non-NULL rows; a table never analysed has an unknown
  count, not 0, and gets no `Stats` (the docs give the catalog read). The
  bound assumes a non-matching row shares no token with
  the query, so on natural text its confidence is nominal; `verify` still
  decides every row.

- **Errors now expose stable codes, help text, and structured details.**
  All error types implement `miette::Diagnostic` with codes such as
  `stack_encrypt::foreign_keyset`. Help text explains how to resolve
  errors callers can fix. `ErrorPayload::payload()` provides details such
  as both keyset IDs for a wrong-keyset error or the field rejected by a
  plan. `ErrorPayload` is re-exported from `stack-profile`. Codes
  identify errors across language boundaries; Rust callers can continue
  matching enum variants.
  The payload policy excludes plaintext, key material, tokens,
  ciphertext, search-index bytes, and raw context values.
- **Data-driven input errors identify the field and the reason.**
  `dynamic::Reason` provides fixed reasons such as `MissingContext`,
  `DuplicateOutput`, and `FieldMissing`, with stable `snake_case` names
  through `as_str()`. Use `dynamic::Error::field()` and `reason()` to
  inspect these details, or `in_field()` to attach a field name.
- **A data plan field may name an EQL type as its target.** Beside the
  output form, `dynamic::record::plan_with` reads `{"context": [...],
  "target": "TextEq", "type"?: ...}` — the two forms are exclusive — and
  resolves the name through a `dynamic::TargetResolver` the host installs:
  the EQL types a build holds (`targets()`, serializable as
  `TargetDescriptor::to_value()` for a guest's `se_targets` export) and how
  to run one. `encrypt_with` zips the type's own `Pending` into the record's,
  so a record with target fields is still one ZeroKMS request, and stores
  the EQL value's JSON bytes under the field's `"eql"` key
  (`record::EQL_KEY`); `decrypt_with` opens it back through the resolver,
  confined to the scope's keyset like every other leaf; `record::query`
  derives a target field's query value. A name the resolver does not know
  or cannot produce, a `"type"` other than the type's plaintext kind, and
  an extended plan (an EQL value is stored under a table and a column, so
  a tenant part has no column) are refused when the plan is built
  (`Error::Target`, `TargetError`), so a guest's `se_plan_check` reports
  them. `dynamic::NoTargets` is the resolver of a build without EQL types
  and refuses every name; the bare `plan`, `encrypt` and `decrypt` run
  under it. `FieldPlan::with_target`, `FieldPlan::target()`,
  `Plan::new_with`.

### Breaking

- **A dynamic plaintext is a frame, not a value tree** (`dynamic` feature;
  #1232, vitaminc ADR 0001). vitaminc 0.6 has no shared value type: a value
  describes itself once, and sinks consume it. `dynamic::ValueFrame` is now
  the engine's plaintext for a value whose type is known only at run time:
  one value as its transport frame, in the engine's value model (an 8- or
  16-bit integer read as the 32-bit integer of its sign, as before; a
  128-bit integer or a date refused, as before), in a `Protected` buffer
  wiped when it drops. It walks its own bytes into any sink (`Encrypt`) and
  is a decrypt target that writes what it opens straight into a frame
  (`Decrypt`). The plaintext paths walk frames:
  - `record::encrypt`, `encrypt_with` and `check_source` take the source as
    any `Encrypt` (a `ValueFrame`, a `vitaminc_aead::Frame`, or an `FfiValue`
    a test spells), walk it once and write each field's value into a
    `ValueFrame` of its own, which is all the engine keeps of it. A value
    refused while the source is split names its field, with the reasons it
    had (`RepeatedKey`, `Unframeable`, `Passthrough`, `FieldType`).
  - `record::decrypt` and `decrypt_with` resolve to one `ValueFrame` (the
    record, or the batch) instead of an `FfiValue`: each field opens into a
    frame, which is walked into its entry of the record's frame and wiped.
  - `read`, `query_term`, `check_query` and `verify` take their input as any
    `Encrypt`, and `read` returns a `ValueFrame`; `verify` takes the page of
    values as any iterator of sources (`ValueFrame::elements` splits a list
    a binding handed over).
  - `IndexSpec` is an `Index` of `ValueFrame` (it was of `FfiValue`), so a
    Rust chain over dynamic fields names `ValueFrame` fields.
  - `TargetResolver::encrypt` and `query` take a `ValueFrame`, and
    `decrypt` resolves to one.

  `FfiValue` stays, as the tree of a binding's control data (plans,
  contexts, options, statistics, configuration, the engine's answers).
  Control data is not plaintext, but a configuration carries credentials
  (a client key, a test build's seed), so its text and bytes leaves stay
  `Protected`.
  Ciphertexts, terms and the cross-language fixtures are byte for byte what
  they were. The Go guest decodes plaintext as `ValueFrame`s and returns an
  opened record's frame as it is. Copies of an opened string that remain in
  the guest's memory after a decrypt were traced to the plaintext output of
  the AES-CTR XOR, left in the unwiped stack temporaries of the RustCrypto
  cipher crates under vitaminc-encrypt's wasm32 backend (their number varies
  with the leaf's length), not to this crate, and
  `TestPlaintextDoesNotRemainInGuestMemoryAfterDecrypt` stays skipped with
  that reason (cipherstash/vitaminc#370). The heap is guarded separately:
  `tests/heap_hygiene.rs` runs the record encrypt (from a `ValueFrame` and
  from a raw frame), the record decrypt (with a nested field), `query_term`
  and `verify` under an allocator that fails the test on any freed block
  still holding plaintext.

- **A match value with no tokens is stored as the empty filter, so
  `KeysetCipher::match_terms` is no longer a query.** In 0.2.0 the same call
  served write time and query time, and refused text that cuts no token
  under the match index's tokenizer (empty or separator-only text, or text
  shorter than the n-gram length) with `TermError::EmptyTermText`. Now it
  derives the stored filter only, and returns the empty filter (`bf: []`)
  for such text with no error. **Do not send the output of `match_terms` as
  a query:** EQL treats an empty filter as contained by every stored filter,
  and its query domains do not refuse one, so that query returns every row
  with no error anywhere. A query comes from `cipher.query(op::Matches, ..)`,
  which still refuses such text with `TermError::EmptyTermText`, when the
  query is awaited, before a term exists and before any keyset is loaded
  (`op::Supports::check` now takes the query's value); `dynamic::term`
  refuses it for a match kind the same way. The stored side is the change a
  caller sees: one two-letter name no longer fails a whole row, the value
  seals and opens as any other, and the `dynamic` record path stores it the
  same way. Storing the empty filter tells a reader of the database that the
  value is empty, separator-only or shorter than the n-gram length
  (ADR-0009).
- **stack-encrypt requires the vitaminc 0.6 crates.** They are the first
  release of vitaminc ADR 0001, which the entries below build on. A crate
  that names a vitaminc type stack-encrypt takes or returns (`Encrypt`,
  `Decrypt`, `Protected`) moves to 0.6 with it.
- **Equality terms derive through `vitaminc-normalize`, so `TextEq` compares
  text in Unicode 16 NFC.** An equality term is the PRF over the value's
  normalized bytes under vitaminc's domain for its kind: `café` written with
  a precomposed `é` and with `e` and a combining accent is one term, every
  integer width of one number is one term (`34u32` and `34i64` match), both
  float widths of one number are one term, and a date, timestamp, decimal
  or uuid derives in a domain of its own. `KeysetCipher::equality_term`,
  `target::equality`, the `Equality` index and `op::Eq` take an `Encrypt`
  that is one scalar where they took a `PrfValue`. A boolean, a null or a
  container has no equality term (`TermError::NoEqualityTerm`); a `bool`
  satisfies the new bound, so equality on one now fails when the term is
  derived where it used to fail to compile. Text holding a code point
  unassigned in Unicode 16 (an emoji newer than it, say) is refused
  (`TermError::Normalize`), when it is written to an equality or match
  column as well as when it is queried: the whole record's encrypt fails.
  Match text is tokenized in the same normal form, and refused the same
  way. Every equality and match term changes
  bytes (the domains move to `/v2`); ORE and OPE terms do not. No stored
  term existed to keep; the record fixture is regenerated. ORE and OPE
  text is still ordered as its raw UTF-8, not normalized, so on a column
  with both an equality and an order index two forms of `café` are one
  value to `=` and two to an ordering. This is a known gap, to be closed
  with block ORE (#1140).
- **`dynamic::Value` and `dynamic::Scalar` are gone.** A field lowered from
  data holds an `FfiValue`, which is now `Clone` (a deep copy into fresh
  `Protected` payloads, as `Value`'s was) and reads as a context label.
  `dynamic::term` takes any `Encrypt` (an `&FfiValue`, a transport frame
  walked in place, a Rust value) and derives at the one scalar it holds;
  `IndexSpec::defines(value)` replaces `IndexSpec::supports(&scalar)`, and
  `IndexSpec` is an `Index<FfiValue>`.
- **A boolean has no order term**, on the typed path and through a plan or
  `dynamic::term`: with two values, an ORE or OPE term would tell anyone
  holding the column which rows are `true`. An ORE or OPE term of a `bool`
  (`KeysetCipher::ore_term`, the `Ore` and `Ope` indexes) is refused with
  the new `TermError::NoOrderTerm`, before any key is minted, where cllw-ore
  used to order one. `dynamic::admits` now refuses ORE and OPE on `bool`, and
  admits equality on `float32` and `float64`, which vitaminc gives an
  equality domain. A 128-bit integer has an equality term and no order
  term.

- **Values describe themselves with vitaminc's new `Encrypt` and read back
  with `Decrypt` (vitaminc ADR 0001).** `KeysetCipher::encrypt`,
  `StackCipher::decrypt` and every target take the new `Encrypt`, a source
  that describes its value to a sink, where they took the old
  visitor-driven `Encrypt`, and `Decrypt` where they took
  `Decrypt<'static>`; derive both with `vitaminc_aead::{Encrypt, Decrypt}`
  (`stack_encrypt::{Encrypt, Decrypt}` re-exports them). The name is the
  same and the trait is not: a hand-written impl of the old one does not
  compile against the new one. `Decipher`, `Element` and `Cipher` are no
  longer re-exported, and `StackDecipher` and `BoxedPassthrough` are gone.
  A pending tree is planned rather than driven:
  `PendingStackCipherText::plan(value, aad)`, then `seal` or
  `into_pending` as before. The key fetch is unchanged: one batched
  `generate_keys` per assembly to seal, one `retrieve_keys` per keyset to
  open.
- **Every leaf records its type, so a Rust field and a data-plan field
  share leaves.** A Rust `u32` and a data plan's `uint32` field seal the
  same leaf under the same context, and each opens the other's; a reader of
  another kind (text for an integer, an integer for bytes) is refused rather
  than handed changed plaintext, as a bare `String` reader used to read a
  binding's leaf as `"\nalice"` (#1118). An integer reader accepts an integer
  leaf of any width whose value fits, and an `f64` reader an `f32` leaf,
  which change no value.
  Leaves are vitaminc's wire version 2, so a ciphertext sealed by an
  earlier build does not open.
- **An absent value is a sealed null leaf**, a `Single` like any other
  value: the absent marker (`CipherText::None`) and
  `transcode::Visitor::absent` are gone.
- **A passthrough travels as its frame.** `StackCipherText` is vitaminc's
  `Node<SealedValue>`: a passthrough subtree is a `PassthroughFrame`, the
  transport frame of its value, in place of a boxed value, and
  `transcode::Visitor::passthrough` takes one.
  A dynamic passthrough value the frame cannot carry is refused when the
  source is read, before any key is requested, as `Error::Source` naming
  the field: a repeated key as `Reason::RepeatedKey`, and a value nested
  deeper, or holding text, bytes or a key longer, than a frame carries as
  the new `Reason::Unframeable` (`"unframeable"`).
- **`dynamic::FfiValue` and `dynamic::ValueKind` are this crate's own**,
  with the same variants and kind names, since vitaminc no longer has a
  value tree. A value crosses a binding's boundary as a transport frame
  (`FfiValue::to_frame`, `FfiValue::from_frame`), and is read through its
  `Decrypt` sink: an 8- or 16-bit integer in a frame reads as the 32-bit
  variant of its sign, and a scalar no variant holds is refused.

- **`StackCipher::query_index` is gone**, with `QueryIndexBuilder` and
  `QueryIndex`. Every query names an operator now that the orderings have
  arrived:
  - `query_index(Ore, &v)` over an integer is `query(op::Lt, &v)` (or any
    ordering; the term is the same `OreTerm`).
  - `query_index(Match, text)` is `query(op::Matches, text)`, which is not
    the same call. It returns a `MatchQuery`, not the stored `MatchTerms`;
    it refuses text that cuts no token (`TermError::EmptyTermText`); and it
    compiles only for a configuration that implements `op::MatchCase`. A
    configuration without one needs that one-line impl to be queried.
  - `query_index(Ore, text)` and `query_index(Ope, text)` have no
    replacement: an ordering over text does not compile until the order of
    text is settled (ADR-0009). A text column can still store ORE and OPE
    terms.
- **`op::Supports`, `op::Answers` and `op::DefaultIndex` are keyed by the
  query's input**, `Supports<Op, In>` with `In: Input<Op::Arity>`, in
  place of the plaintext; for every operator but `Between` the input is
  the plaintext, so `Supports<Eq, S>` reads as before. `Supports::check`
  takes the input and returns `Error`, and `Supports::query` takes the
  input's terms (`In::Terms<Self::Term>`: one term, or a pair for a
  range). `plan::Resolves::resolve` takes the index and the call's context
  and returns the index and the label.
- **The query chain starts with the operator.** `cipher.query(op, v)`
  replaces `cipher.query(v)`: `cipher.query(op::Eq, v).on(&plan)` replaces
  `cipher.query(v).using(&plan).equality()`, and `on` replaces `using` for
  queries only (a write still runs `using` a plan). An index's own term, for
  an index no operator answers yet (`Ore`, `Ope`), is
  `cipher.query_index(Ore, v).on(&plan)`, which goes when the ordering
  operators arrive. `QueryUsing` is gone; the chain's types are `QueryBuilder`, `QueryVia`,
  `QueryIndexBuilder`, `QueryIndex` and `QueryOp`, and the plan shapes
  implement `plan::Chooses` and `plan::Resolves`.
- **`Match::default()` is `Match`.** The match index under the default
  configuration is the value `Match`, and `Default` is now implemented for
  every `Match<O>`, so `Match::default()` no longer infers the configuration.

- **Update pattern matches for `dynamic::Error`.** `Context`, `Plan`,
  `Source`, and `Record` now carry
  `{ field: Option<String>, reason: Reason }`; `Term` also gains
  `field: Option<String>`. For example, replace `Error::Plan` with
  `Error::Plan { .. }`. Messages include the reason and the field when
  known. Extra input fields are reported as `UnknownField` after the
  plan's declared fields are checked, replacing the earlier field-count
  check.
- **Key-management errors pass through directly.** `Error::Kms` now uses
  the underlying `stack_kms::Error` message, code, and help. The
  `ZeroKMS data-key operation failed:` prefix is removed, and `source()`
  returns the underlying error's own cause. ZeroKMS is CipherStash's
  key-management service.
- **Error messages omit potentially sensitive values.**
  `Error::ContextMismatch` reports the stored context's length and number
  of parts instead of its contents. `sem::TermError::Prf` omits the
  underlying pseudorandom-function implementation's message, and
  `sem::TermBytesError::MatchPositionOutOfRange` omits the position read
  from search-index bytes, and `LabelError::Reserved` names the segment
  but not the reserved character, since a `context_field` label is record
  data. These details remain available on the Rust
  error values for callers in the same process, including the `stored`
  field on `ContextMismatch`. A one-value plan's
  `PlanError::DuplicateIndex`, `IndexNotDeclared` and `IndexOptions` name
  `the value` where they used to quote the plan's or the call's context;
  the caller already holds that context.
- **A data plan field with a term output must declare its `"type"`.** A
  plan whose indexed field (`"eq"`, `"match"`, `"ore"`, `"ope"`) has no
  `"type"` is refused when it is built (`Error::UntypedIndex`, naming the
  field), by `record::plan`,
  `record::plan_with`, `Plan::new` / `Plan::new_with` and
  `Plan::with_context_field` alike: the field's
  terms derive from the one declared kind, with every value checked against
  it, never from whatever tag each value arrived with. The type stays
  optional on a field whose only output is `"c"` or `"passthrough"`, and on
  a target field, whose kind is the EQL type's own. The Go SDK already
  fills `"type"` on every field from the Go type, and `record.Plan.Validate`
  refuses an indexed `Untyped` field naming it, so generated code is
  unaffected; a plan written by hand without types must add them. Declaring
  a type changes no stored byte, so a row stored as the declared kind opens
  as before. A row stored as another kind fails to open with
  `PlanError::FieldType`, and fails any batch that holds it; its terms do
  not match a query of the declared kind either. Re-encrypt such rows as
  the declared kind: they are still readable, because a plan that gives the
  field only `"c"` and no `"type"` remains valid and opens a row of any
  kind, whatever indexes it was sealed with. Open the rows under that plan,
  convert each value to the declared kind, and encrypt it again under the
  typed plan.

- **A target description carries a source mode.** `Encryption` gains a
  last type parameter, `M: SourceMode = Borrowed`, saying how it is handed
  its plaintext. Code that names `Encryption<'s, S, T, K, Ctx>` still
  compiles and means the borrowed mode it always ran in.
- `ciphertext`, `equality`, `matching`, `ore` and `ope` gain a source-mode
  type parameter, `M`. A turbofish must name it: `ciphertext::<S, K, M>()`,
  and in `matching` it comes before `O` (`matching::<S, K, M, O>()`). A call
  whose result type does not fix the mode must name it; `Borrowed` is the
  old behaviour. In return `ciphertext`, `equality`, `ore` and `ope` no
  longer ask `S: Clone` themselves: only borrowed mode does.
- `sem::MatchTerm` is renamed `MatchTerms`: a match index produces a set of
  terms, not one. `MatchTerm` remains as a deprecated alias.
- `TermBytesError::OddMatchTermLength` is renamed `OddMatchTermsLength`. An
  enum variant cannot be aliased, so a `match` that names it must change.
- `dynamic::TermKind` is gone; `target::IndexSpec` is the one data form of
  an index. `Output::Term`, `Error::Term`'s `kind`, `Scalar::of` and
  `dynamic::term` take an `IndexSpec` (the last two by reference), and
  `Output` is no longer `Copy`. A plan's wire form is unchanged: a bare
  `"match"` still means the default options.
- **`dynamic::record` is a lowering into the plan builder, not a second
  executor** (ADR-0007). `record::encrypt` and `record::decrypt` are no
  longer `async`: each checks and converts its input with no cipher
  (`Error::Source`, `Error::Term`, `Error::Record`, as before) and returns
  the plan's `Pending`, whose failure is the crate's `Error`; a typed field
  that opens to another kind is now `Error::Plan(PlanError::FieldType)` on
  the await rather than `dynamic::Error::Record`. `dynamic::term` asks
  `K: 'static`. The stored record shape (`"c"` and the term keys per field)
  is unchanged, with one addition below.
- **A data plan field's `"context"` must be the field's label** — a list of
  at least two plain segments (`["users", "age"]`), optionally extended by
  scalar parts nested to the left (`[["users", "age"], 7]`) — and every
  field of one plan must share the label's prefix and the extension, which
  become the plan's one context and its `.extend(..)`. A bare text part
  (`"users/age"`), an integer, bytes or a one-segment label is refused
  (`Error::Plan`): a fields plan cannot seal a field outside the record
  context, and the derive lost that in the same release. Two sealed or
  indexed fields under one label are refused for the same reason the
  builder refuses them (`PlanError::SharedIdentity`). A record a Go program
  wrote with a `label=` tag is unaffected; one written with a `context=`
  tag is not readable through a plan.
- **Every data plan field seals the tagged `FfiValue` leaf, whatever its
  `"type"`**, as every field did before; the type admits indexes and checks
  kinds and changes no bytes, so a row written without a type opens under a
  plan that declares the kind it was sealed as, and a binding that starts
  sending `"type"` re-encrypts nothing stored as that kind. A Rust `u32` or `String` field under the same label
  derives the same terms as the data field but a different leaf, and the
  two leaves cannot be told apart by inspection (a bare string that begins
  with U+000A is a valid tagged string), so the lowering does not choose an
  encoding from the type and a Rust record whose rows a binding must open
  declares `dynamic::Value` fields, which are the same declaration as a data
  plan's. One leaf encoding for both authors, or the encoding bound into
  the leaf's context so the wrong reader fails closed, is a change to the
  Rust chain's bytes, tracked in #1118.
- `dynamic::Output` gains `Passthrough` (the wire key `"passthrough"`). The
  enum is exhaustive on purpose, so a match over it must name the variant.
- `target::DeclaredContext` holds several extension parts: `with(part)`
  appends one, and `under` nests them to the left as `NonEmpty::with` does.
  One part behaves exactly as before.
- **`stack-encrypt-derive`: a field-level `#[stash(context = "..")]` is
  removed on every derive form** (0.2.0 accepted it). On a `plaintext = T`
  record, remove it: all outputs of the record share the caller's context. On
  a field of a `struct = ..` derive, write `#[stash(identity = "..")]`, which
  keys the field under `("<context>", "<identity>")` (`users/nickname`), not
  under the bare literal (`nickname`). Either way the field moves to a
  different context from the one 0.2.0 used: data written by 0.2.0 does not
  decrypt under it (ZeroKMS refuses the key, `Error::Kms`) and its equality,
  match and order terms do not match new query terms, so re-encrypt that
  data. Before the literal went, a non-plain literal such as
  `"readings/unit"` was already refused, for the same reason.
- **`stack-encrypt-derive`: `#[stash(nested)]` is removed** (0.2.0 accepted
  it). Remove it: a record-typed field of a `struct = ..` derive is an
  ordinary field, keyed under `("<context>", "<field>")`, and its inner
  fields sit under that (`("user/age", "accounts/user")` where `nested` gave
  `user/age`). That is a different context from the one 0.2.0 used: data
  written by 0.2.0 does not decrypt under it and its terms do not match, so
  re-encrypt that data.
- **`stack-encrypt-derive`: a plaintext field of a `struct = ..` derive has
  one output.** 0.2.0 accepted several fields `from` one plaintext field
  (`email: StackCipherText` beside `#[stash(from = email)] email_hm:
  EqualityTerm`). Write one field of type `Encrypted<Terms>` instead
  (`email: Encrypted<EqualityTerm>`). Its ciphertext and terms are derived
  under the same context as before (an equality term is the same bytes), so
  stored data still opens and its terms still match; what changes is the
  record's shape, one field where it held two.
- **The plan API listed under Added changes shape before its first
  release** (none of this is in 0.2.0; it matters only to code built
  against the unreleased tree). `Plan::fields()` now starts a fields plan,
  so a built plan's field iterator is `Plan::field_plans()`. A one-value
  plan is `ValuePlan<S, Indexed<X>>` (from `with`) or
  `ValuePlan<S, Typed<T>>` (from `encrypt_into`), in place of
  `ValuePlan<S, X>`. `Plan::label` and `ValuePlan::label` return
  `Option<&Label>` (`None` for a plan whose context comes from the call or
  a context field), as `FieldPlan::label` does. `Runs::pending`,
  `Opens::decryption`, `Plan::encryption`, `Plan::decryption` and
  `ValuePlan::encryption` take the context the call names (an
  `Option<Label>`) beside the extension, and `Runs::check` /
  `Opens::check` take it too. The field verbs take a `FieldRef` (a name or
  a picker) in place of `&str`; a name still works as before.
- **`stack-encrypt-derive`: every field type of a `struct = ..` record
  implements `DecryptField<F, CallerContext>`** for the plaintext field `F`
  it is derived from, even when the record derives `EncryptFrom` alone: the
  record's plan seals and opens each field. 0.2.0 asked only
  `EncryptFrom<F>`. Every target in this crate and every record deriving
  `DecryptInto` qualifies; a borrowed plaintext field (`&'static str`) does
  not, since nothing opens into a `&str`: derive from an owned field.
- **`stack-encrypt-derive`: a record that declares one index twice compiles
  and fails when encrypted**, with `Error::Plan(PlanError::DuplicateIndex)`
  before any key request: two outputs of one index on a `plaintext` record
  (two `EqualityTerm`s), or a field type that declares one twice. 0.2.0 wrote
  the same term twice.

### Added

- **A data plan can take its context from a field of the record**, as a
  Rust chain's `FieldsBuilder::context_field` and the derive's
  `#[stash(context_field)]` do: a plan-level `"context_field": "<name>"`
  key beside the field specs (`dynamic::record::plan`,
  `Plan::with_context_field`). The named field's value in each record (a
  label such as `"tenants/acme"`) is the context every other field is
  sealed under, and the field is carried as a passthrough of type
  `"string"`, so the record stores its own context. Under a context field
  each field's `"context"` is its identity alone, a one-segment label,
  extended as before; without the key the two-segment and shared-prefix
  rules hold and every existing plan seals the same bytes.
  `record::decrypt` and `record::check_record` take the context the caller
  expects (an `Option<Label>`, the chain's `open(record).context(expected)`)
  and refuse a record whose stored context differs with
  `Error::ContextMismatch` before any key is requested. `Plan::label` is
  now an `Option<&Label>` (`None` under a context field) and
  `Plan::context_field` names the field. `dynamic::Value` implements
  `IntoLabel`, and `LabelError` gains `NotText` for a context read from a
  value that is not a string.
- `KeysetCipher::run`: run a description held in a variable over a value,
  under a context, without an `EncryptFrom` declaration.
- `target::{SourceMode, ConsumeSource, ShareSource, Borrowed, Owned}`. In
  `Owned` mode a description is handed the plaintext by value, so a single
  operation consumes it with no copy and a plaintext that is not `Clone`
  (a zeroizing FFI value) can be sealed or indexed. The traits are sealed.
- Indexes as types: `target::{Index, Indexes, Equality, Match, Ore, Ope}`,
  `indexed`, `Encrypted`, `Select` / `At` / `Whole`. A match index on an
  integer does not compile, and an index set is one index or a tuple of two
  to five, never `()`. `Index::spec` lowers an index to its `IndexSpec`.
- `target::passthrough`: a field carried unsealed and unauthenticated.
- `KeysetCipher::run_decryption` and `StackCipher::run_decryption`: run a
  `Decryption` held in a variable.
- A dynamic plan's match index can carry options, as
  `{"match": {"tokenizer", "downcase", "k", "m"}}`.
- A dynamic plan field may be carried through: `"outputs": ["passthrough"]`
  stores the value as it is under the `"passthrough"` key, unsealed and
  unauthenticated, and it comes back from `decrypt`.
- `dynamic::Value`: an `FfiValue` as a plan field's plaintext, `Clone` by
  deep copy into fresh `Protected` payloads, so the borrowed engine can
  consume it. `dynamic::TermBytes`: a term as its frozen bytes.
- `IndexSpec` implements `Index<Value>`, with `TermBytes` as its term, so
  an index named as data runs through `indexed()` like an index named as a
  type, from a data plan or from a Rust chain over `Value` fields. `Vec<I>`
  implements
  `Indexes<S>` for any `I: Index<S>`: an index set sized at run time, whose
  terms are a `Vec`; an empty one is refused when it runs
  (`PlanError::EmptyIndexes`).
- `tests/fixtures/record_lowering.json`: records a Rust chain over `Value`
  fields and the data-plan lowering each sealed under one declaration, with
  their term bytes, under a deterministic key source;
  `tests/record_lowering.rs` opens each with the other. The fixture is the
  proof that the two are one engine (ADR-0007), and a Go test can read it
  later.
- A dynamic plan field may declare its type, as `"type": "<kind>"`. The
  vocabulary is vitaminc's `ValueKind` (re-exported as
  `dynamic::ValueKind`), not a new enum, so this crate now needs vitaminc
  0.5.1. A declared type refuses an index it is not defined for
  (`dynamic::admits`) and a value of another kind, on encrypt and on
  decrypt. `dynamic::read` reads a query value as a kind;
  `FieldPlan::with_type` and `field_type` set and read the declaration.
- The `plan` module, the chained plan builder: `cipher.encrypt(&value)`,
  `cipher.query(&value)` and `cipher.open(record)`, each finished by
  `.await`, with `.keyset(..)` and `.extend(..)` on every chain. A value is
  sealed under a context as one tree (`.context(c)`), with indexes beside
  it (`.with(indexes)`), or field by field (`.fields()` then `encrypt`,
  `encrypt_index`, `index`, `passthrough` and `identity`). Every chain lowers
  to the combinators in `target` and produces the same bytes they do.
- Saved plans: `Plan::context(c).fields()...build()` (a fields plan,
  `Plan<S, K>`) and `Plan::context(c).with(indexes).build()` (a one-value
  plan, `ValuePlan<S, X>`), run with `.using(&plan)` over a value, a slice
  or a `Vec`, queried through `Plan::field(name)` (a `FieldPlan`) or the
  `ValuePlan` itself, and opened with `cipher.open(record).using(&plan)`.
  `FieldValues` is a fields plan's record; `Fields`, `Field` and
  `FieldSchema` describe a value's fields; `FieldKind` says what a field
  does.
- `all((..))`: two to four chains settled in one ZeroKMS request per
  request kind, under one keyset. Chains from different ciphers are
  refused; an opening that names no keyset still reads any keyset.
- `PlanError`, carried in the new `Error::Plan`: every way a plan, or the
  value, record or query it runs with, is refused. A chain is checked
  (`Operation::check`) before it loads a keyset it names.
- A passthrough field's name may be any text: it is under no label, so
  `FieldPlan::label` is `None` for one.
- `IntoLabel` for `&String`, and `KeysetChoice` from a `&String`.
- `target::TermSet`: a term type, or a tuple of two to five, names the
  indexes that derive it (`MatchTerms<O>` names `Match<O>`, options
  included).
- `Encrypted<Terms>` is a target: it implements `EncryptFrom<S>`
  (described as `indexed(Terms::INDEXES)`), `Decryptable` and
  `DecryptField`, so a derived record can hold a ciphertext and its terms
  in one field.
- `stack-encrypt-derive`: `#[stash(identity = "..")]` on a field of a
  `struct = ..` derive keys it under that segment in place of the plaintext
  field's name, the plan builder's `.identity(segment)`.
- Two plan starts, each with an optional `.context(c)`: `Plan::fields()`
  (field by field) and `Plan::value::<S>()` (one value, then `.with(indexes)`
  or `.encrypt_into::<T>()`). `Plan::context(c).fields()` / `.with(..)` keep
  working.
- A plan's context comes from exactly one place: the plan, the call that
  runs it (`cipher.encrypt(&v).context(c).using(&plan)`, and `.context(c)`
  on `cipher.query(..)` and `cipher.open(..)`), or a field of the value
  (`FieldsBuilder::context_field`, carried as a passthrough and checked on
  open against the context the caller expects). Two is
  `PlanError::TwoContextSources`; none is `PlanError::NoContext`, raised
  before any key is requested. `Plan::context_field()` names the field.
- `encrypt_into::<T, _>(field)` on a fields plan, and
  `Plan::value::<S>().encrypt_into::<T>()`: the field or value is laid out by
  the target `T`'s own `EncryptFrom`, under `<context>/<identity>`, and
  answers the queries `T` declares. A field is a target or data verbs, never
  both (`PlanError::TargetWithVerbs`).
  `Plan::value::<S>().encrypt_into::<T>()` builds for a target of any
  context (`plan::ValueLayout`); running it through `.using(..)` or
  `ValuePlan::encryption` asks that a `CallerContext` converts into the
  target's context (`plan::ValueShape`).
- `EncryptFrom::indexes()`: the indexes a target's terms answer, as data
  (empty by default; terms, `Encrypted<Terms>` and tuples name theirs).
- A tuple of two to five targets is a target (`EncryptFrom`, `Decryptable`,
  `DecryptInto`, `DecryptField`): each element derived from the one
  plaintext under one context, opened through the element that holds a
  ciphertext. A tuple of terms alone is no field to open a record through.
- Pickers: every field verb takes a `FieldRef`, a name or a name with an
  accessor (`plan::pick("email", |u: &User| &u.email)`), which reads the
  field directly and needs no `Fields` impl or turbofish.
- `FieldPlan::identity()`; a pinned identity lets a field name that is not a
  plain segment (`"0"`, `"2fa_secret"`) be sealed and queried.
- `PlanError::IndexOptions`: a query asked for an index the field declares
  with other match options.
- **`stack-encrypt-derive`: `#[derive(EncryptFrom)]` emits the record's
  plan**, `Record::plan()`, and its `encryption()` runs it: a `struct = ..`
  record a fields plan of `encrypt_into` fields, a `plaintext = T` record
  `Plan::value::<T>().encrypt_into::<(A, B, ..)>()` over its outputs. The
  bytes are the same as before. `DecryptInto` is unchanged.
- `Plan::value::<S>().context_field::<C>()` (`plan::ContextFieldStart`,
  `plan::Stored`): a one-value plan whose output is `(C, T)`, the call's
  context carried out beside the target, run through
  `ValuePlan::encryption_with_context` and
  `ValuePlan::decryption_with_context` (checked against an
  `ExpectedContext` before any key request). A `Typed` plan gains
  `encryption_with_context::<K, C>()`, run under a context of any type the
  target accepts.
- `target::JoinContext` (sealed): the context a tuple of targets takes,
  the one every element accepts. A tuple of ciphertexts takes an
  `AeadContext`; a ciphertext beside a term takes a `CallerContext`.

## [0.2.0] - 2026-10-04

### Breaking

- **A column has one encryption context, and its ZeroKMS descriptor renders
  `users/email`.** `Descriptor::SEPARATOR` is `/` (was `|`); a text part that
  contains `/` is escaped with URL-safe base64 (the standard alphabet contains
  `/`). A data key minted through 0.1.0 was bound to the old rendering of the
  same context and cannot be retrieved under this one. 0.1.0 had one known
  consumer, aware of this; see ADR-0006.
- `#[derive(EncryptFrom)]` with `struct = User, context = "users"` binds each
  field under the pair `("users", "<field>")`, the same context EQL's
  `Identifier` is. A `#[stash(context = "…")]` literal on a field stays one
  text part, exactly as written.
- `Encryption::under` / `extend` and the context types accept any
  `NonEmpty<impl IntoContext>` as the own context, not only a static string.

### Added

- `Describe` and `Description`: a value whose parts are the descriptor of
  the data it keys. `to_context` is what the type's `IntoContext` returns, so
  the AAD and the ZeroKMS descriptor are one tree seen two ways. EQL's
  `Identifier` (table, column) implements it in `eql-bindings`.
- `Label` and `LabelError`: a path of plain segments written and read as
  `users/email`, for direct consumers. One segment is the same context as the
  bare literal; two are the pair a `struct = ..` derive binds.

## [0.1.0] - 2026-10-04

The first crates.io release. Everything below was in it; the heading was
added after the fact — this section said "Unreleased" when 0.1.0 shipped.

### Breaking

- **Sealed leaves gained a version byte, and the leaf AAD that binds it.**
  Leaves sealed before this change used an unlabelled `PAE(aad, tag)` leaf
  AAD with no version byte; the derivation is now
  `PAE("stack-encrypt/leaf", version, derived_aad, tag)`. Leaves sealed under
  the old derivation cannot be opened by this build — however they were
  persisted (`serde`, `into_parts`, or raw bytes) they fail AEAD verification
  with a plain authentication error, indistinguishable from tampering,
  because the old form carries no version byte to raise
  `LeafBytesError::UnknownVersion` against. Acceptable only because the crate
  is `publish = false` and only dev-persisted data exists; from
  `SealedValue::FORMAT_VERSION` onwards a format move is signalled by the
  version byte instead.

### Added

- `SealedValue::to_bytes` / `from_bytes` / `TryFrom<&[u8]>`: the canonical,
  frozen v1 leaf encoding
  (`version ‖ iv ‖ u16 tag_len ‖ tag ‖ local_ciphertext`), with
  `LeafBytesError` for structural decode failures.
- Frozen transport encodings for every index term (`EqualityTerm`,
  `MatchTerm`, `OreTerm`, `OpeTerm`) with `TermBytesError` for decode
  failures, plus golden vectors in `tests/frozen_bytes.rs`.

### Changed

- `TermError`, `TermBytesError` and `LeafBytesError` are `#[non_exhaustive]`,
  so the versioned decoders can gain variants without a source break.
