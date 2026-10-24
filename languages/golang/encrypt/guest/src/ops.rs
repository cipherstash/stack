//! The guest's operations, written against `StackCipher<K>` / `KeysetCipher<K>` for any
//! [`DataKeySource`] so they compile — and their tests run — on the native
//! host target with `FakeDataKeySource`. The wasm32-only [`crate::abi`]
//! module wires them to the session table and the packed ABI; nothing in
//! here knows about linear memory.
//!
//! Values cross the boundary as vitaminc transport frames, and ciphertext
//! trees in vitaminc's ciphertext codec (`vitaminc_aead_frame`) — the same
//! encodings the vitaminc guest uses, so the Go side carries exactly one
//! codec. A ciphertext tree's
//! leaves are re-encoded through [`SealedValue::to_bytes`] /
//! [`SealedValue::from_bytes`]: the codec sees an opaque byte-string leaf,
//! and the bytes inside it are the frozen storage encoding a database column
//! holds — a leaf lifted out of a tree here can be written to Postgres
//! as-is, and vice versa.
//!
//! # Errors
//!
//! Every function reports a [`crate::status`] code, never a message: these
//! are attacker-reachable decode/decrypt paths, and the status codes leak
//! only the failure class (see `status.rs`).
//!
//! There is no whole-value encrypt or decrypt here. Every value the Go SDK
//! seals goes through a declaration (ADR-0007, amended): an opaque struct
//! is a one-field record, so the record path is the one path.
//!
//! # What is here, and what is not
//!
//! The operations themselves live in [`stack_encrypt::dynamic`]: reading a
//! context out of a value, dispatching an index term on a value's variant,
//! and driving a record plan. That is shared with every other language
//! binding, because none of it is specific to Go or to wasm.
//!
//! What is left here is what genuinely is this guest's: the codec both
//! directions, buffers sized before a byte of plaintext is written, the
//! ABI's numeric term kinds, and the mapping from a library error to a
//! status code.
//!
//! Plaintext is never decoded into a value tree. A term's value is parsed and
//! walked in place to the scalar it holds, the way vitaminc's own guest walks
//! a frame into encryption. A record's source, a query's input and a page of
//! values to verify are read as [`ValueFrame`]s: the frame is checked against
//! the engine's value model, and the engine walks it, splitting a source into
//! one frame per field as it goes. A record opens into one frame, which is
//! the output. Control data (a plan, a context, an options object, query
//! statistics) carries no secret and is read from its frame with serde.

use stack_encrypt::dynamic::frame::{decode_ciphertext, encode_ciphertext, Frame};
use stack_encrypt::dynamic::{self, Scope, ValueFrame};
use stack_encrypt::sem::MatchOptions;
use stack_encrypt::target::IndexSpec;
use stack_encrypt::ErrorPayload;
use stack_encrypt::{CipherText, KeysetCipher, Label, Node, SealedValue, StackCipherText};
use stack_kms::DataKeySource;
use zeroize::Zeroizing;

use stack_guest_abi::last_error;

use crate::status::{fail_dynamic, fail_error, STATUS_ENCODING, STATUS_INTERNAL};
use crate::targets::resolver;

/// Term kinds for `se_term`, part of the guest/host contract (the Go host
/// mirrors these values).
pub const TERM_EQUALITY: u32 = 1;
/// See [`TERM_EQUALITY`].
pub const TERM_MATCH: u32 = 2;
/// See [`TERM_EQUALITY`].
pub const TERM_ORE: u32 = 3;
/// See [`TERM_EQUALITY`].
pub const TERM_OPE: u32 = 4;

/// A ciphertext tree whose leaves are the frozen [`SealedValue`] byte
/// encoding — the shape that crosses the FFI codec.
type BytesTree = Node<Vec<u8>>;

// =============================================================================
// Terms
// =============================================================================

/// Derive one index term: a codec-encoded scalar and a codec-encoded
/// context in, the term's frozen byte encoding out (see `stack-encrypt`'s
/// `sem` module docs). The scalar's frame is walked in place. Under the local HMAC backend the derivation is one
/// PRF/CLLW computation with no ZeroKMS I/O; that is the backend's
/// property, not this operation's contract — the term API is a `Pending`
/// so a backend that derives terms at ZeroKMS settles the same way.
///
/// The context is one part — a string, bytes, or an `i32`/`i64`/`u32`/`u64`
/// — or an array of parts, nested as deep as the transport codec allows
/// ([`MAX_DEPTH`](stack_encrypt::dynamic::frame::MAX_DEPTH) levels from the root of the frame; deeper
/// is [`STATUS_ENCODING`] before the context is read), exactly as a plan
/// field's; [`dynamic::context`] is the one home of that grammar. Shape is identity:
/// `[x]` is a PAE-framed list and `x` is not, so a probe takes the context
/// in the shape the field was sealed under — a plan field's context
/// verbatim, a bare part for a Rust leaf sealed under that part, and the
/// same parts as a (left-nested) list for a Rust row sealed under an
/// extended context.
pub async fn term<K>(
    cipher: &KeysetCipher<'_, K>,
    value: &[u8],
    context: &[u8],
    kind: u32,
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync + 'static,
{
    // The same proof every stack-encrypt leaf demands: an empty context is
    // `STATUS_ENCODING` here, before any derivation.
    let context = parse_context(context)?;
    let value = parse_frame(value)?;
    let kind = parse_term(value, kind)?;
    dynamic::term(cipher, value, &kind, context)
        .await
        .map_err(|e| fail_dynamic(&e))
}

/// A term's context: one frame, read by [`dynamic::context`]. Bytes that
/// are not a frame are refused as every other input's are, before the
/// context's own grammar.
fn parse_context(
    context: &[u8],
) -> Result<stack_encrypt::NonEmpty<stack_encrypt::ContextPiece<'static>>, u32> {
    let _ = parse_frame(context)?;
    dynamic::context(context).map_err(|e| fail_dynamic(&e))
}

/// The static half of a term: the kind is one of the ABI's table, and the
/// value is one scalar the index takes ([`IndexSpec::defines`]). Shared by
/// [`term`] and [`validate::term`] so the ABI refuses exactly what the
/// operation would, before any keyset is resolved.
///
/// The ABI's kind codes carry no options, so [`TERM_MATCH`] is the match
/// index under the default options, the same index a plan's bare `"match"`
/// names.
fn parse_term(value: Frame<'_>, kind: u32) -> Result<IndexSpec, u32> {
    let kind = match kind {
        TERM_EQUALITY => IndexSpec::Equality,
        TERM_MATCH => IndexSpec::Match(MatchOptions::default()),
        TERM_ORE => IndexSpec::Ore,
        TERM_OPE => IndexSpec::Ope,
        _ => {
            return Err(last_error::malformed(
                "the term kind is not one of the four",
            ))
        }
    };
    if !kind.defines(value) {
        return Err(fail_dynamic(&dynamic::Error::Term { field: None, kind }));
    }
    Ok(kind)
}

// =============================================================================
// Records
// =============================================================================

/// Encrypt a record — or a batch of records — per a plan.
///
/// Both arguments are codec-encoded: the plan is the object
/// [`dynamic::record::plan`] parses, the source an object of
/// `{ field: value }` (one record) or an array of them (a batch). The
/// result is a codec-encoded ciphertext tree — per record a map of
/// `field → { output-key → node }`.
///
/// The plan is lowered into the engine's plan builder and run there
/// (ADR-0007): [`dynamic::record::encrypt`] hands back the plan's `Pending`
/// with every key request queued and nothing sent, and awaiting it here is
/// the one batched `generate_keys` for all rows and fields. That batch
/// reaches ZeroKMS as one request per
/// [`ClientOpts::max_keys_per_req`](stack_kms::ClientOpts::with_max_keys_per_req)
/// keyed leaves (500 by default, sent sequentially: the guest pins
/// `max_concurrent_reqs` to 1), so "one call" is exact up to 500 leaves and
/// "one call per 500" past it. Everything else about the shape — the plan
/// grammar, the one-context rule, why terms ride as passthrough — is
/// [`dynamic::record`]'s to state.
pub async fn encrypt_record<K>(
    cipher: &KeysetCipher<'_, K>,
    source: &[u8],
    plan: &[u8],
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync + 'static,
{
    let plan = parse_plan(plan)?;
    let tree =
        dynamic::record::encrypt_with(cipher, checked_plaintext(source)?, &plan, &resolver())
            .map_err(|e| fail_dynamic(&e))?
            .await
            .map_err(|e| fail_error(&e))?;
    encode_tree(tree)
}

/// Decrypt a record — or a batch — produced by [`encrypt_record`] under the
/// same plan. Only the `"c"` and `"passthrough"` outputs participate (terms
/// are one-way).
///
/// `expected` is the context the host expects each record's context field
/// to hold, from the options object's `context` key (see
/// [`crate::options`]), for a plan that takes its context from a field; a
/// record whose stored context differs is
/// [`STATUS_CONTEXT_MISMATCH`](crate::status::STATUS_CONTEXT_MISMATCH)
/// before any key is retrieved. `None` opens each record under the
/// context it stores.
///
/// The plan's opener runs in the engine; awaiting it here is the one
/// batched `retrieve_keys` per invocation, dispatched as one ZeroKMS call
/// per 500 keyed leaves and, under [`Scope::Client`], per keyset the leaves
/// were sealed under. The output buffer contains plaintext — the ABI layer's
/// ownership rules govern its wiping.
pub async fn decrypt_record<K>(
    scope: Scope<'_, K>,
    record: &[u8],
    plan: &[u8],
    expected: Option<Label>,
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync + 'static,
{
    let plan = parse_plan(plan)?;
    let value =
        dynamic::record::decrypt_with(scope, decode_tree(record)?, &plan, expected, &resolver())
            .map_err(|e| fail_dynamic(&e))?
            .await
            .map_err(|e| fail_error(&e))?;
    encode_frame(value)
}

// =============================================================================
// Queries by operator
// =============================================================================

/// Derive the query term for one plan field, an operator and its input
/// (ADR-0009; ADR-0007, amended 2026-10-16): a codec-encoded input, the
/// codec-encoded plan, the field's name and the operator's name (both UTF-8)
/// in, the term's codec-encoded object out (the `Serialize` form of
/// [`dynamic::QueryTerm`]):
///
/// ```text
/// { "operator": "matches", "fidelity": "probabilistic", "index": "match",
///   "domain": null, "term": <bytes> }
/// ```
///
/// The input is one value for every operator but `between`, whose input is
/// a list of two, low then high. It is read as the field's declared kind
/// first, so a host's float `34.0` queries a `uint64` field. A field with
/// indexes derives the term of the index that answers the operator, as
/// bytes; `between` derives one per bound, as a list of two. A field that
/// names an EQL type runs the type's query twin through this build's
/// resolver, and `term` holds the twin's JSON bytes and `domain` its
/// PostgreSQL domain. No data key is minted.
pub async fn query_term<K>(
    cipher: &KeysetCipher<'_, K>,
    input: &[u8],
    plan: &[u8],
    field: &[u8],
    operator: &[u8],
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync + 'static,
{
    let (plan, field, operator) = parse_query(plan, field, operator)?;
    let term = dynamic::query_term(
        cipher,
        &plan,
        field,
        operator,
        checked_plaintext(input)?,
        &resolver(),
    )
    .map_err(|e| fail_dynamic(&e))?
    .await
    .map_err(|e| fail_error(&e))?;
    encode_answer(&term)
}

/// Verify a page of decrypted values against a probabilistic query: the
/// query's codec-encoded input and a codec-encoded list of values, with the
/// plan, the field's name and the operator's name, in; a codec-encoded list
/// of booleans out, one per value in order ([`dynamic::verify`]). The query
/// is named as it was derived, and its tokens are cut again from the input:
/// they are plaintext, so no term carries them. A null value is `false`.
/// Needs no cipher and no key.
pub fn verify(
    input: &[u8],
    values: &[u8],
    plan: &[u8],
    field: &[u8],
    operator: &[u8],
) -> Result<Vec<u8>, u32> {
    let (plan, field, operator) = parse_query(plan, field, operator)?;
    // Each value becomes a frame of its own (wiped on drop): vitaminc's
    // `Frame` walks a sequence but does not hand out its elements' frames,
    // and reading them out of the frame layout here would duplicate
    // vitaminc's parser.
    let values = decode_plaintext(values)?
        .elements()
        .ok_or_else(|| last_error::malformed("the values to verify are not a list"))?;
    let verified = dynamic::verify(
        &plan,
        field,
        operator,
        checked_plaintext(input)?,
        values,
        &resolver(),
    )
    .map_err(|e| fail_dynamic(&e))?;
    encode_answer(&verified)
}

/// How many rows a probabilistic query should fetch for `want` of them to
/// verify: the term's bytes as [`query_term`] returned them (not a frame),
/// the codec-encoded statistics
/// ([`Stats::from_frame`](stack_encrypt::op::Stats::from_frame)), the plan,
/// the field's name and the operator's name in; the codec-encoded limit out,
/// an unsigned 64-bit integer or null for no finite fetch
/// ([`Limit::rows`](stack_encrypt::op::Limit::rows)). Needs no cipher and
/// no key.
pub fn target_limit(
    term: &[u8],
    stats: &[u8],
    plan: &[u8],
    field: &[u8],
    operator: &[u8],
    want: u64,
) -> Result<Vec<u8>, u32> {
    let (plan, field, operator) = parse_query(plan, field, operator)?;
    // Statistics are read without a field to hand; the error names the
    // query's, as every other refusal of a query does.
    let stats = stack_encrypt::op::Stats::from_frame(stats)
        .map_err(|e| fail_dynamic(&e.in_field(field)))?;
    let limit = dynamic::target_limit(&plan, field, operator, term, want, &stats, &resolver())
        .map_err(|e| fail_dynamic(&e))?;
    encode_answer(&limit.rows())
}

/// The plan, field name and operator a query names: the plan parsed against
/// this build's resolver, the field's name UTF-8, and the operator one the
/// engine knows ([`dynamic::OpSpec::parse`]); an unknown operator is
/// refused naming the field, as an operator the field does not answer is.
fn parse_query<'f>(
    plan: &[u8],
    field: &'f [u8],
    operator: &[u8],
) -> Result<(dynamic::record::Plan, &'f str, dynamic::OpSpec), u32> {
    let plan = parse_plan(plan)?;
    let field = std::str::from_utf8(field)
        .map_err(|_| last_error::malformed("the field name is not UTF-8"))?;
    let operator = std::str::from_utf8(operator)
        .ok()
        .and_then(dynamic::OpSpec::parse)
        .ok_or_else(|| {
            fail_dynamic(&dynamic::Error::Source {
                field: Some(field.to_owned()),
                reason: dynamic::Reason::UnknownOperator,
            })
        })?;
    Ok((plan, field, operator))
}

/// A plan's frame, parsed against this build's resolver: a target name this
/// build cannot run is refused here, the same way at every export that
/// takes a plan. Bytes that are not a frame are refused as every other
/// input's are, before the plan's own grammar.
fn parse_plan(plan: &[u8]) -> Result<dynamic::record::Plan, u32> {
    let _ = parse_frame(plan)?;
    dynamic::record::plan_with(plan, &resolver()).map_err(|e| fail_dynamic(&e))
}

// =============================================================================
// The generator's questions
// =============================================================================

/// Check a codec-encoded plan without a cipher: everything
/// [`dynamic::record::plan`] refuses — a malformed object, an unknown output,
/// a type that does not admit one of its indexes, a context that is not a
/// label of two or more segments, two fields under one identity — is
/// [`STATUS_ENCODING`]. The Go generator (`stashgen`) asks this for every
/// declaration it writes, so it holds no copy of the engine's rules; it
/// asks one field at a time to name the field that failed.
pub fn plan_check(plan: &[u8]) -> Result<(), u32> {
    parse_plan(plan).map(drop)
}

/// The EQL types this build of the engine knows, as a codec-encoded
/// `{"targets": [...]}`: one entry per type in
/// [`TargetDescriptor`](stack_encrypt::dynamic::TargetDescriptor)'s
/// `Serialize` form, producible or not, with the reason when not. The build
/// without EQL types lists none, which a generator reads as "no
/// `encrypt_into` type is available" and refuses the tag; the `eql` build
/// lists the catalog, and a generator writes `encrypt_into` only for an
/// entry whose `producible` is true.
///
/// **Each entry is wire format**, the serialisation of eql-bindings' target
/// record, and the Go reader (`encrypt.parseTargets`) refuses an entry with
/// any other key or a value of another type:
///
/// | key                | type              | meaning |
/// |--------------------|-------------------|---------|
/// | `name`             | string            | the Go type name and the `encrypt_into` value: `TextEq` |
/// | `family`           | string            | `Text`, `Integer`, … |
/// | `suffix`           | string            | `Eq`, `Ord`, `Match`, … or `""` |
/// | `plaintext`        | string or null    | the vitaminc `ValueKind` name the type seals: `"string"` |
/// | `sql_domain`       | string            | the Postgres domain of the stored value |
/// | `indexes`          | list of string    | `eq`, `match`, `ore`, `ope`, `json` |
/// | `query`            | string or null    | the Go type name of the query value: `TextEqQuery` |
/// | `query_sql_domain` | string or null    | the Postgres domain of the query value |
/// | `producible`       | bool              | whether this build produces the type |
/// | `reason`           | string or null    | why not, when `producible` is false |
/// | `operators`        | list of objects   | the operators the engine answers for the type, each `{"operator", "fidelity", "arity", "index"}` ([`TargetDescriptor`](stack_encrypt::dynamic::TargetDescriptor#wire-format)) |
///
/// The first ten keys are eql-bindings' row; `operators` is the engine's,
/// computed from the row, so a generator asks the engine which operators a
/// type answers and how far each answer can be trusted.
pub fn targets() -> Result<Vec<u8>, u32> {
    use stack_encrypt::dynamic::TargetResolver as _;
    #[derive(serde::Serialize)]
    struct Targets {
        targets: Vec<dynamic::TargetDescriptor>,
    }
    encode_answer(&Targets {
        targets: resolver().targets(),
    })
}

/// The operators one field of a codec-encoded plan answers, as a
/// codec-encoded list: one object per operator, in the order the engine
/// lists them, each the `Serialize` form of a
/// [`dynamic::OperatorEntry`]:
///
/// ```text
/// [ { "operator": "eq", "fidelity": "exact", "arity": "one", "index": "eq" }, ... ]
/// ```
///
/// Exactly the operators [`query_term`] derives a term for on that field
/// ([`dynamic::field_operators`]): the operators a field declared with
/// indexes answers, and those its EQL type answers for a field that names
/// one. The Go generator (`stashgen`) asks this for every sealed field it
/// writes and generates one query method per entry, so it holds no copy of
/// which index answers which operator. A field the plan does not have is
/// [`STATUS_ENCODING`]. Needs no cipher.
pub fn operators(plan: &[u8], field: &[u8]) -> Result<Vec<u8>, u32> {
    let plan = parse_plan(plan)?;
    let field = std::str::from_utf8(field)
        .map_err(|_| last_error::malformed("the field name is not UTF-8"))?;
    let operators =
        dynamic::field_operators(&plan, field, &resolver()).map_err(|e| fail_dynamic(&e))?;
    encode_answer(
        &operators
            .iter()
            .map(|(operator, index)| dynamic::OperatorEntry::new(*operator, index))
            .collect::<Vec<_>>(),
    )
}

// =============================================================================
// Boundary validation
// =============================================================================

/// The static checks the ABI runs on every operation input *before* it
/// consults the cipher, so a malformed call is [`STATUS_ENCODING`] whether
/// or not the instance is initialised, and never costs a keyset load. Each
/// runs the same parser the operation itself runs — `parse_term`,
/// [`dynamic::record::check_source`], [`dynamic::record::check_record`] —
/// so the two cannot disagree on what is malformed; the second pass is
/// cheap next to the AEAD and buys a stable status precedence.
pub mod validate {
    use super::*;

    /// A term's inputs, as [`term`] takes them: the context decodes and is
    /// non-empty, the kind is one of [`TERM_EQUALITY`] .. [`TERM_OPE`], and
    /// the value is one scalar the index takes ([`IndexSpec::defines`]).
    pub fn term(value: &[u8], context: &[u8], kind: u32) -> Result<(), u32> {
        let _ = parse_context(context)?;
        parse_term(parse_frame(value)?, kind).map(drop)
    }

    /// A record source against its plan, as [`encrypt_record`] takes them:
    /// the plan decodes and parses (every field's context non-empty, every
    /// output known), and the source fits it (shape, field set, each value
    /// against its field's outputs).
    pub fn record(source: &[u8], plan: &[u8]) -> Result<(), u32> {
        let plan = parse_plan(plan)?;
        dynamic::record::check_source(checked_plaintext(source)?, &plan)
            .map_err(|e| fail_dynamic(&e))
    }

    /// A query's inputs, as [`query_term`](super::query_term) takes them:
    /// the plan parses, the field is one of its fields, the operator is one
    /// the engine knows and the field answers, and the input reads as the
    /// field's kind and passes the refusals the typed path makes before a
    /// term exists ([`dynamic::check_query`]).
    pub fn query_term(input: &[u8], plan: &[u8], field: &[u8], operator: &[u8]) -> Result<(), u32> {
        let (plan, field, operator) = parse_query(plan, field, operator)?;
        dynamic::check_query(
            &plan,
            field,
            operator,
            checked_plaintext(input)?,
            &resolver(),
        )
        .map_err(|e| fail_dynamic(&e))
    }

    /// A record tree against its plan, as [`decrypt_record`] takes them:
    /// the plan parses, the tree decodes with well-formed leaves, every
    /// ciphertext-bearing field has a `"c"` node that is not a passthrough,
    /// and a stored context field is the `expected` one, when the host
    /// names one.
    pub fn record_tree(record: &[u8], plan: &[u8], expected: Option<&Label>) -> Result<(), u32> {
        let plan = parse_plan(plan)?;
        dynamic::record::check_record(decode_tree(record)?, &plan, expected)
            .map_err(|e| fail_dynamic(&e))
    }
}

// =============================================================================
// Codec glue
// =============================================================================

/// Plaintext from a frame: checked against the engine's value model and
/// held as the frame, in a buffer wiped when it drops. The same frames are
/// refused as control data's, so a malformed input fails the same way on
/// every path.
fn decode_plaintext(bytes: &[u8]) -> Result<ValueFrame, u32> {
    ValueFrame::from_bytes(bytes).map_err(|_| not_a_frame())
}

/// Plaintext checked as [`decode_plaintext`] checks it, and walked in place
/// from the host's buffer: for a source or an input that is walked once,
/// where a frame of its own would be one more copy of the plaintext. The
/// record split copies each field into its own wiped frame, and a query's
/// input is read straight into its term.
fn checked_plaintext(bytes: &[u8]) -> Result<Frame<'_>, u32> {
    ValueFrame::check(bytes).map_err(|_| not_a_frame())
}

/// An opened value as the output buffer: its frame, copied into a buffer
/// whose capacity is exactly its length (see [`encode_tree`]); the frame
/// is wiped when it drops.
fn encode_frame(frame: ValueFrame) -> Result<Vec<u8>, u32> {
    let mut out = exact_buffer(Some(frame.risky_ref().len()))?;
    out.extend_from_slice(frame.risky_ref());
    Ok(out)
}

/// One frame, parsed and checked but not decoded: what a term's value is
/// walked from, in place.
fn parse_frame(bytes: &[u8]) -> Result<Frame<'_>, u32> {
    Frame::parse(bytes).map_err(|_| not_a_frame())
}

fn not_a_frame() -> u32 {
    last_error::malformed("an input is not a value in the transport frame")
}

/// One of the engine's answers (a query term, a page of verdicts, a limit, a
/// catalog), written to its frame by serde, in a buffer whose capacity is
/// exactly its length. An answer is not plaintext, but the registry's
/// `into_boxed_slice` would reallocate a buffer with spare capacity, so it
/// is sized as every other output is. A query term's search tokens are
/// derived from plaintext, so the staging buffer is wiped once copied.
fn encode_answer<T: serde::Serialize>(answer: &T) -> Result<Vec<u8>, u32> {
    let frame = Zeroizing::new(
        stack_encrypt::dynamic::frame::serde::to_vec(answer).map_err(|_| STATUS_ENCODING)?,
    );
    let mut out = exact_buffer(Some(frame.len()))?;
    out.extend_from_slice(&frame);
    Ok(out)
}

fn decode_tree(bytes: &[u8]) -> Result<StackCipherText, u32> {
    let tree: BytesTree = decode_ciphertext(bytes).map_err(|_| {
        last_error::malformed("the record is not a ciphertext tree in the transport codec")
    })?;
    // Structural only — a decoded leaf proves nothing until its AEAD opens
    // (see the `SealedValue` docs).
    map_leaves(tree, &mut |l: Vec<u8>| {
        SealedValue::from_bytes(&l)
            .map_err(|e| last_error::record(&e, e.payload(), STATUS_ENCODING))
    })
}

/// The encode twin of [`decode_tree`]. Passthrough nodes can carry caller
/// plaintext, so this is sized up front: the registry wipes only the buffer
/// it holds, and `register`'s `into_boxed_slice` reallocates a `Vec` whose
/// capacity exceeds its length, leaving the old allocation unwiped.
fn encode_tree(tree: StackCipherText) -> Result<Vec<u8>, u32> {
    let tree = map_leaves(tree, &mut |l: SealedValue| Ok::<_, u32>(l.to_bytes()))?;
    let mut out = exact_buffer(tree_encoded_len(&tree))?;
    encode_ciphertext(&tree, &mut out).map_err(|_| STATUS_ENCODING)?;
    Ok(out)
}

/// Rebuild a ciphertext tree with every leaf run through `leaf`, keeping the
/// structure (and the passthrough frames) untouched. One definition for
/// both directions of the frozen [`SealedValue`] leaf encoding.
fn map_leaves<A, B, E>(
    tree: Node<A>,
    leaf: &mut impl FnMut(A) -> Result<B, E>,
) -> Result<Node<B>, E> {
    Ok(match tree {
        CipherText::Single(l) => CipherText::Single(leaf(l)?),
        CipherText::EmptySequence(l) => CipherText::EmptySequence(leaf(l)?),
        CipherText::EmptyMap(l) => CipherText::EmptyMap(leaf(l)?),
        CipherText::Sequence(items) => CipherText::Sequence(
            items
                .into_iter()
                .map(|item| map_leaves(item, leaf))
                .collect::<Result<_, E>>()?,
        ),
        CipherText::Map(entries) => CipherText::Map(
            entries
                .into_iter()
                .map(|(k, v)| Ok((k, map_leaves(v, leaf)?)))
                .collect::<Result<_, E>>()?,
        ),
        CipherText::Passthrough(p) => CipherText::Passthrough(p),
    })
}

/// A buffer with exactly `len` bytes of capacity, or [`STATUS_ENCODING`] if
/// the length could not be computed (an encoding the codec would refuse
/// anyway) or [`STATUS_INTERNAL`] if the allocation failed. `try_reserve_exact`
/// rather than `reserve`: on wasm32 an oversized request must be a status,
/// not an abort that poisons the instance — and the *exact* variant so that
/// `register`'s `into_boxed_slice` finds capacity already equal to length
/// and does not shrink-to-fit (a shrink that moved would free the filled
/// block without wiping it, which is the whole hazard this avoids).
fn exact_buffer(len: Option<usize>) -> Result<Vec<u8>, u32> {
    let len = len.ok_or(STATUS_ENCODING)?;
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| STATUS_INTERNAL)?;
    Ok(out)
}

/// Exact byte length of the codec's encoding of a ciphertext tree. A
/// passthrough is its node byte and its frame, written as it is.
fn tree_encoded_len(tree: &BytesTree) -> Option<usize> {
    let framed = |len: usize| u32::try_from(len).ok().and_then(|_| len.checked_add(5));
    match tree {
        CipherText::Single(l) | CipherText::EmptySequence(l) | CipherText::EmptyMap(l) => {
            framed(l.len())
        }
        CipherText::Sequence(items) => items
            .iter()
            .try_fold(5usize, |acc, item| acc.checked_add(tree_encoded_len(item)?)),
        CipherText::Map(entries) => entries.iter().try_fold(5usize, |acc, (key, value)| {
            acc.checked_add(framed(key.len())?.checked_sub(1)?)?
                .checked_add(tree_encoded_len(value)?)
        }),
        CipherText::Passthrough(p) => p.0.len().checked_add(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::Tree;
    use stack_encrypt::Controlled;

    // `tree_encoded_len` re-derives the codec's arithmetic; the codec exports
    // no `encoded_len` of its own, so this pin is the only thing that fails if
    // the two drift. Drift is not a cosmetic bug: an undersized reservation
    // makes `encode_tree` reallocate mid-encode, leaving unwiped partial
    // plaintext in the abandoned allocation — silently.

    /// The registry wipes the buffer it is handed, and `into_boxed_slice`
    /// reallocates one whose capacity exceeds its length. So every answer's
    /// capacity is its length.
    #[test]
    fn an_encoded_answer_has_no_spare_capacity() {
        let entries = [
            dynamic::OperatorEntry::new(dynamic::OpSpec::Eq, &IndexSpec::Equality),
            dynamic::OperatorEntry::new(dynamic::OpSpec::Between, &IndexSpec::Ope),
        ];
        for out in [
            encode_answer(&vec![true, false, true]),
            encode_answer(&Some(11u64)),
            encode_answer(&None::<u64>),
            encode_answer(&entries),
        ] {
            let out = out.expect("encodes");
            assert_eq!(out.capacity(), out.len());
        }
    }

    #[test]
    fn tree_encoded_len_matches_the_codec_exactly() {
        let leaf = |bytes: &[u8]| -> BytesTree { CipherText::Single(bytes.to_vec()) };
        let trees: Vec<BytesTree> = vec![
            leaf(b""),
            leaf(&[7u8; 40]),
            CipherText::EmptySequence(vec![3]),
            CipherText::EmptyMap(Vec::new()),
            CipherText::Sequence(vec![leaf(b"a"), CipherText::EmptyMap(vec![9])]),
            CipherText::Map(vec![
                ("name".to_string(), leaf(b"ct")),
                (
                    "inner".to_string(),
                    CipherText::Map(vec![("x".to_string(), leaf(b"y"))]),
                ),
            ]),
            CipherText::Passthrough(stack_encrypt::PassthroughFrame(
                Tree::Bytes(vec![1, 2, 3])
                    .to_frame()
                    .expect("a frame")
                    .risky_unwrap(),
            )),
        ];
        for (i, tree) in trees.into_iter().enumerate() {
            let expected = tree_encoded_len(&tree).expect("encodable shape");
            let mut out = Vec::new();
            encode_ciphertext(&tree, &mut out).expect("codec encode");
            assert_eq!(out.len(), expected, "tree {i}");
        }
    }

    // ---- the EQL target path, native, over FakeDataKeySource -----------------

    fn encoded(value: Tree) -> Vec<u8> {
        value.to_frame().expect("encode").risky_unwrap()
    }

    fn text(value: &str) -> Tree {
        Tree::String(value.into())
    }

    fn object(entries: Vec<(&str, Tree)>) -> Tree {
        Tree::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    /// `email` named as a `TextEq` target under users/email, beside a
    /// sealed `notes`.
    fn target_plan() -> Vec<u8> {
        encoded(object(vec![
            (
                "email",
                object(vec![
                    ("context", Tree::Array(vec![text("users"), text("email")])),
                    ("target", text("TextEq")),
                    ("type", text("string")),
                ]),
            ),
            (
                "notes",
                object(vec![
                    ("context", Tree::Array(vec![text("users"), text("notes")])),
                    ("outputs", Tree::Array(vec![text("c")])),
                    ("type", text("string")),
                ]),
            ),
        ]))
    }

    #[test]
    fn targets_lists_what_this_build_holds_in_the_wire_shape() {
        let out = targets().expect("encodes");
        let Tree::Object(entries) = Tree::from_frame(&out).expect("decodes") else {
            panic!("an object");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "targets");
        let Tree::Array(items) = &entries[0].1 else {
            panic!("a list");
        };
        if !crate::targets::HOLDS_EQL {
            assert!(items.is_empty(), "the build without EQL types lists none");
            return;
        }
        let Tree::Object(text_eq) = items
            .iter()
            .find(|item| {
                matches!(item, Tree::Object(fields) if fields.iter().any(|(k, v)| k == "name" && matches!(v, Tree::String(s) if s.as_bytes() == b"TextEq")))
            })
            .expect("TextEq is listed")
        else {
            panic!("an object")
        };
        let keys: Vec<&str> = text_eq.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            [
                "name",
                "family",
                "suffix",
                "plaintext",
                "sql_domain",
                "indexes",
                "query",
                "query_sql_domain",
                "producible",
                "reason",
                "operators"
            ]
        );
        assert!(matches!(text_eq[8].1, Tree::Bool(true)));
        assert!(
            matches!(&text_eq[10].1, Tree::Array(operators) if operators.len() == 1),
            "TextEq answers one operator"
        );
    }

    #[test]
    fn a_plan_naming_a_target_is_accepted_exactly_by_the_eql_build() {
        let plan = target_plan();
        if crate::targets::HOLDS_EQL {
            assert_eq!(plan_check(&plan), Ok(()), "the eql build runs TextEq");
            // A type the engine cannot produce, and one that does not exist,
            // are refused at plan_check.
            for name in ["Json", "Nope"] {
                let refused = encoded(object(vec![(
                    "email",
                    object(vec![
                        ("context", Tree::Array(vec![text("users"), text("email")])),
                        ("target", text(name)),
                    ]),
                )]));
                assert_eq!(plan_check(&refused), Err(STATUS_ENCODING), "{name}");
            }
        } else {
            assert_eq!(
                plan_check(&plan),
                Err(STATUS_ENCODING),
                "the build without EQL types refuses a target name"
            );
        }
    }

    #[cfg(feature = "eql")]
    #[test]
    fn a_text_eq_field_round_trips_and_queries_through_the_record_exports() {
        use futures::executor::block_on;
        use stack_encrypt::StackCipher;
        use stack_kms::FakeDataKeySource;

        let cipher = block_on(StackCipher::builder().kms(FakeDataKeySource::new()).init())
            .expect("a cipher");
        let keyset = cipher.default_keyset();
        let plan = target_plan();
        let source = encoded(object(vec![
            ("email", text("alice@example.com")),
            ("notes", text("likes cats")),
        ]));
        validate::record(&source, &plan).expect("the source fits");
        let sealed = block_on(encrypt_record(&keyset, &source, &plan)).expect("seals");

        // The stored tree carries the EQL JSON under "eql": the v4 envelope
        // with the column as its i and a stack-encrypt ciphertext.
        let tree = decode_tree(&sealed).expect("a tree");
        let CipherText::Map(mut fields) = tree else {
            panic!("a record")
        };
        let at = fields
            .iter()
            .position(|(k, _)| k == "email")
            .expect("email");
        let (_, CipherText::Map(outputs)) = fields.swap_remove(at) else {
            panic!("outputs")
        };
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].0, dynamic::record::EQL_KEY);
        let CipherText::Passthrough(payload) = &outputs[0].1 else {
            panic!("a passthrough")
        };
        let Tree::Bytes(bytes) = Tree::from_frame(&payload.0).expect("a value") else {
            panic!("bytes")
        };
        let eql: serde_json::Value = serde_json::from_slice(bytes.as_slice()).expect("JSON");
        assert_eq!(eql["v"], 4, "Stack Encrypt writes EQL v4");
        assert_eq!(eql["i"], serde_json::json!({"t": "users", "c": "email"}));
        assert!(eql["c"].as_str().unwrap().starts_with("stack-encrypt:1:"));
        assert_eq!(eql["hm"].as_str().unwrap().len(), 64);

        // Opens back through the EQL type's own decryption.
        validate::record_tree(&sealed, &plan, None).expect("the tree fits");
        let opened =
            block_on(decrypt_record(Scope::Client(&cipher), &sealed, &plan, None)).expect("opens");
        let Tree::Object(values) = Tree::from_frame(&opened).expect("a value") else {
            panic!("an object")
        };
        assert!(matches!(&values[0].1, Tree::String(s) if s.as_bytes() == b"alice@example.com"));
        assert!(matches!(&values[1].1, Tree::String(s) if s.as_bytes() == b"likes cats"));

        // The eq query's term is the type's query value, and it matches the
        // stored term.
        let probe = encoded(text("alice@example.com"));
        validate::query_term(&probe, &plan, b"email", b"eq").expect("a target field answers eq");
        let term = block_on(query_term(&keyset, &probe, &plan, b"email", b"eq")).expect("derives");
        let Tree::Object(term) = Tree::from_frame(&term).expect("a value") else {
            panic!("a query term is an object")
        };
        assert!(matches!(&term[3].1, Tree::String(s) if s.as_bytes() == b"eql_v4.query_text_eq"));
        let Tree::Bytes(query_bytes) = &term[4].1 else {
            panic!("the term is the query value's bytes")
        };
        let probe_json: serde_json::Value =
            serde_json::from_slice(query_bytes.as_slice()).expect("JSON");
        assert_eq!(
            probe_json["hm"], eql["hm"],
            "the query matches the stored value"
        );
        assert!(
            probe_json.get("c").is_none(),
            "a query carries no ciphertext"
        );
        // A query on a sealed field, an unknown field, or a wrong kind is
        // refused at validation.
        assert_eq!(
            validate::query_term(&probe, &plan, b"notes", b"eq"),
            Err(STATUS_ENCODING)
        );
        assert_eq!(
            validate::query_term(&probe, &plan, b"nope", b"eq"),
            Err(STATUS_ENCODING)
        );
        assert_eq!(
            validate::query_term(&encoded(Tree::UInt32(1)), &plan, b"email", b"eq"),
            Err(STATUS_ENCODING)
        );
    }
}
