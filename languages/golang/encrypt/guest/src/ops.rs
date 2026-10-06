//! The guest's operations, written against `StackCipher<K>` / `KeysetCipher<K>` for any
//! [`DataKeySource`] so they compile — and their tests run — on the native
//! host target with `FakeDataKeySource`. The wasm32-only [`crate::abi`]
//! module wires them to the session table and the packed ABI; nothing in
//! here knows about linear memory.
//!
//! Values and ciphertext trees cross the boundary in the vitaminc FFI codec
//! (`vitaminc_aead_value::transport`) — the same codec the vitaminc guest
//! uses, so the Go side carries exactly one codec. A ciphertext tree's
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

use stack_encrypt::dynamic::{self, Scalar, Scope};
use stack_encrypt::sem::MatchOptions;
use stack_encrypt::target::IndexSpec;
use stack_encrypt::{BoxedPassthrough, CipherText, KeysetCipher, SealedValue, StackCipherText};
use stack_kms::DataKeySource;
use vitaminc_aead_value::{transport as codec, FfiValue};
use vitaminc_protected::Controlled;

use crate::status::{status_for_dynamic, status_for_error, STATUS_ENCODING, STATUS_INTERNAL};

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
type BytesTree = CipherText<Vec<u8>, BoxedPassthrough>;

// =============================================================================
// Terms
// =============================================================================

/// Derive one index term: a codec-encoded scalar and a codec-encoded
/// context in, the term's frozen byte encoding out (see `stack-encrypt`'s
/// `sem` module docs). Under the local HMAC backend the derivation is one
/// PRF/CLLW computation with no ZeroKMS I/O; that is the backend's
/// property, not this operation's contract — the term API is a `Pending`
/// so a backend that derives terms at ZeroKMS settles the same way.
///
/// The context is one part — a string, bytes, or an `i32`/`i64`/`u32`/`u64`
/// — or an array of parts, nested as deep as the transport codec allows
/// ([`codec::MAX_DEPTH`] levels from the root of the encoded value; deeper
/// is [`STATUS_ENCODING`] before the context is parsed), exactly as a plan
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
    let context = dynamic::context(decode_value(context)?).map_err(|e| status_for_dynamic(&e))?;
    let (scalar, kind) = parse_term(decode_value(value)?, kind)?;
    dynamic::term(cipher, scalar, &kind, context)
        .await
        .map_err(|e| status_for_dynamic(&e))
}

/// The static half of a term: the kind is one of the ABI's table, the value
/// is a scalar, and the scheme defines the pair
/// ([`IndexSpec::supports`]). Shared by [`term`] and [`validate::term`] so
/// the ABI refuses exactly what the operation would, before any keyset is
/// resolved.
///
/// The ABI's kind codes carry no options, so [`TERM_MATCH`] is the match
/// index under the default options, the same index a plan's bare `"match"`
/// names.
fn parse_term(value: FfiValue, kind: u32) -> Result<(Scalar, IndexSpec), u32> {
    let kind = match kind {
        TERM_EQUALITY => IndexSpec::Equality,
        TERM_MATCH => IndexSpec::Match(MatchOptions::default()),
        TERM_ORE => IndexSpec::Ore,
        TERM_OPE => IndexSpec::Ope,
        _ => return Err(STATUS_ENCODING),
    };
    let scalar = Scalar::of(&value, &kind).map_err(|e| status_for_dynamic(&e))?;
    if !kind.supports(&scalar) {
        return Err(STATUS_ENCODING);
    }
    Ok((scalar, kind))
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
    let plan = dynamic::record::plan(decode_value(plan)?).map_err(|e| status_for_dynamic(&e))?;
    let tree = dynamic::record::encrypt(cipher, decode_value(source)?, &plan)
        .map_err(|e| status_for_dynamic(&e))?
        .await
        .map_err(|e| status_for_error(&e))?;
    encode_tree(tree)
}

/// Decrypt a record — or a batch — produced by [`encrypt_record`] under the
/// same plan. Only the `"c"` and `"passthrough"` outputs participate (terms
/// are one-way).
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
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync + 'static,
{
    let plan = dynamic::record::plan(decode_value(plan)?).map_err(|e| status_for_dynamic(&e))?;
    let value = dynamic::record::decrypt(scope, decode_tree(record)?, &plan)
        .map_err(|e| status_for_dynamic(&e))?
        .await
        .map_err(|e| status_for_error(&e))?;
    encode_value(value)
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
    dynamic::record::plan(decode_value(plan)?)
        .map(drop)
        .map_err(|e| status_for_dynamic(&e))
}

/// The EQL types this build of the engine produces, as a codec-encoded
/// `{"targets": [...]}`. Empty until the EQL target dispatch lands: a
/// generator reads an empty list as "no `encrypt_into` type is available
/// yet" and refuses the tag. The shape is fixed here so the next build adds
/// entries to the list rather than a second export.
pub fn targets() -> Result<Vec<u8>, u32> {
    encode_value(FfiValue::Object(vec![(
        "targets".to_string(),
        FfiValue::Array(Vec::new()),
    )]))
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
    /// the value is a scalar the scheme defines that term for
    /// ([`IndexSpec::supports`]).
    pub fn term(value: &[u8], context: &[u8], kind: u32) -> Result<(), u32> {
        dynamic::context(decode_value(context)?)
            .map(drop)
            .map_err(|e| status_for_dynamic(&e))?;
        parse_term(decode_value(value)?, kind).map(drop)
    }

    /// A record source against its plan, as [`encrypt_record`] takes them:
    /// the plan decodes and parses (every field's context non-empty, every
    /// output known), and the source fits it (shape, field set, each value
    /// against its field's outputs).
    pub fn record(source: &[u8], plan: &[u8]) -> Result<(), u32> {
        let plan =
            dynamic::record::plan(decode_value(plan)?).map_err(|e| status_for_dynamic(&e))?;
        dynamic::record::check_source(decode_value(source)?, &plan)
            .map_err(|e| status_for_dynamic(&e))
    }

    /// A record tree against its plan, as [`decrypt_record`] takes them:
    /// the plan parses, the tree decodes with well-formed leaves, and every
    /// ciphertext-bearing field has a `"c"` node that is not a passthrough.
    pub fn record_tree(record: &[u8], plan: &[u8]) -> Result<(), u32> {
        let plan =
            dynamic::record::plan(decode_value(plan)?).map_err(|e| status_for_dynamic(&e))?;
        dynamic::record::check_record(decode_tree(record)?, &plan)
            .map_err(|e| status_for_dynamic(&e))
    }
}

// =============================================================================
// Codec glue
// =============================================================================

fn decode_value(bytes: &[u8]) -> Result<FfiValue, u32> {
    codec::decode_value(&mut codec::Reader::new(bytes)).map_err(|_| STATUS_ENCODING)
}

/// Encode a value tree into a buffer sized **before** the first byte is
/// written.
///
/// This buffer is plaintext on the decrypt path, and a `Vec` grown by the
/// codec's pushes would leave partial plaintext in every abandoned
/// allocation a reallocation could not extend in place — memory nothing
/// wipes, undercutting the guarantee the registry makes about the buffer it
/// eventually hands the host. Reserving the exact encoded length up front
/// means the encoder never reallocates, and `register`'s `into_boxed_slice`
/// (capacity == length) does not copy either.
fn encode_value(value: FfiValue) -> Result<Vec<u8>, u32> {
    let mut out = exact_buffer(value_encoded_len(&value))?;
    codec::encode_value(value, &mut out).map_err(|_| STATUS_ENCODING)?;
    Ok(out)
}

fn decode_tree(bytes: &[u8]) -> Result<StackCipherText, u32> {
    let tree: BytesTree = codec::decode_ciphertext_boxed(&mut codec::Reader::new(bytes))
        .map_err(|_| STATUS_ENCODING)?;
    // Structural only — a decoded leaf proves nothing until its AEAD opens
    // (see the `SealedValue` docs).
    map_leaves(tree, &mut |l: Vec<u8>| {
        SealedValue::from_bytes(&l).map_err(|_| STATUS_ENCODING)
    })
}

/// The encode twin of [`decode_tree`]. Passthrough nodes can carry caller
/// plaintext, so this is sized up front for the same reason
/// [`encode_value`] is.
fn encode_tree(tree: StackCipherText) -> Result<Vec<u8>, u32> {
    let tree = map_leaves(tree, &mut |l: SealedValue| Ok::<_, u32>(l.to_bytes()))?;
    let mut out = exact_buffer(tree_encoded_len(&tree))?;
    codec::encode_ciphertext_boxed(tree, &mut out).map_err(|_| STATUS_ENCODING)?;
    Ok(out)
}

/// Rebuild a ciphertext tree with every leaf run through `leaf`, keeping the
/// structure (and the passthrough payloads) untouched. One definition for
/// both directions of the frozen [`SealedValue`] leaf encoding.
fn map_leaves<A, B, E>(
    tree: CipherText<A, BoxedPassthrough>,
    leaf: &mut impl FnMut(A) -> Result<B, E>,
) -> Result<CipherText<B, BoxedPassthrough>, E> {
    Ok(match tree {
        CipherText::Single(l) => CipherText::Single(leaf(l)?),
        CipherText::None(l) => CipherText::None(leaf(l)?),
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

/// Exact byte length of the codec's encoding of `value`. `None` on overflow
/// or on a length the codec's `u32` frames cannot express — the encode would
/// fail on those anyway, so the caller reports an encoding error.
fn value_encoded_len(value: &FfiValue) -> Option<usize> {
    // tag byte + fixed payload, or tag + u32 length prefix + payload.
    let framed = |len: usize| u32::try_from(len).ok().and_then(|_| len.checked_add(5));
    match value {
        FfiValue::Null | FfiValue::Undefined | FfiValue::Bool(_) => Some(1),
        FfiValue::Int32(_) | FfiValue::UInt32(_) | FfiValue::Float32(_) => Some(5),
        FfiValue::Int64(_) | FfiValue::UInt64(_) | FfiValue::Float64(_) => Some(9),
        FfiValue::String(s) => framed(s.risky_ref().len()),
        FfiValue::Bytes(b) => framed(b.risky_ref().len()),
        FfiValue::Array(items) => items.iter().try_fold(5usize, |acc, item| {
            acc.checked_add(value_encoded_len(item)?)
        }),
        FfiValue::Object(entries) => entries.iter().try_fold(5usize, |acc, (key, value)| {
            acc.checked_add(framed(key.len())?.checked_sub(1)?)?
                .checked_add(value_encoded_len(value)?)
        }),
        FfiValue::Passthrough(inner) => value_encoded_len(inner)?.checked_add(1),
    }
}

/// Exact byte length of the codec's encoding of a ciphertext tree. The
/// passthrough payloads are read (not consumed) through `Any::downcast_ref`,
/// matching what `encode_ciphertext_boxed` will re-home them to; a payload
/// that is not an [`FfiValue`] is `None`, which is the same rejection the
/// encoder would make.
fn tree_encoded_len(tree: &BytesTree) -> Option<usize> {
    let framed = |len: usize| u32::try_from(len).ok().and_then(|_| len.checked_add(5));
    match tree {
        CipherText::Single(l)
        | CipherText::None(l)
        | CipherText::EmptySequence(l)
        | CipherText::EmptyMap(l) => framed(l.len()),
        CipherText::Sequence(items) => items
            .iter()
            .try_fold(5usize, |acc, item| acc.checked_add(tree_encoded_len(item)?)),
        CipherText::Map(entries) => entries.iter().try_fold(5usize, |acc, (key, value)| {
            acc.checked_add(framed(key.len())?.checked_sub(1)?)?
                .checked_add(tree_encoded_len(value)?)
        }),
        CipherText::Passthrough(p) => {
            value_encoded_len((**p).downcast_ref::<FfiValue>()?)?.checked_add(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_protected::Protected;

    // `value_encoded_len` / `tree_encoded_len` re-derive the codec's framing
    // arithmetic; the codec exports no `encoded_len` of its own, so these
    // pins are the only thing that fails if the two drift. Drift is not a
    // cosmetic bug: an undersized reservation makes `encode_value`
    // reallocate mid-encode, leaving unwiped partial plaintext in the
    // abandoned allocation — silently.

    fn every_value_shape() -> Vec<FfiValue> {
        vec![
            FfiValue::Null,
            FfiValue::Undefined,
            FfiValue::Bool(true),
            FfiValue::Int32(-5),
            FfiValue::UInt32(5),
            FfiValue::Float32(1.5),
            FfiValue::Int64(-9),
            FfiValue::UInt64(9),
            FfiValue::Float64(2.5),
            FfiValue::String("".into()),
            FfiValue::String("héllo".into()),
            FfiValue::Bytes(Protected::new(Vec::new())),
            FfiValue::Bytes(Protected::new(vec![0u8; 300])),
            FfiValue::Array(Vec::new()),
            FfiValue::Array(vec![FfiValue::Bool(false), FfiValue::String("x".into())]),
            FfiValue::Object(Vec::new()),
            FfiValue::Object(vec![
                ("a".to_string(), FfiValue::Int32(1)),
                (
                    "nested".to_string(),
                    FfiValue::Object(vec![("b".to_string(), FfiValue::Null)]),
                ),
            ]),
            FfiValue::Passthrough(Box::new(FfiValue::Int64(7))),
            FfiValue::Passthrough(Box::new(FfiValue::Array(vec![FfiValue::String(
                "deep".into(),
            )]))),
        ]
    }

    #[test]
    fn value_encoded_len_matches_the_codec_exactly() {
        for (i, value) in every_value_shape().into_iter().enumerate() {
            let expected = value_encoded_len(&value).expect("encodable shape");
            let mut out = Vec::new();
            codec::encode_value(value, &mut out).expect("codec encode");
            assert_eq!(out.len(), expected, "shape {i}");
        }
    }

    #[test]
    fn tree_encoded_len_matches_the_codec_exactly() {
        let leaf = |bytes: &[u8]| -> BytesTree { CipherText::Single(bytes.to_vec()) };
        let trees: Vec<BytesTree> = vec![
            leaf(b""),
            leaf(&[7u8; 40]),
            CipherText::None(vec![1, 2]),
            CipherText::EmptySequence(vec![3]),
            CipherText::EmptyMap(Vec::new()),
            CipherText::Sequence(vec![leaf(b"a"), CipherText::None(vec![9])]),
            CipherText::Map(vec![
                ("name".to_string(), leaf(b"ct")),
                (
                    "inner".to_string(),
                    CipherText::Map(vec![("x".to_string(), leaf(b"y"))]),
                ),
            ]),
            CipherText::Passthrough(
                Box::new(FfiValue::Bytes(Protected::new(vec![1, 2, 3]))) as BoxedPassthrough
            ),
        ];
        for (i, tree) in trees.into_iter().enumerate() {
            let expected = tree_encoded_len(&tree).expect("encodable shape");
            let mut out = Vec::new();
            codec::encode_ciphertext_boxed(tree, &mut out).expect("codec encode");
            assert_eq!(out.len(), expected, "tree {i}");
        }
    }
}
