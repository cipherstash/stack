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
//! # Records
//!
//! [`encrypt_record`] is the runtime form of `#[derive(EncryptFrom)]`: a
//! *plan* says, per field, which encryption context to bind and which
//! outputs to produce (ciphertext and/or index terms); the source supplies
//! the field values. However many rows and fields are in one call, all
//! ciphertext leaves seal from **one** batched `generate_keys` — the
//! pendings are merged before settling, exactly like the derive's `zip`/`all`
//! composition — and index terms derive locally with no ZeroKMS traffic at
//! all. That batch reaches ZeroKMS as one request per
//! `ClientOpts::max_keys_per_req` keyed leaves (500 by default, sent
//! sequentially: the guest pins `max_concurrent_reqs` to 1), so "one call"
//! is exact up to 500 leaves and "one call per 500" past it. See
//! `parse_plan` for the plan encoding.

use stack_encrypt::sem::{CllwOpeEncrypt, CllwOreEncrypt, DefaultMatch};
use stack_encrypt::target::Pending;
use stack_encrypt::{
    AadPiece, BoxedPassthrough, CipherText, Decrypt, Element, Encrypt, IntoPrfContext,
    KeysetCipher, NonEmpty, SealedValue, StackCipher, StackCipherText,
};
use stack_kms::DataKeySource;
use vitaminc_aead_value::{transport as codec, FfiValue};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroizing;

use crate::context::{borrowed, parse_context};
use crate::status::{status_for_error, STATUS_AUTH, STATUS_ENCODING, STATUS_INTERNAL};

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
// Whole-value encrypt / decrypt (the vitaminc guest's vc_encrypt shape)
// =============================================================================

/// Encrypt a codec-encoded [`FfiValue`] tree under `aad`, sealing every leaf
/// against a fresh ZeroKMS data key (one batched request; see the module
/// docs for how a batch is chunked). With `as_element`,
/// seal it as a *sequence element* — interchangeable with rows written by
/// encrypting a whole sequence under the same AAD.
///
/// This is the cipher-directed path, and it takes the AAD as `StackCipher`
/// does: any bytes, including none. An empty `aad` seals under no context —
/// the plain AEAD use `Aes256Cipher` allows, opened symmetrically by
/// [`decrypt_value`] — and is the Go caller's choice to make. The record and
/// term paths ([`encrypt_record`], [`decrypt_record`], [`term`]) are the
/// ones that bind fields: each takes a [`NonEmpty`] context, proven once at
/// the boundary when the plan or the term's context is parsed, and refused
/// as [`STATUS_ENCODING`] when empty.
pub async fn encrypt_value<K>(
    cipher: &KeysetCipher<'_, K>,
    value: &[u8],
    aad: &[u8],
    as_element: bool,
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
{
    let value = decode_value(value)?;
    let tree = if as_element {
        Element(value).encrypt_with_aad(cipher, aad)
    } else {
        value.encrypt_with_aad(cipher, aad)
    }
    .map_err(|_| STATUS_INTERNAL)?;
    let ct = tree
        .seal(cipher, aad)
        .await
        .map_err(|e| status_for_error(&e))?;
    encode_tree(ct)
}

/// Decrypt a codec-encoded ciphertext tree back into a codec-encoded
/// [`FfiValue`] tree (one batched `retrieve_keys` request). The output buffer
/// contains plaintext — the ABI layer's ownership rules govern its wiping.
///
/// Symmetric with [`encrypt_value`]: the AAD is whatever the value was sealed
/// under, empty included.
pub async fn decrypt_value<K>(
    cipher: &StackCipher<K>,
    ciphertext: &[u8],
    aad: &[u8],
    as_element: bool,
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
{
    let tree = decode_tree(ciphertext)?;
    let decipher = cipher
        .decipher(tree, aad)
        .await
        .map_err(|e| status_for_error(&e))?;
    let value: FfiValue = if as_element {
        Element::<FfiValue>::decrypt_with_aad(decipher, aad).map(Element::into_inner)
    } else {
        FfiValue::decrypt_with_aad(decipher, aad)
    }
    .map_err(|_| STATUS_AUTH)?;
    encode_value(value)
}

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
/// field's; [`crate::context`] is the one home of that grammar. Shape is identity:
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
    K: DataKeySource + Sync,
{
    let value = decode_value(value)?;
    // The same proof every stack-encrypt leaf demands: an empty context is
    // `STATUS_ENCODING` here, before any derivation.
    let context = parse_context(decode_value(context)?)?;
    let output = match kind {
        TERM_EQUALITY => Output::Equality,
        TERM_MATCH => Output::Match,
        TERM_ORE => Output::Ore,
        TERM_OPE => Output::Ope,
        _ => return Err(STATUS_ENCODING),
    };
    term_bytes(cipher, scalar_of(&value)?, context, output).await
}

/// A term-able scalar lifted (by copy) out of an [`FfiValue`] leaf, so the
/// value itself stays movable into the ciphertext path. The owned text/bytes
/// copies wipe on drop; the PRF/CLLW layers move them into `Protected`
/// internally.
#[derive(Clone)]
enum Scalar {
    Bool(bool),
    I32(i32),
    I64(i64),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
    Text(Zeroizing<String>),
    Bytes(Zeroizing<Vec<u8>>),
}

fn scalar_of(value: &FfiValue) -> Result<Scalar, u32> {
    Ok(match value {
        FfiValue::Bool(v) => Scalar::Bool(*v),
        FfiValue::Int32(v) => Scalar::I32(*v),
        FfiValue::Int64(v) => Scalar::I64(*v),
        FfiValue::UInt32(v) => Scalar::U32(*v),
        FfiValue::UInt64(v) => Scalar::U64(*v),
        FfiValue::Float32(v) => Scalar::F32(*v),
        FfiValue::Float64(v) => Scalar::F64(*v),
        FfiValue::String(s) => Scalar::Text(Zeroizing::new(text_of(s)?.to_string())),
        FfiValue::Bytes(b) => Scalar::Bytes(Zeroizing::new(b.risky_ref().to_vec())),
        // Containers, nulls and passthroughs have no term semantics.
        _ => return Err(STATUS_ENCODING),
    })
}

/// Derive one output's term bytes for a scalar.
///
/// The type dispatch decides the term's PRF/CLLW input encoding, which is
/// part of the cross-language contract: an equality term for `UInt32(34)`
/// must equal the term the Rust side derives for `34u32`. Unsupported
/// combinations (floats or booleans under equality, anything non-text under
/// match) are [`STATUS_ENCODING`] — the scheme does not define them.
async fn term_bytes<'c, K, D>(
    cipher: &KeysetCipher<'_, K>,
    scalar: Scalar,
    context: NonEmpty<D>,
    output: Output,
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
    D: IntoPrfContext<'c>,
{
    let term_err = |e| status_for_error(&e);
    match output {
        Output::Ciphertext => Err(STATUS_ENCODING),
        Output::Equality => {
            let term = match scalar {
                Scalar::I32(v) => cipher.equality_term(v, context).await,
                Scalar::I64(v) => cipher.equality_term(v, context).await,
                Scalar::U32(v) => cipher.equality_term(v, context).await,
                Scalar::U64(v) => cipher.equality_term(v, context).await,
                Scalar::Text(t) => cipher.equality_term(String::clone(&t), context).await,
                Scalar::Bytes(b) => {
                    cipher
                        .equality_term(Protected::new(Vec::clone(&b)), context)
                        .await
                }
                // No PRF encoding is defined for floats (equality on IEEE-754
                // values is a modelling error) or booleans.
                Scalar::Bool(_) | Scalar::F32(_) | Scalar::F64(_) => return Err(STATUS_ENCODING),
            }
            .map_err(term_err)?;
            Ok(term.into_bytes().to_vec())
        }
        Output::Match => match scalar {
            Scalar::Text(t) => cipher
                .match_terms::<DefaultMatch>(&t, context)
                .await
                .map(|t| t.to_bytes())
                .map_err(term_err),
            _ => Err(STATUS_ENCODING),
        },
        // The text and bytes arms hand the encryptor the `Zeroizing` operand
        // itself, not a bare clone of its contents: the CLLW encryptors take
        // their value by `'static` ownership (the visitor carries it), so a
        // cloned-out `String`/`Vec<u8>` would be freed with the plaintext
        // still in it — in linear memory the host can read. Keeping the
        // wrapper costs nothing and saves the copy as well.
        Output::Ore => match scalar {
            Scalar::Bool(v) => ore(cipher, v, context).await,
            Scalar::I32(v) => ore(cipher, v, context).await,
            Scalar::I64(v) => ore(cipher, v, context).await,
            Scalar::U32(v) => ore(cipher, v, context).await,
            Scalar::U64(v) => ore(cipher, v, context).await,
            Scalar::F32(v) => ore(cipher, v, context).await,
            Scalar::F64(v) => ore(cipher, v, context).await,
            Scalar::Text(t) => ore(cipher, t, context).await,
            Scalar::Bytes(b) => ore(cipher, b, context).await,
        },
        Output::Ope => match scalar {
            Scalar::Bool(v) => ope(cipher, v, context).await,
            Scalar::I32(v) => ope(cipher, v, context).await,
            Scalar::I64(v) => ope(cipher, v, context).await,
            Scalar::U32(v) => ope(cipher, v, context).await,
            Scalar::U64(v) => ope(cipher, v, context).await,
            Scalar::F32(v) => ope(cipher, v, context).await,
            Scalar::F64(v) => ope(cipher, v, context).await,
            Scalar::Text(t) => ope(cipher, t, context).await,
            Scalar::Bytes(b) => ope(cipher, b, context).await,
        },
    }
}

/// The `AsRef<[u8]>` on the output is what turns the typed CLLW ciphertext
/// into the frozen raw-bytes encoding.
async fn ore<'c, K, T, D>(
    cipher: &KeysetCipher<'_, K>,
    value: T,
    context: NonEmpty<D>,
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
    T: CllwOreEncrypt + Send + 'static,
    T::Output: AsRef<[u8]> + Send + 'static,
    D: IntoPrfContext<'c>,
{
    cipher
        .ore_term(value, context)
        .await
        .map(|t| t.as_ref().to_vec())
        .map_err(|e| status_for_error(&e))
}

/// See [`ore`].
async fn ope<'c, K, T, D>(
    cipher: &KeysetCipher<'_, K>,
    value: T,
    context: NonEmpty<D>,
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
    T: CllwOpeEncrypt + Send + 'static,
    T::Output: AsRef<[u8]> + Send + 'static,
    D: IntoPrfContext<'c>,
{
    cipher
        .ope_term(value, context)
        .await
        .map(|t| t.as_ref().to_vec())
        .map_err(|e| status_for_error(&e))
}

// =============================================================================
// Records
// =============================================================================

/// What a plan field asks for. The strings are the plan encoding *and* the
/// keys of the per-field output map in the result.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Output {
    /// `"c"` — the field's [`StackCipherText`].
    Ciphertext,
    /// `"eq"` — equality term (raw 32 PRF bytes).
    Equality,
    /// `"match"` — match term (LE `u16` positions), default tokenizer config.
    Match,
    /// `"ore"` — ORE term (raw CLLW bytes).
    Ore,
    /// `"ope"` — OPE term (raw CLLW bytes).
    Ope,
}

impl Output {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "c" => Output::Ciphertext,
            "eq" => Output::Equality,
            "match" => Output::Match,
            "ore" => Output::Ore,
            "ope" => Output::Ope,
            _ => return None,
        })
    }

    fn key(self) -> &'static str {
        match self {
            Output::Ciphertext => "c",
            Output::Equality => "eq",
            Output::Match => "match",
            Output::Ore => "ore",
            Output::Ope => "ope",
        }
    }
}

/// One field of a record plan.
struct FieldPlan {
    name: String,
    /// Proven non-empty when the plan is parsed, so every path that seals or
    /// opens under it — the cipher-directed `encrypt_with_aad` in
    /// [`build_row`] as much as the target-directed `decrypt_into` in
    /// [`decrypt_record`] — is under a context stack-encrypt's leaves accept.
    context: NonEmpty<AadPiece<'static>>,
    outputs: Vec<Output>,
}

/// Parse a record plan from a decoded value. The plan is an
/// [`FfiValue::Object`]:
///
/// ```text
/// { <field>: { "context": <context>, "outputs": [ "c" | "eq" | "match" | "ore" | "ope", ... ] }, ... }
/// ```
///
/// `<context>` is defined once, in [`crate::context`]: a string, bytes, an
/// integer, or a list of those, with what each spells in Rust and the
/// emptiness rule.
///
/// Rejected as [`STATUS_ENCODING`]: an empty plan, a missing, malformed or
/// *empty* context (contexts domain-separate fields; stack-encrypt's leaves
/// take a `NonEmpty<_>` and nothing else), an empty/unknown/duplicated
/// output list, unknown keys. Field names are unique by construction (the
/// codec rejects duplicate object keys).
///
/// The context is proven here, once, and carried as a [`NonEmpty`]: the
/// cipher-directed path [`build_row`] seals through accepts any AAD, so
/// nothing downstream would otherwise stop an empty context from being
/// sealed under — and [`decrypt_record`] opens through `decrypt_into`,
/// which would then never open it.
///
/// A plan context is the *whole* context of the field: the guest has no
/// caller context to extend it with, so the plan spells the extension
/// itself. A bare string matches a Rust `#[derive(EncryptFrom)]` record
/// sealed with `encrypt_into` (no caller context); a list matches one
/// sealed with `encrypt_into_with_context` — see [`crate::context`] for
/// which list spells which Rust context. Rows are readable across the two
/// however they were sealed, provided the plan names the context the row
/// was sealed under.
fn parse_plan(value: FfiValue) -> Result<Vec<FieldPlan>, u32> {
    let FfiValue::Object(entries) = value else {
        return Err(STATUS_ENCODING);
    };
    if entries.is_empty() {
        return Err(STATUS_ENCODING);
    }
    entries
        .into_iter()
        .map(|(name, spec)| {
            let FfiValue::Object(spec) = spec else {
                return Err(STATUS_ENCODING);
            };
            let mut context: Option<NonEmpty<AadPiece<'static>>> = None;
            let mut outputs: Option<Vec<Output>> = None;
            for (key, value) in spec {
                match key.as_str() {
                    "context" => context = Some(parse_context(value)?),
                    "outputs" => {
                        let FfiValue::Array(items) = value else {
                            return Err(STATUS_ENCODING);
                        };
                        let mut parsed = Vec::with_capacity(items.len());
                        for item in &items {
                            let FfiValue::String(s) = item else {
                                return Err(STATUS_ENCODING);
                            };
                            let output = Output::parse(text_of(s)?).ok_or(STATUS_ENCODING)?;
                            if parsed.contains(&output) {
                                return Err(STATUS_ENCODING);
                            }
                            parsed.push(output);
                        }
                        outputs = Some(parsed);
                    }
                    _ => return Err(STATUS_ENCODING),
                }
            }
            let context = context.ok_or(STATUS_ENCODING)?;
            let outputs = outputs.filter(|o| !o.is_empty()).ok_or(STATUS_ENCODING)?;
            Ok(FieldPlan {
                name,
                context,
                outputs,
            })
        })
        .collect()
}

/// A row's assembled outputs, ciphertext slots still pending: the terms are
/// derived (locally), and each `None` is filled from the settled ciphertexts
/// in build order.
type RowSkeleton = Vec<(String, Vec<(&'static str, Option<Vec<u8>>)>)>;

/// Reject a source field value that contains a passthrough anywhere, before
/// it reaches a `"c"` slot. A passthrough node is *unauthenticated by
/// definition* — on decrypt it hands its payload back with no AEAD opened —
/// so admitting one under a plan field the plan declares ciphertext-bearing
/// would quietly produce a slot whose bytes verify nothing. Rejecting it
/// here is what makes [`decrypt_record`]'s mirror-image rejection a
/// round-trip invariant rather than data loss.
fn reject_passthrough_value(value: &FfiValue) -> Result<(), u32> {
    match value {
        FfiValue::Passthrough(_) => Err(STATUS_ENCODING),
        FfiValue::Array(items) => items.iter().try_for_each(reject_passthrough_value),
        FfiValue::Object(entries) => entries
            .iter()
            .try_for_each(|(_, v)| reject_passthrough_value(v)),
        _ => Ok(()),
    }
}

/// Reject a `"c"` subtree that contains a passthrough anywhere. This is the
/// decrypt-side half of [`reject_passthrough_value`], and it is
/// load-bearing: `decrypt_into` collects **zero** retrieve-requests for a
/// passthrough and returns its payload with no AEAD opened, so an attacker
/// with write access to the stored tree could replace a field's `"c"`
/// subtree with a passthrough carrying forged plaintext and this function's
/// absence would report it as a successful decrypt. [`encrypt_record`] never
/// produces a passthrough under `"c"`, so the shape is unconditionally
/// [`STATUS_ENCODING`].
fn reject_passthrough_tree(tree: &StackCipherText) -> Result<(), u32> {
    match tree {
        CipherText::Passthrough(_) => Err(STATUS_ENCODING),
        CipherText::Sequence(items) => items.iter().try_for_each(reject_passthrough_tree),
        CipherText::Map(entries) => entries
            .iter()
            .try_for_each(|(_, v)| reject_passthrough_tree(v)),
        CipherText::Single(_)
        | CipherText::None(_)
        | CipherText::EmptySequence(_)
        | CipherText::EmptyMap(_) => Ok(()),
    }
}

/// Encrypt a record — or a batch of records — per a plan.
///
/// `source` is a codec-encoded [`FfiValue::Object`] of `{ field: scalar }`
/// (one record), or an [`FfiValue::Array`] of such objects (a batch). Every
/// plan field must be present in each record, and every record field must be
/// named by the plan — silently dropping a field on either side would lose
/// data or index nothing.
///
/// The result is a codec-encoded ciphertext tree: per record a map of
/// `field → { output-key → node }`, where `"c"` is the field's sealed
/// ciphertext subtree and each term rides as a passthrough
/// [`FfiValue::Bytes`] node (terms are comparands, not ciphertexts to open —
/// passthrough is their honest encoding). A batch is a sequence of such
/// maps. All rows and fields seal in one batched `generate_keys`; that
/// batch is split into one ZeroKMS request per
/// [`ClientOpts::max_keys_per_req`](stack_kms::ClientOpts::with_max_keys_per_req)
/// keyed leaves (500 by default), sent sequentially.
///
/// **Cross-language note.** A `"c"` leaf seals the aead-value *tagged*
/// plaintext encoding (`[type tag] ++ payload`), because that tag table is
/// the contract Go, Node and this guest share. A Rust
/// `#[derive(EncryptFrom)]` over a plain primitive — a bare `u32` — seals
/// four untagged bytes instead, so a plain-primitive Rust derive and a Go
/// plan do **not** interchange ciphertexts for the same field until the Rust
/// side uses aead-value's tagged types too. This is by design, not a defect
/// in either side; making the derive tagged is a separate follow-up.
pub async fn encrypt_record<K>(
    cipher: &KeysetCipher<'_, K>,
    source: &[u8],
    plan: &[u8],
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
{
    let plan = parse_plan(decode_value(plan)?)?;

    let (rows, batched) = match decode_value(source)? {
        FfiValue::Object(entries) => (vec![entries], false),
        FfiValue::Array(items) => {
            let rows = items
                .into_iter()
                .map(|item| match item {
                    FfiValue::Object(entries) => Ok(entries),
                    _ => Err(STATUS_ENCODING),
                })
                .collect::<Result<Vec<_>, u32>>()?;
            (rows, true)
        }
        _ => return Err(STATUS_ENCODING),
    };

    // Build every row: terms derive now (local), ciphertexts queue their
    // data-key requests into one flat pending list.
    let mut pendings: Vec<Pending<'_, StackCipherText, K>> = Vec::new();
    let mut skeletons: Vec<RowSkeleton> = Vec::with_capacity(rows.len());
    for row in rows {
        skeletons.push(build_row(cipher, row, &plan, &mut pendings).await?);
    }

    // The one ZeroKMS call for the whole invocation.
    let sealed = Pending::all(cipher, pendings)
        .await
        .map_err(|e| status_for_error(&e))?;
    let mut sealed = sealed.into_iter();

    // Fill the ciphertext slots back in, in build order.
    let mut row_nodes = Vec::with_capacity(skeletons.len());
    for skeleton in skeletons {
        let mut fields = Vec::with_capacity(skeleton.len());
        for (field, outputs) in skeleton {
            let mut nodes = Vec::with_capacity(outputs.len());
            for (key, slot) in outputs {
                let node = match slot {
                    Some(term) => CipherText::Passthrough(Box::new(FfiValue::Bytes(Protected::new(
                        term,
                    )))
                        as BoxedPassthrough),
                    None => sealed.next().ok_or(STATUS_INTERNAL)?,
                };
                nodes.push((key.to_string(), node));
            }
            fields.push((field, CipherText::Map(nodes)));
        }
        row_nodes.push(CipherText::Map(fields));
    }
    if sealed.next().is_some() {
        return Err(STATUS_INTERNAL);
    }

    let tree = if batched {
        CipherText::Sequence(row_nodes)
    } else {
        row_nodes.pop().ok_or(STATUS_INTERNAL)?
    };
    encode_tree(tree)
}

/// Build one record row: derive its terms and queue its ciphertext pendings,
/// returning the row skeleton. The plan drives the iteration so the output
/// field order is the plan's; the row must contain exactly the plan's fields.
async fn build_row<'c, K>(
    cipher: &'c KeysetCipher<'_, K>,
    mut row: Vec<(String, FfiValue)>,
    plan: &[FieldPlan],
    pendings: &mut Vec<Pending<'c, StackCipherText, K>>,
) -> Result<RowSkeleton, u32>
where
    K: DataKeySource + Sync,
{
    if row.len() != plan.len() {
        return Err(STATUS_ENCODING);
    }
    let mut skeleton = Vec::with_capacity(plan.len());
    for field in plan {
        let at = row
            .iter()
            .position(|(name, _)| name == &field.name)
            .ok_or(STATUS_ENCODING)?;
        let (name, value) = row.swap_remove(at);
        // A borrowed view of the plan's context, once per field: the proof
        // was made at parse time, so re-taking it over the same tree cannot
        // fail, and the view clones cheaply for each output below.
        let context = NonEmpty::new(borrowed(field.context.get())).map_err(|_| STATUS_INTERNAL)?;

        // Terms first — they lift a copy of the scalar; the value itself is
        // consumed by the ciphertext path below.
        let wants_terms = field.outputs.iter().any(|o| *o != Output::Ciphertext);
        let scalar = if wants_terms {
            Some(scalar_of(&value)?)
        } else {
            None
        };

        let mut outputs: Vec<(&'static str, Option<Vec<u8>>)> =
            Vec::with_capacity(field.outputs.len());
        for output in &field.outputs {
            if *output == Output::Ciphertext {
                outputs.push((output.key(), None));
                continue;
            }
            let scalar = scalar.clone().ok_or(STATUS_INTERNAL)?;
            let term = term_bytes(cipher, scalar, context.clone(), *output).await?;
            outputs.push((output.key(), Some(term)));
        }

        if field.outputs.contains(&Output::Ciphertext) {
            reject_passthrough_value(&value)?;
            let tree = value
                .encrypt_with_aad(cipher, context.clone())
                .map_err(|_| STATUS_INTERNAL)?;
            pendings.push(tree.into_pending(cipher, context));
        }

        skeleton.push((name, outputs));
    }
    Ok(skeleton)
}

/// Decrypt a record — or a batch — produced by [`encrypt_record`] under the
/// same plan. Only the `"c"` outputs participate (terms are one-way); the
/// result is a codec-encoded [`FfiValue::Object`] per record holding the
/// plan's ciphertext-bearing fields, in plan order — or an
/// [`FfiValue::Array`] of them for a batch. One `retrieve_keys` call per
/// invocation.
pub async fn decrypt_record<K>(
    cipher: &StackCipher<K>,
    record: &[u8],
    plan: &[u8],
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
{
    use stack_encrypt::target::DecryptInto;

    let plan = parse_plan(decode_value(plan)?)?;

    let (rows, batched) = match decode_tree(record)? {
        CipherText::Map(entries) => (vec![entries], false),
        CipherText::Sequence(items) => {
            let rows = items
                .into_iter()
                .map(|item| match item {
                    CipherText::Map(entries) => Ok(entries),
                    _ => Err(STATUS_ENCODING),
                })
                .collect::<Result<Vec<_>, u32>>()?;
            (rows, true)
        }
        _ => return Err(STATUS_ENCODING),
    };

    // Per row, per ciphertext-bearing plan field: lift out the "c" subtree
    // and queue its decrypt. Terms and extra fields in the tree are ignored
    // (they are comparands, not ciphertext).
    let mut pendings: Vec<Pending<'_, FfiValue, K>> = Vec::new();
    let mut names: Vec<Vec<String>> = Vec::with_capacity(rows.len());
    for row in rows {
        let mut row = row;
        let mut row_names = Vec::new();
        for field in &plan {
            if !field.outputs.contains(&Output::Ciphertext) {
                continue;
            }
            let context =
                NonEmpty::new(borrowed(field.context.get())).map_err(|_| STATUS_INTERNAL)?;
            let at = row
                .iter()
                .position(|(name, _)| name == &field.name)
                .ok_or(STATUS_ENCODING)?;
            let (name, node) = row.swap_remove(at);
            let CipherText::Map(outputs) = node else {
                return Err(STATUS_ENCODING);
            };
            let ct = outputs
                .into_iter()
                .find_map(|(key, node)| (key == "c").then_some(node))
                .ok_or(STATUS_ENCODING)?;
            reject_passthrough_tree(&ct)?;
            pendings.push(ct.decrypt_into(cipher, context));
            row_names.push(name);
        }
        names.push(row_names);
    }

    // The one ZeroKMS call for the whole invocation.
    let values = Pending::all(cipher, pendings)
        .await
        .map_err(|e| status_for_error(&e))?;
    let mut values = values.into_iter();

    let mut row_values = Vec::with_capacity(names.len());
    for row_names in names {
        let mut entries = Vec::with_capacity(row_names.len());
        for name in row_names {
            entries.push((name, values.next().ok_or(STATUS_INTERNAL)?));
        }
        row_values.push(FfiValue::Object(entries));
    }
    if values.next().is_some() {
        return Err(STATUS_INTERNAL);
    }

    let value = if batched {
        FfiValue::Array(row_values)
    } else {
        row_values.pop().ok_or(STATUS_INTERNAL)?
    };
    encode_value(value)
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

fn text_of(s: &vitaminc_aead_value::Utf8String) -> Result<&str, u32> {
    // Valid UTF-8 by `Utf8String`'s construction invariant; checked rather
    // than assumed because this is boundary code.
    std::str::from_utf8(s.risky_ref()).map_err(|_| STATUS_ENCODING)
}

#[cfg(test)]
mod tests {
    use super::*;

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
