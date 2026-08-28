//! The guest's operations, written against `StackCipher<K>` for any
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
//! ciphertext leaves seal in **one** batched `generate_keys` — the pendings
//! are merged before settling, exactly like the derive's `zip`/`all`
//! composition — and index terms derive locally with no ZeroKMS traffic at
//! all. See [`parse_plan`] for the plan encoding.

use stack_encrypt::sem::{CllwOpeEncrypt, CllwOreEncrypt, DefaultMatch};
use stack_encrypt::target::Pending;
use stack_encrypt::{
    Aad, BoxedPassthrough, CipherText, Decrypt, Element, Encrypt, SealedValue, StackCipher,
    StackCipherText,
};
use stack_kms::DataKeySource;
use vitaminc_aead_value::{transport as codec, FfiValue};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroizing;

use crate::status::{
    status_for_error, status_for_term_error, STATUS_AUTH, STATUS_ENCODING, STATUS_INTERNAL,
};

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
/// against a fresh ZeroKMS data key (one batched call). With `as_element`,
/// seal it as a *sequence element* — interchangeable with rows written by
/// encrypting a whole sequence under the same AAD.
pub async fn encrypt_value<K>(
    cipher: &StackCipher<K>,
    value: &[u8],
    aad: &[u8],
    as_element: bool,
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
{
    let value = decode_value(value)?;
    let aad = Aad::from_slice(aad);
    let tree = if as_element {
        Element(value).encrypt_with_aad(cipher, aad)
    } else {
        value.encrypt_with_aad(cipher, aad)
    }
    .map_err(|_| STATUS_INTERNAL)?;
    let ct = tree.seal(cipher).await.map_err(|e| status_for_error(&e))?;
    encode_tree(ct)
}

/// Decrypt a codec-encoded ciphertext tree back into a codec-encoded
/// [`FfiValue`] tree (one batched `retrieve_keys` call). The output buffer
/// contains plaintext — the ABI layer's ownership rules govern its wiping.
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
        .decipher(tree)
        .await
        .map_err(|e| status_for_error(&e))?;
    let aad = Aad::from_slice(aad);
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

/// Derive one index term: a codec-encoded scalar in, the term's frozen byte
/// encoding out (see `stack-encrypt`'s `sem` module docs). Purely local —
/// this never touches ZeroKMS, which is what makes query probes cheap.
pub async fn term<K>(
    cipher: &StackCipher<K>,
    value: &[u8],
    context: &[u8],
    kind: u32,
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
{
    let value = decode_value(value)?;
    let context = std::str::from_utf8(context).map_err(|_| STATUS_ENCODING)?;
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
async fn term_bytes<K>(
    cipher: &StackCipher<K>,
    scalar: Scalar,
    context: &str,
    output: Output,
) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
{
    let term_err = |e| status_for_term_error(&e);
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
        Output::Ore => match scalar {
            Scalar::Bool(v) => ore(cipher, v, context).await,
            Scalar::I32(v) => ore(cipher, v, context).await,
            Scalar::I64(v) => ore(cipher, v, context).await,
            Scalar::U32(v) => ore(cipher, v, context).await,
            Scalar::U64(v) => ore(cipher, v, context).await,
            Scalar::F32(v) => ore(cipher, v, context).await,
            Scalar::F64(v) => ore(cipher, v, context).await,
            Scalar::Text(t) => ore(cipher, String::clone(&t), context).await,
            Scalar::Bytes(b) => ore(cipher, Vec::clone(&b), context).await,
        },
        Output::Ope => match scalar {
            Scalar::Bool(v) => ope(cipher, v, context).await,
            Scalar::I32(v) => ope(cipher, v, context).await,
            Scalar::I64(v) => ope(cipher, v, context).await,
            Scalar::U32(v) => ope(cipher, v, context).await,
            Scalar::U64(v) => ope(cipher, v, context).await,
            Scalar::F32(v) => ope(cipher, v, context).await,
            Scalar::F64(v) => ope(cipher, v, context).await,
            Scalar::Text(t) => ope(cipher, String::clone(&t), context).await,
            Scalar::Bytes(b) => ope(cipher, Vec::clone(&b), context).await,
        },
    }
}

/// The `AsRef<[u8]>` on the output is what turns the typed CLLW ciphertext
/// into the frozen raw-bytes encoding.
async fn ore<K, T>(cipher: &StackCipher<K>, value: T, context: &str) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
    T: CllwOreEncrypt + Send + 'static,
    T::Output: AsRef<[u8]> + Send + 'static,
{
    cipher
        .ore_term(value, context)
        .await
        .map(|t| t.as_ref().to_vec())
        .map_err(|e| status_for_term_error(&e))
}

/// See [`ore`].
async fn ope<K, T>(cipher: &StackCipher<K>, value: T, context: &str) -> Result<Vec<u8>, u32>
where
    K: DataKeySource + Sync,
    T: CllwOpeEncrypt + Send + 'static,
    T::Output: AsRef<[u8]> + Send + 'static,
{
    cipher
        .ope_term(value, context)
        .await
        .map(|t| t.as_ref().to_vec())
        .map_err(|e| status_for_term_error(&e))
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
    context: String,
    outputs: Vec<Output>,
}

/// Parse a record plan from a decoded value. The plan is an
/// [`FfiValue::Object`]:
///
/// ```text
/// { <field>: { "context": <string>, "outputs": [ "c" | "eq" | "match" | "ore" | "ope", ... ] }, ... }
/// ```
///
/// Rejected as [`STATUS_ENCODING`]: an empty plan, an empty or missing
/// context (contexts domain-separate fields — see `Error::EmptyContext` in
/// stack-encrypt), an empty/unknown/duplicated output list, unknown keys.
/// Field names are unique by construction (the codec rejects duplicate
/// object keys).
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
            let mut context: Option<String> = None;
            let mut outputs: Option<Vec<Output>> = None;
            for (key, value) in spec {
                match key.as_str() {
                    "context" => {
                        let FfiValue::String(s) = value else {
                            return Err(STATUS_ENCODING);
                        };
                        context = Some(text_of(&s)?.to_string());
                    }
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
            let context = context.filter(|c| !c.is_empty()).ok_or(STATUS_ENCODING)?;
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
/// maps. One `generate_keys` call per invocation, however many rows.
pub async fn encrypt_record<K>(
    cipher: &StackCipher<K>,
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
    cipher: &'c StackCipher<K>,
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
            let term = term_bytes(cipher, scalar, &field.context, *output).await?;
            outputs.push((output.key(), Some(term)));
        }

        if field.outputs.contains(&Output::Ciphertext) {
            let tree = value
                .encrypt_with_aad(cipher, field.context.as_str())
                .map_err(|_| STATUS_INTERNAL)?;
            pendings.push(tree.into_pending(cipher));
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
            pendings.push(ct.decrypt_into(cipher, field.context.as_str()));
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

fn encode_value(value: FfiValue) -> Result<Vec<u8>, u32> {
    let mut out = Vec::new();
    codec::encode_value(value, &mut out).map_err(|_| STATUS_ENCODING)?;
    Ok(out)
}

fn decode_tree(bytes: &[u8]) -> Result<StackCipherText, u32> {
    let tree: BytesTree = codec::decode_ciphertext_boxed(&mut codec::Reader::new(bytes))
        .map_err(|_| STATUS_ENCODING)?;
    sealed_tree(tree)
}

fn encode_tree(tree: StackCipherText) -> Result<Vec<u8>, u32> {
    let tree = leaf_bytes_tree(tree)?;
    let mut out = Vec::new();
    codec::encode_ciphertext_boxed(tree, &mut out).map_err(|_| STATUS_ENCODING)?;
    Ok(out)
}

/// Re-encode every leaf through the frozen [`SealedValue::to_bytes`]
/// encoding. `TagTooLong` cannot arise for a ZeroKMS-issued tag, so an
/// encode failure is internal, not an input error.
fn leaf_bytes_tree(tree: StackCipherText) -> Result<BytesTree, u32> {
    let leaf = |l: SealedValue| l.to_bytes().map_err(|_| STATUS_INTERNAL);
    Ok(match tree {
        CipherText::Single(l) => CipherText::Single(leaf(l)?),
        CipherText::None(l) => CipherText::None(leaf(l)?),
        CipherText::EmptySequence(l) => CipherText::EmptySequence(leaf(l)?),
        CipherText::EmptyMap(l) => CipherText::EmptyMap(leaf(l)?),
        CipherText::Sequence(items) => CipherText::Sequence(
            items
                .into_iter()
                .map(leaf_bytes_tree)
                .collect::<Result<_, _>>()?,
        ),
        CipherText::Map(entries) => CipherText::Map(
            entries
                .into_iter()
                .map(|(k, v)| Ok((k, leaf_bytes_tree(v)?)))
                .collect::<Result<_, u32>>()?,
        ),
        CipherText::Passthrough(p) => CipherText::Passthrough(p),
    })
}

/// Decode every leaf through the frozen [`SealedValue::from_bytes`]
/// encoding. Structural only — a decoded leaf proves nothing until its AEAD
/// opens (see the `SealedValue` docs).
fn sealed_tree(tree: BytesTree) -> Result<StackCipherText, u32> {
    let leaf = |l: Vec<u8>| SealedValue::from_bytes(&l).map_err(|_| STATUS_ENCODING);
    Ok(match tree {
        CipherText::Single(l) => CipherText::Single(leaf(l)?),
        CipherText::None(l) => CipherText::None(leaf(l)?),
        CipherText::EmptySequence(l) => CipherText::EmptySequence(leaf(l)?),
        CipherText::EmptyMap(l) => CipherText::EmptyMap(leaf(l)?),
        CipherText::Sequence(items) => CipherText::Sequence(
            items
                .into_iter()
                .map(sealed_tree)
                .collect::<Result<_, _>>()?,
        ),
        CipherText::Map(entries) => CipherText::Map(
            entries
                .into_iter()
                .map(|(k, v)| Ok((k, sealed_tree(v)?)))
                .collect::<Result<_, u32>>()?,
        ),
        CipherText::Passthrough(p) => CipherText::Passthrough(p),
    })
}

fn text_of(s: &vitaminc_aead_value::Utf8String) -> Result<&str, u32> {
    // Valid UTF-8 by `Utf8String`'s construction invariant; checked rather
    // than assumed because this is boundary code.
    std::str::from_utf8(s.risky_ref()).map_err(|_| STATUS_ENCODING)
}
