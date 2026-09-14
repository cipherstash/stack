//! One index term for a runtime value.
//!
//! The dispatch here is the whole point of the module: which arm a value
//! takes decides the term's PRF/CLLW *input encoding*, and that encoding is
//! part of the cross-language contract. An equality term for
//! `FfiValue::UInt32(34)` must equal the term the typed path derives for
//! `34u32`, so each variant is handed to the same typed operation a Rust
//! caller would have named.
//!
//! # These are the query-probe path
//!
//! Same caveat as [`crate::sem`]: a term derived here is bound to the
//! context you pass and to nothing else. Use it to *query*. A term that is
//! going to be **stored** should come from the record path, where it shares
//! one context with the ciphertext beside it by construction (ADR-0004).

use std::fmt;

use stack_kms::DataKeySource;
use vitaminc_aead_value::FfiValue;
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroizing;

use super::{utf8, Error};
use crate::sem::{CllwOpeEncrypt, CllwOreEncrypt, DefaultMatch};
use crate::{IntoPrfContext, KeysetCipher, NonEmpty};

/// Which index term to derive.
///
/// The `key` strings are wire format — see the [module docs](super) on
/// stability.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum TermKind {
    /// `"eq"` — equality (exact match). Raw 32 PRF bytes.
    Equality,
    /// `"match"` — full-text match under the default tokenizer config. LE
    /// `u16` bit positions.
    Match,
    /// `"ore"` — order-revealing comparison. Raw CLLW bytes.
    Ore,
    /// `"ope"` — order-preserving comparison. Raw CLLW bytes.
    Ope,
}

impl TermKind {
    /// The map key this term rides under in a record, and the string a
    /// binding spells it as.
    pub fn key(self) -> &'static str {
        match self {
            TermKind::Equality => "eq",
            TermKind::Match => "match",
            TermKind::Ore => "ore",
            TermKind::Ope => "ope",
        }
    }

    /// Whether the scheme defines this term for `scalar`.
    ///
    /// No PRF encoding exists for floats (equality on IEEE-754 values is a
    /// modelling error) or booleans; match is text-only; the ordering
    /// schemes take every scalar. This is the one table — [`term`]'s arms
    /// mirror it and are unreachable for a pair it refuses — and it is
    /// consulted before any cipher work, so a binding can reject a bad
    /// request at its boundary without minting anything.
    pub fn supports(self, scalar: &Scalar) -> bool {
        match self {
            TermKind::Equality => {
                !matches!(scalar, Scalar::Bool(_) | Scalar::F32(_) | Scalar::F64(_))
            }
            TermKind::Match => matches!(scalar, Scalar::Text(_)),
            TermKind::Ore | TermKind::Ope => true,
        }
    }
}

impl fmt::Display for TermKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

/// A term-able scalar lifted out of an [`FfiValue`] leaf.
///
/// Lifting is a copy, so the value it came from stays movable into the
/// ciphertext path beside it. The owned text and bytes copies wipe on drop;
/// the PRF and CLLW layers move them into [`Protected`] internally.
#[derive(Clone)]
#[non_exhaustive]
pub enum Scalar {
    /// From [`FfiValue::Bool`].
    Bool(bool),
    /// From [`FfiValue::Int32`].
    I32(i32),
    /// From [`FfiValue::Int64`].
    I64(i64),
    /// From [`FfiValue::UInt32`].
    U32(u32),
    /// From [`FfiValue::UInt64`].
    U64(u64),
    /// From [`FfiValue::Float32`].
    F32(f32),
    /// From [`FfiValue::Float64`].
    F64(f64),
    /// From [`FfiValue::String`].
    Text(Zeroizing<String>),
    /// From [`FfiValue::Bytes`].
    Bytes(Zeroizing<Vec<u8>>),
}

impl Scalar {
    /// Lift the scalar out of a value leaf.
    ///
    /// # Errors
    ///
    /// [`Error::Term`] for a container, null, undefined or passthrough:
    /// those have no term semantics at all, whatever the kind. `kind` names
    /// the term the caller was after, for the error only — whether that kind
    /// is defined for the scalar is [`TermKind::supports`].
    pub fn of(value: &FfiValue, kind: TermKind) -> Result<Self, Error> {
        Ok(match value {
            FfiValue::Bool(v) => Scalar::Bool(*v),
            FfiValue::Int32(v) => Scalar::I32(*v),
            FfiValue::Int64(v) => Scalar::I64(*v),
            FfiValue::UInt32(v) => Scalar::U32(*v),
            FfiValue::UInt64(v) => Scalar::U64(*v),
            FfiValue::Float32(v) => Scalar::F32(*v),
            FfiValue::Float64(v) => Scalar::F64(*v),
            FfiValue::String(s) => Scalar::Text(Zeroizing::new(
                utf8(s).ok_or(Error::Term { kind })?.to_string(),
            )),
            FfiValue::Bytes(b) => Scalar::Bytes(Zeroizing::new(b.risky_ref().to_vec())),
            // Containers, nulls and passthroughs have no term semantics.
            _ => return Err(Error::Term { kind }),
        })
    }
}

/// Derive one index term's frozen byte encoding.
///
/// # Errors
///
/// [`Error::Term`] if the scheme defines no such term for the scalar
/// ([`TermKind::supports`] is the table, and checking it first is how a
/// binding turns this into a boundary rejection). [`Error::Cipher`] if the
/// derivation itself fails.
pub async fn term<'c, K, D>(
    cipher: &KeysetCipher<'_, K>,
    scalar: Scalar,
    kind: TermKind,
    context: NonEmpty<D>,
) -> Result<Vec<u8>, Error>
where
    K: DataKeySource + Sync,
    D: IntoPrfContext<'c>,
{
    match kind {
        TermKind::Equality => {
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
                // No PRF encoding is defined for floats (equality on
                // IEEE-754 values is a modelling error) or booleans.
                Scalar::Bool(_) | Scalar::F32(_) | Scalar::F64(_) => {
                    return Err(Error::Term { kind })
                }
            }?;
            Ok(term.into_bytes().to_vec())
        }
        TermKind::Match => match scalar {
            Scalar::Text(t) => Ok(cipher
                .match_terms::<DefaultMatch>(&t, context)
                .await
                .map(|t| t.to_bytes())?),
            _ => Err(Error::Term { kind }),
        },
        // The text and bytes arms hand the encryptor the `Zeroizing` operand
        // itself, not a bare clone of its contents: the CLLW encryptors take
        // their value by `'static` ownership (the visitor carries it), so a
        // cloned-out `String`/`Vec<u8>` would be freed with the plaintext
        // still in it — in a guest's linear memory, where the host can read
        // it. Keeping the wrapper costs nothing and saves the copy as well.
        TermKind::Ore => match scalar {
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
        TermKind::Ope => match scalar {
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
) -> Result<Vec<u8>, Error>
where
    K: DataKeySource + Sync,
    T: CllwOreEncrypt + Send + 'static,
    T::Output: AsRef<[u8]> + Send + 'static,
    D: IntoPrfContext<'c>,
{
    Ok(cipher
        .ore_term(value, context)
        .await
        .map(|t| t.as_ref().to_vec())?)
}

/// See [`ore`].
async fn ope<'c, K, T, D>(
    cipher: &KeysetCipher<'_, K>,
    value: T,
    context: NonEmpty<D>,
) -> Result<Vec<u8>, Error>
where
    K: DataKeySource + Sync,
    T: CllwOpeEncrypt + Send + 'static,
    T::Output: AsRef<[u8]> + Send + 'static,
    D: IntoPrfContext<'c>,
{
    Ok(cipher
        .ope_term(value, context)
        .await
        .map(|t| t.as_ref().to_vec())?)
}
