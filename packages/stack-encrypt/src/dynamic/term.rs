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
//! one context with the ciphertext beside it (ADR-0004).

use std::fmt;

use stack_kms::DataKeySource;
use vitaminc_aead_value::FfiValue;
use vitaminc_protected::{Controlled, OpaqueDebug, Protected};
use zeroize::Zeroizing;

use super::{utf8, Error};
use crate::sem::{CllwOpeEncrypt, CllwOreEncrypt, DefaultMatch};
use crate::{IntoPrfContext, KeysetCipher, NonEmpty};

/// Which index term to derive.
///
/// The `key` strings are wire format, and that is why this enum is
/// exhaustive — see the [module docs](super#stability).
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
///
/// It is plaintext, so its `Debug` is opaque: the variant is named, the
/// value is masked.
#[derive(Clone, OpaqueDebug)]
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
/// # Examples
///
/// A probe for a value a binding decoded derives the bytes the typed path
/// derives for the same value under the same context:
///
/// ```
/// use stack_encrypt::dynamic::{context, term, FfiValue, Scalar, TermKind};
/// use stack_encrypt::StackCipher;
/// use stack_encrypt::kms::FakeDataKeySource;
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let cipher = StackCipher::builder()
///     .kms(FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// let ctx = context(FfiValue::String("users/age".into()))?;
/// let probe = term(&keyset, Scalar::U32(34), TermKind::Equality, ctx.clone()).await?;
/// let typed = keyset.equality_term(34u32, ctx).await?;
/// assert_eq!(probe, typed.into_bytes().to_vec());
/// # Ok::<(), stack_encrypt::dynamic::Error>(())
/// # }).unwrap();
/// ```
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
        TermKind::Equality => equality(cipher, scalar, context).await,
        TermKind::Match => match_term(cipher, scalar, context).await,
        TermKind::Ore => ore_of(cipher, scalar, context).await,
        TermKind::Ope => ope_of(cipher, scalar, context).await,
    }
}

/// [`TermKind::Equality`] per scalar: one PRF block over the value, for
/// every integer width, text and bytes.
async fn equality<'c, K, D>(
    cipher: &KeysetCipher<'_, K>,
    scalar: Scalar,
    context: NonEmpty<D>,
) -> Result<Vec<u8>, Error>
where
    K: DataKeySource + Sync,
    D: IntoPrfContext<'c>,
{
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
        Scalar::Bool(_) | Scalar::F32(_) | Scalar::F64(_) => {
            return Err(Error::Term {
                kind: TermKind::Equality,
            })
        }
    }?;
    Ok(term.into_bytes().to_vec())
}

/// [`TermKind::Match`] per scalar: text only.
async fn match_term<'c, K, D>(
    cipher: &KeysetCipher<'_, K>,
    scalar: Scalar,
    context: NonEmpty<D>,
) -> Result<Vec<u8>, Error>
where
    K: DataKeySource + Sync,
    D: IntoPrfContext<'c>,
{
    match scalar {
        Scalar::Text(t) => Ok(cipher
            .match_terms::<DefaultMatch>(&t, context)
            .await
            .map(|t| t.to_bytes())?),
        _ => Err(Error::Term {
            kind: TermKind::Match,
        }),
    }
}

/// [`TermKind::Ore`] per scalar: every scalar has an ORE encoding.
///
/// The text and bytes arms hand the encryptor the `Zeroizing` operand
/// itself, not a bare clone of its contents: the CLLW encryptors take
/// their value by `'static` ownership (the visitor carries it), so a
/// cloned-out `String`/`Vec<u8>` would be freed with the plaintext
/// still in it — in a guest's linear memory, where the host can read
/// it. Keeping the wrapper costs nothing and saves the copy as well.
async fn ore_of<'c, K, D>(
    cipher: &KeysetCipher<'_, K>,
    scalar: Scalar,
    context: NonEmpty<D>,
) -> Result<Vec<u8>, Error>
where
    K: DataKeySource + Sync,
    D: IntoPrfContext<'c>,
{
    match scalar {
        Scalar::Bool(v) => ore(cipher, v, context).await,
        Scalar::I32(v) => ore(cipher, v, context).await,
        Scalar::I64(v) => ore(cipher, v, context).await,
        Scalar::U32(v) => ore(cipher, v, context).await,
        Scalar::U64(v) => ore(cipher, v, context).await,
        Scalar::F32(v) => ore(cipher, v, context).await,
        Scalar::F64(v) => ore(cipher, v, context).await,
        Scalar::Text(t) => ore(cipher, t, context).await,
        Scalar::Bytes(b) => ore(cipher, b, context).await,
    }
}

/// [`TermKind::Ope`] per scalar; see [`ore_of`] for why the text and bytes
/// arms pass the wrapper.
async fn ope_of<'c, K, D>(
    cipher: &KeysetCipher<'_, K>,
    scalar: Scalar,
    context: NonEmpty<D>,
) -> Result<Vec<u8>, Error>
where
    K: DataKeySource + Sync,
    D: IntoPrfContext<'c>,
{
    match scalar {
        Scalar::Bool(v) => ope(cipher, v, context).await,
        Scalar::I32(v) => ope(cipher, v, context).await,
        Scalar::I64(v) => ope(cipher, v, context).await,
        Scalar::U32(v) => ope(cipher, v, context).await,
        Scalar::U64(v) => ope(cipher, v, context).await,
        Scalar::F32(v) => ope(cipher, v, context).await,
        Scalar::F64(v) => ope(cipher, v, context).await,
        Scalar::Text(t) => ope(cipher, t, context).await,
        Scalar::Bytes(b) => ope(cipher, b, context).await,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::{context, Output};
    use crate::{nonempty, StackCipher};
    use stack_kms::FakeDataKeySource;

    async fn cipher() -> StackCipher<FakeDataKeySource> {
        StackCipher::builder()
            .kms(FakeDataKeySource::new())
            .init()
            .await
            .expect("build cipher")
    }

    fn s(value: &str) -> FfiValue {
        FfiValue::String(value.into())
    }

    fn bytes(value: &[u8]) -> FfiValue {
        FfiValue::Bytes(Protected::new(value.to_vec()))
    }

    /// Every scalar variant, from the leaf it lifts out of.
    fn every_scalar() -> Vec<(&'static str, FfiValue)> {
        vec![
            ("a bool", FfiValue::Bool(true)),
            ("an i32", FfiValue::Int32(-3)),
            ("an i64", FfiValue::Int64(-4)),
            ("a u32", FfiValue::UInt32(34)),
            ("a u64", FfiValue::UInt64(35)),
            ("an f32", FfiValue::Float32(1.5)),
            ("an f64", FfiValue::Float64(2.5)),
            ("text", s("alice")),
            ("bytes", bytes(b"ab")),
        ]
    }

    mod given_a_scalar_the_scheme_defines_the_term_for {
        use super::*;

        /// The contract the dispatch exists for: the bytes are the typed
        /// path's, so a probe from any language finds a Rust-written term.
        #[tokio::test]
        async fn derives_the_bytes_the_typed_path_derives() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
            let dynamic = |value: &FfiValue, kind: TermKind| {
                let scalar = Scalar::of(value, kind).expect("a scalar");
                term(&keyset, scalar, kind, ctx.clone())
            };
            let eq = |t: crate::sem::EqualityTerm| t.into_bytes().to_vec();

            // Equality, per PRF-encodable variant.
            let typed = keyset.equality_term(-3i32, nonempty!("users/x")).await;
            assert_eq!(
                dynamic(&FfiValue::Int32(-3), TermKind::Equality)
                    .await
                    .expect("eq"),
                eq(typed.expect("typed")),
                "i32 equality"
            );
            let typed = keyset.equality_term(-4i64, nonempty!("users/x")).await;
            assert_eq!(
                dynamic(&FfiValue::Int64(-4), TermKind::Equality)
                    .await
                    .expect("eq"),
                eq(typed.expect("typed")),
                "i64 equality"
            );
            let typed = keyset.equality_term(34u32, nonempty!("users/x")).await;
            assert_eq!(
                dynamic(&FfiValue::UInt32(34), TermKind::Equality)
                    .await
                    .expect("eq"),
                eq(typed.expect("typed")),
                "u32 equality"
            );
            let typed = keyset.equality_term(35u64, nonempty!("users/x")).await;
            assert_eq!(
                dynamic(&FfiValue::UInt64(35), TermKind::Equality)
                    .await
                    .expect("eq"),
                eq(typed.expect("typed")),
                "u64 equality"
            );
            let typed = keyset
                .equality_term("alice".to_string(), nonempty!("users/x"))
                .await;
            assert_eq!(
                dynamic(&s("alice"), TermKind::Equality).await.expect("eq"),
                eq(typed.expect("typed")),
                "text equality"
            );
            let typed = keyset
                .equality_term(Protected::new(b"ab".to_vec()), nonempty!("users/x"))
                .await;
            assert_eq!(
                dynamic(&bytes(b"ab"), TermKind::Equality)
                    .await
                    .expect("eq"),
                eq(typed.expect("typed")),
                "bytes equality"
            );

            // Match, text only.
            let typed = keyset
                .match_terms::<DefaultMatch>("alice smith", nonempty!("users/x"))
                .await
                .expect("typed");
            assert_eq!(
                dynamic(&s("alice smith"), TermKind::Match)
                    .await
                    .expect("match"),
                typed.to_bytes(),
                "text match"
            );

            // The ordering schemes take every scalar; the typed side is
            // spelled once per variant because each is its own type.
            macro_rules! ordered {
                ($value:expr, $leaf:expr, $label:literal) => {
                    let typed = keyset.ore_term($value, nonempty!("users/x")).await;
                    assert_eq!(
                        dynamic(&$leaf, TermKind::Ore).await.expect("ore"),
                        typed.expect("typed").as_ref().to_vec(),
                        concat!($label, " ore")
                    );
                    let typed = keyset.ope_term($value, nonempty!("users/x")).await;
                    assert_eq!(
                        dynamic(&$leaf, TermKind::Ope).await.expect("ope"),
                        typed.expect("typed").as_ref().to_vec(),
                        concat!($label, " ope")
                    );
                };
            }
            ordered!(true, FfiValue::Bool(true), "bool");
            ordered!(-3i32, FfiValue::Int32(-3), "i32");
            ordered!(-4i64, FfiValue::Int64(-4), "i64");
            ordered!(34u32, FfiValue::UInt32(34), "u32");
            ordered!(35u64, FfiValue::UInt64(35), "u64");
            ordered!(1.5f32, FfiValue::Float32(1.5), "f32");
            ordered!(2.5f64, FfiValue::Float64(2.5), "f64");
            ordered!("alice".to_string(), s("alice"), "text");
            ordered!(b"ab".to_vec(), bytes(b"ab"), "bytes");
        }

        #[test]
        fn supports_is_true() {
            for (label, leaf) in every_scalar() {
                let scalar = Scalar::of(&leaf, TermKind::Ore).expect("a scalar");
                assert!(TermKind::Ore.supports(&scalar), "{label} takes an ore term");
                assert!(TermKind::Ope.supports(&scalar), "{label} takes an ope term");
            }
            for (label, leaf) in every_scalar() {
                let scalar = Scalar::of(&leaf, TermKind::Equality).expect("a scalar");
                let prf_encodable = !matches!(
                    leaf,
                    FfiValue::Bool(_) | FfiValue::Float32(_) | FfiValue::Float64(_)
                );
                assert_eq!(
                    TermKind::Equality.supports(&scalar),
                    prf_encodable,
                    "{label} takes an equality term exactly when it has a PRF encoding"
                );
                assert_eq!(
                    TermKind::Match.supports(&scalar),
                    matches!(leaf, FfiValue::String(_)),
                    "{label} takes a match term exactly when it is text"
                );
            }
        }
    }

    mod given_a_pair_the_scheme_refuses {
        use super::*;

        /// The arms of `term` are unreachable for a pair `supports` refuses,
        /// and they say so with the same error the table would have let a
        /// binding raise at its boundary.
        #[tokio::test]
        async fn term_is_error_term_naming_the_kind() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
            let refused = [
                ("a bool", FfiValue::Bool(true), TermKind::Equality),
                ("an f32", FfiValue::Float32(1.5), TermKind::Equality),
                ("an f64", FfiValue::Float64(2.5), TermKind::Equality),
                ("a bool", FfiValue::Bool(true), TermKind::Match),
                ("a u32", FfiValue::UInt32(34), TermKind::Match),
                ("bytes", bytes(b"ab"), TermKind::Match),
            ];
            for (label, leaf, kind) in refused {
                let scalar = Scalar::of(&leaf, kind).expect("a scalar");
                assert!(
                    !kind.supports(&scalar),
                    "{label} must not take a {kind} term"
                );
                let result = term(&keyset, scalar, kind, ctx.clone()).await;
                assert!(
                    matches!(result, Err(Error::Term { kind: k }) if k == kind),
                    "{label} asked for a {kind} term must be refused as that kind: {result:?}"
                );
            }
        }
    }

    mod given_a_value_that_is_not_a_scalar {
        use super::*;

        #[test]
        fn lifting_is_error_term_naming_the_kind() {
            let not_scalars = [
                ("null", FfiValue::Null),
                ("undefined", FfiValue::Undefined),
                ("an array", FfiValue::Array(vec![FfiValue::UInt32(1)])),
                (
                    "an object",
                    FfiValue::Object(vec![("k".to_string(), FfiValue::UInt32(1))]),
                ),
                (
                    "a passthrough",
                    FfiValue::Passthrough(Box::new(FfiValue::UInt32(1))),
                ),
            ];
            for (label, value) in not_scalars {
                for kind in [
                    TermKind::Equality,
                    TermKind::Match,
                    TermKind::Ore,
                    TermKind::Ope,
                ] {
                    let result = Scalar::of(&value, kind);
                    assert!(
                        matches!(result, Err(Error::Term { kind: k }) if k == kind),
                        "{label} has no {kind} term: {result:?}"
                    );
                }
            }
        }
    }

    mod given_a_term_kind {
        use super::*;

        #[test]
        fn its_key_is_how_a_plan_spells_it() {
            for kind in [
                TermKind::Equality,
                TermKind::Match,
                TermKind::Ore,
                TermKind::Ope,
            ] {
                assert_eq!(
                    Output::parse(kind.key()),
                    Some(Output::Term(kind)),
                    "a plan spelling {kind} by its key names that term"
                );
                assert_eq!(
                    kind.to_string(),
                    kind.key(),
                    "the display form is the key, for error messages"
                );
            }
        }
    }

    mod given_a_scalar_holding_plaintext {
        use super::*;

        #[test]
        fn debug_prints_none_of_it() {
            let rendered = format!(
                "{:?}",
                Scalar::of(&s("hunter2"), TermKind::Equality).expect("a scalar")
            );
            assert!(
                !rendered.contains("hunter2"),
                "a scalar's Debug must not print its plaintext: {rendered}"
            );
            assert!(
                rendered.contains("Text"),
                "a scalar's Debug names the variant, which is not secret: {rendered}"
            );
        }
    }
}
