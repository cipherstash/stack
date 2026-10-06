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

use stack_kms::DataKeySource;
use vitaminc_aead_value::FfiValue;
use vitaminc_protected::{Controlled, OpaqueDebug, Protected};
use zeroize::Zeroizing;

use super::{utf8, Error, Value};
use crate::sem::{CllwOpeEncrypt, CllwOreEncrypt, DefaultMatch, MatchOptions, Tokenizer};
use crate::target::{chosen, CallerContext, ConsumeSource, Encryption, Index, IndexSpec, Pending};
use crate::{IntoPrfContext, KeysetCipher, NonEmpty};

/// The runtime half of [`IndexSpec`]: the domain table, and the index's wire
/// form in a record plan.
///
/// # Wire form
///
/// An index is its key, a string: `"eq"`, `"match"`, `"ore"` or `"ope"`.
/// `"match"` is a match index under the default options
/// ([`MatchOptions::default`]), so every plan written before options had a
/// wire form reads as it always did.
///
/// A match index under other options is a one-entry object, the key
/// `"match"` mapped to its options:
///
/// ```text
/// { "match": { "tokenizer": "standard" | { "ngram": <length> },
///              "downcase": <bool>, "k": <int>, "m": <int> } }
/// ```
///
/// Every option is optional and defaults to [`MatchOptions::default`]'s
/// value; an unknown option, an option given twice, or options that fail
/// the match scheme's bounds (`k` in `3..=16`, `m` a power of two in
/// `[32, 65536]`, a non-zero n-gram length) are refused. The other three
/// indexes have no options and no object form.
///
/// [`to_value`](Self::to_value) writes the string whenever the options are
/// the defaults and the object, with all four options, otherwise, so a
/// default plan is byte-for-byte what it was before options had a wire form.
impl IndexSpec {
    /// The index a bare key names, under default options, or `None` for a
    /// string that is not an index key.
    pub fn parse(key: &str) -> Option<Self> {
        Some(match key {
            "eq" => IndexSpec::Equality,
            "match" => IndexSpec::Match(MatchOptions::default()),
            "ore" => IndexSpec::Ore,
            "ope" => IndexSpec::Ope,
            _ => return None,
        })
    }

    /// Read an index from its wire form (see the [type docs](Self#wire-form)).
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] for a value that is neither an index key nor a match
    /// options object, or whose options are unknown, repeated, mistyped or
    /// out of bounds.
    pub fn from_value(value: &FfiValue) -> Result<Self, Error> {
        match value {
            FfiValue::String(s) => Self::parse(utf8(s).ok_or(Error::Plan)?).ok_or(Error::Plan),
            FfiValue::Object(entries) => match entries.as_slice() {
                [(key, FfiValue::Object(options))] if key == "match" => {
                    Ok(IndexSpec::Match(match_options(options)?))
                }
                _ => Err(Error::Plan),
            },
            _ => Err(Error::Plan),
        }
    }

    /// Write this index in its wire form (see the [type docs](Self#wire-form)):
    /// the key, or for a match index under non-default options, the object
    /// carrying all four of them. [`from_value`](Self::from_value) reads it
    /// back to an equal index.
    pub fn to_value(&self) -> FfiValue {
        match self {
            IndexSpec::Match(options) if *options != MatchOptions::default() => {
                let tokenizer = match options.tokenizer {
                    Tokenizer::Standard => FfiValue::String("standard".into()),
                    Tokenizer::Ngram { length } => FfiValue::Object(vec![(
                        "ngram".to_string(),
                        FfiValue::UInt64(length as u64),
                    )]),
                };
                FfiValue::Object(vec![(
                    "match".to_string(),
                    FfiValue::Object(vec![
                        ("tokenizer".to_string(), tokenizer),
                        ("downcase".to_string(), FfiValue::Bool(options.downcase)),
                        ("k".to_string(), FfiValue::UInt64(options.k as u64)),
                        ("m".to_string(), FfiValue::UInt64(u64::from(options.m))),
                    ]),
                )])
            }
            _ => FfiValue::String(self.key().into()),
        }
    }

    /// Whether the scheme defines this index's term for `scalar`.
    ///
    /// No PRF encoding exists for floats (equality on IEEE-754 values is a
    /// modelling error) or booleans; match is text-only; the ordering
    /// schemes take every scalar. This is the one table — [`term`]'s arms
    /// mirror it and are unreachable for a pair it refuses — and it is
    /// consulted before any cipher work, so a binding can reject a bad
    /// request at its boundary without minting anything. A match index's
    /// options do not change its domain.
    pub fn supports(&self, scalar: &Scalar) -> bool {
        match self {
            IndexSpec::Equality => {
                !matches!(scalar, Scalar::Bool(_) | Scalar::F32(_) | Scalar::F64(_))
            }
            IndexSpec::Match(_) => matches!(scalar, Scalar::Text(_)),
            IndexSpec::Ore | IndexSpec::Ope => true,
        }
    }
}

/// The options object of a match index's wire form: each key at most once,
/// each defaulting, and the whole checked against the scheme's bounds.
fn match_options(entries: &[(String, FfiValue)]) -> Result<MatchOptions, Error> {
    let mut options = MatchOptions::default();
    let mut seen: Vec<&str> = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        if seen.contains(&key.as_str()) {
            return Err(Error::Plan);
        }
        seen.push(key);
        match (key.as_str(), value) {
            ("tokenizer", FfiValue::String(s)) if utf8(s) == Some("standard") => {
                options.tokenizer = Tokenizer::Standard;
            }
            ("tokenizer", FfiValue::Object(tokenizer)) => match tokenizer.as_slice() {
                [(name, length)] if name == "ngram" => {
                    options.tokenizer = Tokenizer::Ngram {
                        length: integer(length)?,
                    };
                }
                _ => return Err(Error::Plan),
            },
            ("downcase", FfiValue::Bool(downcase)) => options.downcase = *downcase,
            ("k", k) => options.k = integer(k)?,
            ("m", m) => options.m = integer(m)?,
            _ => return Err(Error::Plan),
        }
    }
    if options.validate().is_err() {
        return Err(Error::Plan);
    }
    Ok(options)
}

/// A non-negative integer leaf of any width, as the target type, or
/// [`Error::Plan`].
fn integer<T: TryFrom<u64>>(value: &FfiValue) -> Result<T, Error> {
    let wide = match value {
        FfiValue::Int32(v) => u64::try_from(*v).ok(),
        FfiValue::Int64(v) => u64::try_from(*v).ok(),
        FfiValue::UInt32(v) => Some(u64::from(*v)),
        FfiValue::UInt64(v) => Some(*v),
        _ => None,
    };
    wide.and_then(|v| T::try_from(v).ok()).ok_or(Error::Plan)
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
    /// is defined for the scalar is [`IndexSpec::supports`].
    pub fn of(value: &FfiValue, kind: &IndexSpec) -> Result<Self, Error> {
        Ok(match value {
            FfiValue::Bool(v) => Scalar::Bool(*v),
            FfiValue::Int32(v) => Scalar::I32(*v),
            FfiValue::Int64(v) => Scalar::I64(*v),
            FfiValue::UInt32(v) => Scalar::U32(*v),
            FfiValue::UInt64(v) => Scalar::U64(*v),
            FfiValue::Float32(v) => Scalar::F32(*v),
            FfiValue::Float64(v) => Scalar::F64(*v),
            FfiValue::String(s) => Scalar::Text(Zeroizing::new(
                utf8(s)
                    .ok_or_else(|| Error::Term { kind: kind.clone() })?
                    .to_string(),
            )),
            FfiValue::Bytes(b) => Scalar::Bytes(Zeroizing::new(b.risky_ref().to_vec())),
            // Containers, nulls and passthroughs have no term semantics.
            _ => return Err(Error::Term { kind: kind.clone() }),
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
/// use stack_encrypt::dynamic::{context, term, FfiValue, Scalar};
/// use stack_encrypt::target::IndexSpec;
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
/// let ctx = context(FfiValue::Array(vec![
///     FfiValue::String("users".into()),
///     FfiValue::String("age".into()),
/// ]))?;
/// let probe = term(&keyset, Scalar::U32(34), &IndexSpec::Equality, ctx.clone()).await?;
/// let typed = keyset.equality_term(34u32, ctx).await?;
/// assert_eq!(probe, typed.into_bytes().to_vec());
/// # Ok::<(), stack_encrypt::dynamic::Error>(())
/// # }).unwrap();
/// ```
///
/// The derivation is `scalar_term`'s, the one dispatch from a runtime
/// scalar to the typed term operation; the record path runs the same
/// dispatch as an [`Index`] of a [`Value`] field. It is local to the keyset
/// cipher, so the await settles a pending that has nothing to request.
///
/// # Errors
///
/// [`Error::Term`] if the scheme defines no such term for the scalar
/// ([`IndexSpec::supports`] is the table, and checking it first is how a
/// binding turns this into a boundary rejection). [`Error::Cipher`] if the
/// derivation itself fails.
pub async fn term<'c, K, D>(
    cipher: &KeysetCipher<'_, K>,
    scalar: Scalar,
    kind: &IndexSpec,
    context: NonEmpty<D>,
) -> Result<Vec<u8>, Error>
where
    K: DataKeySource + Sync + 'static,
    D: IntoPrfContext<'c>,
{
    scalar_term(cipher, scalar, kind, context)?
        .await
        .map(TermBytes::into_bytes)
        .map_err(Error::Cipher)
}

/// An index term in its frozen byte encoding, as a binding stores and
/// compares it: the raw 32 PRF bytes of an equality term, a match term's
/// positions, the raw CLLW bytes of an ORE or OPE term (see
/// [`sem`](crate::sem)'s byte encodings).
///
/// The term type of [`IndexSpec`]'s [`Index`] impl: a term derived through
/// the dynamic path has no Rust term type to be, since the index was named
/// as data, so it is its bytes. Those bytes are exactly the typed term's
/// (`EqualityTerm::into_bytes`, `OreTerm::to_bytes`, …), which is what
/// makes a Rust-written term and a binding's probe compare.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TermBytes(Vec<u8>);

impl TermBytes {
    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes, owned.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for TermBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The one dispatch from a runtime scalar to a typed term operation: which
/// arm a scalar takes decides the term's input encoding, and each arm is
/// the operation a Rust caller would have named for that type, so the
/// bytes are the typed path's. Nothing is requested: a term is derived by
/// the keyset cipher's own PRF, so the pending is ready when it is built.
///
/// # Errors
///
/// [`Error::Term`] if the scheme defines no such term for the scalar.
pub(super) fn scalar_term<'a, 'c, K: 'static, D>(
    cipher: &'a KeysetCipher<'_, K>,
    scalar: Scalar,
    kind: &IndexSpec,
    context: NonEmpty<D>,
) -> Result<Pending<'a, TermBytes, K>, Error>
where
    D: IntoPrfContext<'c>,
{
    Ok(match kind {
        IndexSpec::Equality => equality_of(cipher, scalar, context)?,
        IndexSpec::Match(options) => match_of(cipher, scalar, options, context)?,
        IndexSpec::Ore => ore_of(cipher, scalar, context),
        IndexSpec::Ope => ope_of(cipher, scalar, context),
    })
}

fn equality_bytes(term: crate::sem::EqualityTerm) -> TermBytes {
    TermBytes(term.into_bytes().to_vec())
}

/// [`IndexSpec::Equality`] per scalar: one PRF block over the value, for
/// every integer width, text and bytes.
fn equality_of<'a, 'c, K: 'static, D>(
    cipher: &'a KeysetCipher<'_, K>,
    scalar: Scalar,
    context: NonEmpty<D>,
) -> Result<Pending<'a, TermBytes, K>, Error>
where
    D: IntoPrfContext<'c>,
{
    let term = match scalar {
        Scalar::I32(v) => cipher.equality_term(v, context),
        Scalar::I64(v) => cipher.equality_term(v, context),
        Scalar::U32(v) => cipher.equality_term(v, context),
        Scalar::U64(v) => cipher.equality_term(v, context),
        Scalar::Text(t) => cipher.equality_term(String::clone(&t), context),
        Scalar::Bytes(b) => cipher.equality_term(Protected::new(Vec::clone(&b)), context),
        // No PRF encoding is defined for floats (equality on IEEE-754
        // values is a modelling error) or booleans.
        Scalar::Bool(_) | Scalar::F32(_) | Scalar::F64(_) => {
            return Err(Error::Term {
                kind: IndexSpec::Equality,
            })
        }
    };
    Ok(term.map(equality_bytes))
}

/// [`IndexSpec::Match`] per scalar: text only, under the index's options.
/// Under the default options the bytes are the typed
/// `match_terms::<DefaultMatch>`'s; under others, those of a
/// [`MatchConfig`](crate::sem::MatchConfig) returning the same options.
fn match_of<'a, 'c, K: 'static, D>(
    cipher: &'a KeysetCipher<'_, K>,
    scalar: Scalar,
    options: &MatchOptions,
    context: NonEmpty<D>,
) -> Result<Pending<'a, TermBytes, K>, Error>
where
    D: IntoPrfContext<'c>,
{
    match scalar {
        Scalar::Text(t) => Ok(cipher
            .match_terms_under::<DefaultMatch>(&t, context, options.clone())
            .map(|terms| TermBytes(terms.to_bytes()))),
        _ => Err(Error::Term {
            kind: IndexSpec::Match(options.clone()),
        }),
    }
}

/// [`IndexSpec::Ore`] per scalar: every scalar has an ORE encoding.
///
/// The text and bytes arms hand the encryptor the `Zeroizing` operand
/// itself, not a bare clone of its contents: the CLLW encryptors take
/// their value by `'static` ownership (the visitor carries it), so a
/// cloned-out `String`/`Vec<u8>` would be freed with the plaintext
/// still in it — in a guest's linear memory, where the host can read
/// it. Keeping the wrapper costs nothing and saves the copy as well.
fn ore_of<'a, 'c, K: 'static, D>(
    cipher: &'a KeysetCipher<'_, K>,
    scalar: Scalar,
    context: NonEmpty<D>,
) -> Pending<'a, TermBytes, K>
where
    D: IntoPrfContext<'c>,
{
    match scalar {
        Scalar::Bool(v) => ore(cipher, v, context),
        Scalar::I32(v) => ore(cipher, v, context),
        Scalar::I64(v) => ore(cipher, v, context),
        Scalar::U32(v) => ore(cipher, v, context),
        Scalar::U64(v) => ore(cipher, v, context),
        Scalar::F32(v) => ore(cipher, v, context),
        Scalar::F64(v) => ore(cipher, v, context),
        Scalar::Text(t) => ore(cipher, t, context),
        Scalar::Bytes(b) => ore(cipher, b, context),
    }
}

/// [`IndexSpec::Ope`] per scalar; see [`ore_of`] for why the text and bytes
/// arms pass the wrapper.
fn ope_of<'a, 'c, K: 'static, D>(
    cipher: &'a KeysetCipher<'_, K>,
    scalar: Scalar,
    context: NonEmpty<D>,
) -> Pending<'a, TermBytes, K>
where
    D: IntoPrfContext<'c>,
{
    match scalar {
        Scalar::Bool(v) => ope(cipher, v, context),
        Scalar::I32(v) => ope(cipher, v, context),
        Scalar::I64(v) => ope(cipher, v, context),
        Scalar::U32(v) => ope(cipher, v, context),
        Scalar::U64(v) => ope(cipher, v, context),
        Scalar::F32(v) => ope(cipher, v, context),
        Scalar::F64(v) => ope(cipher, v, context),
        Scalar::Text(t) => ope(cipher, t, context),
        Scalar::Bytes(b) => ope(cipher, b, context),
    }
}

/// The `AsRef<[u8]>` on the output is what turns the typed CLLW ciphertext
/// into the frozen raw-bytes encoding.
fn ore<'a, 'c, K: 'static, T, D>(
    cipher: &'a KeysetCipher<'_, K>,
    value: T,
    context: NonEmpty<D>,
) -> Pending<'a, TermBytes, K>
where
    T: CllwOreEncrypt + Send + 'static,
    T::Output: AsRef<[u8]> + Send + 'static,
    D: IntoPrfContext<'c>,
{
    cipher
        .ore_term(value, context)
        .map(|term| TermBytes(term.as_ref().to_vec()))
}

/// See [`ore`].
fn ope<'a, 'c, K: 'static, T, D>(
    cipher: &'a KeysetCipher<'_, K>,
    value: T,
    context: NonEmpty<D>,
) -> Pending<'a, TermBytes, K>
where
    T: CllwOpeEncrypt + Send + 'static,
    T::Output: AsRef<[u8]> + Send + 'static,
    D: IntoPrfContext<'c>,
{
    cipher
        .ope_term(value, context)
        .map(|term| TermBytes(term.as_ref().to_vec()))
}

/// A dynamic error, where an operation's pending can only carry the crate's.
fn lifted(error: Error) -> crate::Error {
    crate::Error::Other(Box::new(error))
}

/// An [`IndexSpec`] is an [`Index`] of a [`Value`]: the index named as data,
/// over a plaintext whose type is known only when it arrives. Its
/// `operation` is `scalar_term`'s dispatch — the one step of the dynamic
/// path that stays dynamic — wrapped as a description, so a field lowered
/// from data runs through the same `indexed()` and `zip` every other field
/// does, and its term is a [`TermBytes`]. A Rust chain over `Value` fields
/// names its indexes this way too (`(IndexSpec::Equality, IndexSpec::Ore)`),
/// and is then the same declaration as a data plan's.
///
/// A value the scheme defines no such term for (a container, a float under
/// equality) fails the description when it runs; a plan lowered from data
/// refuses it before that, at its boundary ([`IndexSpec::supports`]).
impl Index<Value> for IndexSpec {
    type Term = TermBytes;
    fn spec(&self) -> IndexSpec {
        self.clone()
    }
    fn operation<'s, K: 'static, M: ConsumeSource<'s, Value>>(
        &self,
    ) -> Encryption<'s, Value, TermBytes, K, CallerContext, M> {
        let spec = self.clone();
        chosen(move |source: M::Source, cipher, cx: CallerContext| {
            let scalar = match Scalar::of(M::view(&source).get(), &spec) {
                Ok(scalar) => scalar,
                Err(error) => return Pending::failed(cipher, lifted(error)),
            };
            let context = match cx.validated() {
                Ok(context) => context,
                Err(error) => return Pending::failed(cipher, error),
            };
            match scalar_term(cipher, scalar, &spec, context) {
                Ok(pending) => pending,
                Err(error) => Pending::failed(cipher, lifted(error)),
            }
        })
    }
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

    /// A pair the scheme refuses fails the run of `IndexSpec`'s public
    /// `Index<Value>` with the dynamic `Error::Term` inside the crate error,
    /// and requests nothing: the record path refuses such a pair at its
    /// boundary, a Rust caller running the index directly meets it here.
    #[tokio::test]
    async fn a_refused_pair_fails_the_index_when_it_runs() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let ctx = || CallerContext::from(nonempty!("users/age"));
        for (what, value, kind) in [
            (
                "a float under equality",
                FfiValue::Float64(1.5),
                IndexSpec::Equality,
            ),
            (
                "an integer under match",
                FfiValue::UInt32(34),
                default_match(),
            ),
            (
                "a container under ore",
                FfiValue::Array(vec![FfiValue::UInt32(1)]),
                IndexSpec::Ore,
            ),
        ] {
            let refused = keyset
                .run(
                    Index::<Value>::operation::<FakeDataKeySource, crate::target::Owned>(&kind),
                    Value::new(value),
                    ctx(),
                )
                .await;
            match refused {
                Err(crate::Error::Other(inner)) => assert!(
                    matches!(
                        inner.downcast_ref::<Error>(),
                        Some(Error::Term { kind: refused_kind }) if *refused_kind == kind
                    ),
                    "{what}: the lifted error names the index: {inner:?}"
                ),
                other => panic!("{what}: expected the lifted Error::Term, got {other:?}"),
            }
        }
    }

    /// A `TermBytes` reads as the typed term's bytes, through every
    /// accessor: `as_bytes`, `as_ref` and `into_bytes` give the same
    /// 32 PRF bytes an `EqualityTerm` holds, for a term derived through
    /// `IndexSpec`'s `Index<Value>`.
    #[tokio::test]
    async fn term_bytes_read_as_the_typed_terms_bytes() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let typed = keyset
            .equality_term(34u32, nonempty!("users/age"))
            .await
            .expect("typed")
            .into_bytes()
            .to_vec();
        assert_eq!(typed.len(), 32);

        let through_value: TermBytes = keyset
            .run(
                Index::<Value>::operation::<FakeDataKeySource, crate::target::Owned>(
                    &IndexSpec::Equality,
                ),
                Value::new(FfiValue::UInt32(34)),
                CallerContext::from(nonempty!("users/age")),
            )
            .await
            .expect("the dynamic index derives");
        assert_eq!(through_value.as_bytes(), typed.as_slice());
        assert_eq!(through_value.as_ref(), typed.as_slice());
        assert_eq!(through_value.into_bytes(), typed);
    }

    /// A match index under the default options: what a plan's bare
    /// `"match"` names.
    fn default_match() -> IndexSpec {
        IndexSpec::Match(MatchOptions::default())
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
            let ks = &keyset;
            let dynamic = |value: &FfiValue, kind: IndexSpec| {
                let scalar = Scalar::of(value, &kind).expect("a scalar");
                let ctx = ctx.clone();
                async move { term(ks, scalar, &kind, ctx).await }
            };
            let eq = |t: crate::sem::EqualityTerm| t.into_bytes().to_vec();

            // Equality, per PRF-encodable variant.
            let typed = keyset.equality_term(-3i32, nonempty!("users/x")).await;
            assert_eq!(
                dynamic(&FfiValue::Int32(-3), IndexSpec::Equality)
                    .await
                    .expect("eq"),
                eq(typed.expect("typed")),
                "i32 equality"
            );
            let typed = keyset.equality_term(-4i64, nonempty!("users/x")).await;
            assert_eq!(
                dynamic(&FfiValue::Int64(-4), IndexSpec::Equality)
                    .await
                    .expect("eq"),
                eq(typed.expect("typed")),
                "i64 equality"
            );
            let typed = keyset.equality_term(34u32, nonempty!("users/x")).await;
            assert_eq!(
                dynamic(&FfiValue::UInt32(34), IndexSpec::Equality)
                    .await
                    .expect("eq"),
                eq(typed.expect("typed")),
                "u32 equality"
            );
            let typed = keyset.equality_term(35u64, nonempty!("users/x")).await;
            assert_eq!(
                dynamic(&FfiValue::UInt64(35), IndexSpec::Equality)
                    .await
                    .expect("eq"),
                eq(typed.expect("typed")),
                "u64 equality"
            );
            let typed = keyset
                .equality_term("alice".to_string(), nonempty!("users/x"))
                .await;
            assert_eq!(
                dynamic(&s("alice"), IndexSpec::Equality).await.expect("eq"),
                eq(typed.expect("typed")),
                "text equality"
            );
            let typed = keyset
                .equality_term(Protected::new(b"ab".to_vec()), nonempty!("users/x"))
                .await;
            assert_eq!(
                dynamic(&bytes(b"ab"), IndexSpec::Equality)
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
                dynamic(&s("alice smith"), default_match())
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
                        dynamic(&$leaf, IndexSpec::Ore).await.expect("ore"),
                        typed.expect("typed").as_ref().to_vec(),
                        concat!($label, " ore")
                    );
                    let typed = keyset.ope_term($value, nonempty!("users/x")).await;
                    assert_eq!(
                        dynamic(&$leaf, IndexSpec::Ope).await.expect("ope"),
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
                let scalar = Scalar::of(&leaf, &IndexSpec::Ore).expect("a scalar");
                assert!(
                    IndexSpec::Ore.supports(&scalar),
                    "{label} takes an ore term"
                );
                assert!(
                    IndexSpec::Ope.supports(&scalar),
                    "{label} takes an ope term"
                );
            }
            for (label, leaf) in every_scalar() {
                let scalar = Scalar::of(&leaf, &IndexSpec::Equality).expect("a scalar");
                let prf_encodable = !matches!(
                    leaf,
                    FfiValue::Bool(_) | FfiValue::Float32(_) | FfiValue::Float64(_)
                );
                assert_eq!(
                    IndexSpec::Equality.supports(&scalar),
                    prf_encodable,
                    "{label} takes an equality term exactly when it has a PRF encoding"
                );
                assert_eq!(
                    default_match().supports(&scalar),
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
                ("a bool", FfiValue::Bool(true), IndexSpec::Equality),
                ("an f32", FfiValue::Float32(1.5), IndexSpec::Equality),
                ("an f64", FfiValue::Float64(2.5), IndexSpec::Equality),
                ("a bool", FfiValue::Bool(true), default_match()),
                ("a u32", FfiValue::UInt32(34), default_match()),
                ("bytes", bytes(b"ab"), default_match()),
            ];
            for (label, leaf, kind) in refused {
                let scalar = Scalar::of(&leaf, &kind).expect("a scalar");
                assert!(
                    !kind.supports(&scalar),
                    "{label} must not take a {kind} term"
                );
                let result = term(&keyset, scalar, &kind, ctx.clone()).await;
                assert!(
                    matches!(&result, Err(Error::Term { kind: k }) if *k == kind),
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
                    IndexSpec::Equality,
                    default_match(),
                    IndexSpec::Ore,
                    IndexSpec::Ope,
                ] {
                    let result = Scalar::of(&value, &kind);
                    assert!(
                        matches!(&result, Err(Error::Term { kind: k }) if *k == kind),
                        "{label} has no {kind} term: {result:?}"
                    );
                }
            }
        }
    }

    mod given_an_index_spec {
        use super::*;

        fn non_default_match() -> MatchOptions {
            MatchOptions {
                tokenizer: crate::sem::Tokenizer::Standard,
                downcase: false,
                k: 6,
                m: 1024,
            }
        }

        /// The four keys are wire format: a plan spells each index by
        /// exactly this string, and the stored record keys its term by it.
        #[test]
        fn its_keys_are_the_four_wire_strings() {
            let cases = [
                (IndexSpec::Equality, "eq"),
                (default_match(), "match"),
                (IndexSpec::Match(non_default_match()), "match"),
                (IndexSpec::Ore, "ore"),
                (IndexSpec::Ope, "ope"),
            ];
            for (spec, key) in cases {
                assert_eq!(spec.key(), key, "{spec:?} rides under {key}");
                assert_eq!(
                    spec.to_string(),
                    key,
                    "the display form is the key, for error messages"
                );
            }
        }

        /// Every index under default options writes as its bare key and
        /// reads back from it, so a plan written before options had a wire
        /// form means what it always meant.
        #[test]
        fn a_default_index_round_trips_through_its_bare_key() {
            for spec in [
                IndexSpec::Equality,
                default_match(),
                IndexSpec::Ore,
                IndexSpec::Ope,
            ] {
                let wire = spec.to_value();
                assert!(
                    matches!(&wire, FfiValue::String(k) if utf8(k) == Some(spec.key())),
                    "{spec} writes as its bare key"
                );
                assert_eq!(
                    IndexSpec::from_value(&wire).expect("reads back"),
                    spec,
                    "{spec} reads back from its key"
                );
                assert_eq!(IndexSpec::parse(spec.key()), Some(spec.clone()));
                assert_eq!(
                    Output::parse(spec.key()),
                    Some(Output::Term(spec.clone())),
                    "a plan spelling {spec} by its key names that index"
                );
            }
            assert_eq!(IndexSpec::parse("c"), None, "the ciphertext is no index");
            assert_eq!(IndexSpec::parse("Match"), None, "keys are case-sensitive");
        }

        /// Non-default match options have a wire form, and it is lossless:
        /// each option written, each read back.
        #[test]
        fn non_default_match_options_round_trip() {
            let cases = [
                non_default_match(),
                MatchOptions {
                    tokenizer: crate::sem::Tokenizer::Ngram { length: 4 },
                    ..MatchOptions::default()
                },
                MatchOptions {
                    downcase: false,
                    ..MatchOptions::default()
                },
                MatchOptions {
                    k: 4,
                    ..MatchOptions::default()
                },
                MatchOptions {
                    m: 512,
                    ..MatchOptions::default()
                },
            ];
            for options in cases {
                let spec = IndexSpec::Match(options.clone());
                let wire = spec.to_value();
                assert!(
                    matches!(&wire, FfiValue::Object(_)),
                    "{options:?} is not the default, so it writes as an object"
                );
                assert_eq!(
                    IndexSpec::from_value(&wire).expect("reads back"),
                    spec,
                    "{options:?} round-trips"
                );
            }
        }

        /// The object form spells each option by name and defaults the
        /// rest; the exact shape here is what a binding writes.
        #[test]
        fn the_object_form_defaults_omitted_options() {
            let obj = |entries: Vec<(&str, FfiValue)>| {
                FfiValue::Object(
                    entries
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                )
            };
            let wire = obj(vec![(
                "match",
                obj(vec![
                    ("tokenizer", obj(vec![("ngram", FfiValue::UInt32(4))])),
                    ("k", FfiValue::Int64(5)),
                    ("m", FfiValue::Int32(64)),
                ]),
            )]);
            assert_eq!(
                IndexSpec::from_value(&wire).expect("reads"),
                IndexSpec::Match(MatchOptions {
                    tokenizer: crate::sem::Tokenizer::Ngram { length: 4 },
                    k: 5,
                    m: 64,
                    ..MatchOptions::default()
                })
            );
            let wire = obj(vec![(
                "match",
                obj(vec![
                    ("tokenizer", s("standard")),
                    ("downcase", FfiValue::Bool(false)),
                    ("m", FfiValue::UInt64(2048)),
                ]),
            )]);
            assert_eq!(
                IndexSpec::from_value(&wire).expect("reads"),
                IndexSpec::Match(MatchOptions {
                    tokenizer: crate::sem::Tokenizer::Standard,
                    downcase: false,
                    m: 2048,
                    ..MatchOptions::default()
                })
            );
            // An empty options object is the defaults, and reads as the
            // bare key does.
            assert_eq!(
                IndexSpec::from_value(&obj(vec![("match", obj(vec![]))])).expect("reads"),
                default_match()
            );
        }

        #[test]
        fn a_malformed_wire_form_is_error_plan() {
            let obj = |entries: Vec<(&str, FfiValue)>| {
                FfiValue::Object(
                    entries
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v))
                        .collect(),
                )
            };
            let opts = |entries: Vec<(&str, FfiValue)>| obj(vec![("match", obj(entries))]);
            let refused = [
                ("an unknown key", s("eqq")),
                ("the ciphertext key", s("c")),
                ("a number", FfiValue::UInt32(1)),
                ("an object for eq", obj(vec![("eq", obj(vec![]))])),
                (
                    "match options that are not an object",
                    obj(vec![("match", s("x"))]),
                ),
                (
                    "two entries",
                    obj(vec![("match", obj(vec![])), ("ore", obj(vec![]))]),
                ),
                ("an empty object", obj(vec![])),
                ("an unknown option", opts(vec![("q", FfiValue::UInt32(1))])),
                (
                    "an option twice",
                    opts(vec![("k", FfiValue::UInt32(4)), ("k", FfiValue::UInt32(5))]),
                ),
                (
                    "an unknown tokenizer",
                    opts(vec![("tokenizer", s("words"))]),
                ),
                (
                    "a tokenizer object that is not ngram",
                    opts(vec![(
                        "tokenizer",
                        obj(vec![("words", FfiValue::UInt32(3))]),
                    )]),
                ),
                (
                    "a zero n-gram",
                    opts(vec![(
                        "tokenizer",
                        obj(vec![("ngram", FfiValue::UInt32(0))]),
                    )]),
                ),
                ("a mistyped downcase", opts(vec![("downcase", s("yes"))])),
                ("a negative k", opts(vec![("k", FfiValue::Int32(-3))])),
                ("a float k", opts(vec![("k", FfiValue::Float64(3.0))])),
                ("k out of bounds", opts(vec![("k", FfiValue::UInt32(17))])),
                (
                    "m not a power of two",
                    opts(vec![("m", FfiValue::UInt32(300))]),
                ),
                (
                    "m too wide for u16",
                    opts(vec![("m", FfiValue::UInt64(1 << 17))]),
                ),
            ];
            for (label, wire) in refused {
                assert!(
                    matches!(IndexSpec::from_value(&wire), Err(Error::Plan)),
                    "{label} is not an index"
                );
            }
        }

        /// A match index's options reach the derivation: the default is the
        /// typed default's bytes, and other options derive other bytes —
        /// those of a typed config naming the same options.
        #[tokio::test]
        async fn match_options_drive_the_derivation() {
            struct Wide;
            impl crate::sem::MatchConfig for Wide {
                fn options() -> MatchOptions {
                    MatchOptions {
                        tokenizer: crate::sem::Tokenizer::Standard,
                        downcase: false,
                        k: 6,
                        m: 1024,
                    }
                }
            }
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
            let text = || Scalar::of(&s("Alice Smith"), &default_match()).expect("text");
            let wide = term(
                &keyset,
                text(),
                &IndexSpec::Match(non_default_match()),
                ctx.clone(),
            )
            .await
            .expect("wide");
            let typed = keyset
                .match_terms::<Wide>("Alice Smith", nonempty!("users/x"))
                .await
                .expect("typed");
            assert_eq!(wide, typed.to_bytes(), "the options are the typed config's");
            let default = term(&keyset, text(), &default_match(), ctx)
                .await
                .expect("default");
            assert_ne!(wide, default, "other options derive other terms");
        }
    }

    mod given_a_scalar_holding_plaintext {
        use super::*;

        #[test]
        fn debug_prints_none_of_it() {
            let rendered = format!(
                "{:?}",
                Scalar::of(&s("hunter2"), &IndexSpec::Equality).expect("a scalar")
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

/// The typed side's lowering meets the wire form: an `Index`'s `spec()` is
/// what a saved plan writes, so its options must survive the trip.
#[cfg(test)]
mod wire_form {
    use super::*;
    use crate::sem::{MatchConfig, Tokenizer};
    use crate::target::{Equality, Index, Match, Ope, Ore};

    /// Whole words, case kept: not the default configuration.
    struct Words;
    impl MatchConfig for Words {
        fn options() -> MatchOptions {
            MatchOptions {
                tokenizer: Tokenizer::Standard,
                downcase: false,
                k: 4,
                m: 512,
            }
        }
    }

    #[test]
    fn every_typed_index_round_trips_through_the_wire_form() {
        let specs = [
            Index::<String>::spec(&Equality),
            Index::<String>::spec(&Match::default()),
            Index::<String>::spec(&Match::<Words>::new()),
            Index::<String>::spec(&Ore),
            Index::<String>::spec(&Ope),
        ];
        for spec in specs {
            assert_eq!(
                IndexSpec::from_value(&spec.to_value()).expect("reads back"),
                spec,
                "{spec:?} survives the data form"
            );
        }
    }

    #[test]
    fn a_default_match_index_is_the_bare_match_key() {
        let spec = Index::<String>::spec(&Match::default());
        assert!(matches!(
            spec.to_value(),
            FfiValue::String(key) if super::utf8(&key) == Some("match")
        ));
    }

    #[test]
    fn a_match_index_with_other_options_keeps_them_never_rewritten() {
        let spec = Index::<String>::spec(&Match::<Words>::new());
        assert_eq!(spec, IndexSpec::Match(Words::options()));
        assert!(
            matches!(spec.to_value(), FfiValue::Object(_)),
            "non-default options are written, not dropped"
        );
    }
}
