//! One index term for a runtime value.
//!
//! A value arrives here as anything that describes itself to vitaminc
//! ([`Encrypt`]): a transport frame a guest walks in place, a
//! [`ValueFrame`] the engine holds, a Rust value. It is walked to the one
//! scalar it must be, and the term derives there, from the scalar vitaminc
//! hands the sink, so this module restates none of vitaminc's vocabulary.
//! The derivation is the typed path's, which is what makes a term a
//! cross-language contract: an equality term for a frame holding `34` is the
//! term `equality_term(34u32)` derives.
//!
//! - **Equality** normalizes the scalar with `vitaminc-normalize` and runs
//!   the PRF over the result, as the typed path does through that crate's
//!   `Terms` sink. Every integer width of one number is one term, text is
//!   compared in Unicode 16 NFC, and a date, timestamp, decimal or uuid has
//!   a domain of its own. A boolean has none.
//! - **Match** takes text only, cut in Unicode 16 NFC.
//! - **ORE and OPE** take an integer of any width, a float, text or bytes,
//!   each handed to cllw-ore as the Rust type the typed path would have
//!   named: an `i8` as an `i8`, a `u128` as a `u128`. A boolean has no
//!   order term: with two values, its order term would tell anyone holding
//!   the column which rows are `true`. A decimal, a date and a timestamp
//!   have none yet: cllw-ore 0.5 does not encode them the ADR-0002 way, and
//!   their order terms wait for new cllw-ore and ore-rs releases (#1236).
//!
//! # These are the query-probe path
//!
//! Same caveat as [`crate::sem`]: a term derived here is bound to the
//! context you pass and to nothing else. Use it to *query*. A term that is
//! going to be **stored** should come from the record path, where it shares
//! one context with the ciphertext beside it (ADR-0004).

use std::convert::Infallible;
use std::marker::PhantomData;

use super::{FfiValue, ValueFrame};
use stack_kms::DataKeySource;
use vitaminc_aead::plaintext::{
    Error as SinkError, Float, Int, Logical, MapSink, Physical, SeqSink, Sink, SourceError,
};
use vitaminc_normalize::{domain_of, normalize, NormalizeError};
use zeroize::Zeroizing;

use super::{utf8, Error, Reason};
use crate::sem::{
    CllwOpeEncrypt, CllwOreEncrypt, DefaultMatch, MatchOptions, QueryTokens, TermError, Tokenizer,
};
use crate::target::{chosen, CallerContext, ConsumeSource, Encryption, Index, IndexSpec, Pending};
use crate::{Encrypt, IntoPrfContext, KeysetCipher, NonEmpty};

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
    /// [`Error::Plan`] ([`Reason::UnknownOutput`]) for a value that is
    /// neither an index key nor a match options object, or whose options are
    /// unknown, mistyped or out of bounds; [`Reason::RepeatedKey`] for an
    /// option given twice. It names no field: the plan parser names it.
    pub fn from_value(value: &FfiValue) -> Result<Self, Error> {
        let unknown = || Error::bad_plan(Reason::UnknownOutput);
        match value {
            FfiValue::String(s) => Self::parse(utf8(s).ok_or_else(unknown)?).ok_or_else(unknown),
            FfiValue::Object(entries) => match entries.as_slice() {
                [(key, FfiValue::Object(options))] if key == "match" => {
                    Ok(IndexSpec::Match(match_options(options)?))
                }
                _ => Err(unknown()),
            },
            _ => Err(unknown()),
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

    /// Whether the scheme defines this index's term for `value`: whether it
    /// is one scalar the index takes. Equality takes every scalar vitaminc
    /// gives an equality domain (an integer, a float, text, bytes, and a
    /// date, timestamp, decimal or uuid), not a boolean or a null. Match
    /// takes text. ORE and OPE take an integer of any width, a float, text
    /// or bytes; not a boolean, and not yet a decimal, date or timestamp
    /// (#1236). A match index's options do not change what it takes.
    ///
    /// This is the one table: [`term`] refuses exactly what it refuses, and
    /// checking it first is how a binding refuses a bad request at its
    /// boundary, before a keyset is resolved or anything is derived. It says
    /// nothing about whether the value's text normalizes; that is found when
    /// the term is derived.
    ///
    /// ```
    /// use stack_encrypt::target::IndexSpec;
    ///
    /// assert!(IndexSpec::Equality.defines(34u32));
    /// assert!(IndexSpec::Equality.defines(1.5f64));
    /// assert!(!IndexSpec::Equality.defines(true));
    /// assert!(!IndexSpec::Ore.defines(true));
    /// assert!(!IndexSpec::Ope.defines(vec![1u32, 2]));
    /// ```
    pub fn defines<P: Encrypt>(&self, value: P) -> bool {
        value
            .visit(OneScalar::new(
                |ty: Option<Logical>, value: Physical<'_>| {
                    if self.takes(ty, &value) {
                        Ok(())
                    } else {
                        Err(None)
                    }
                },
            ))
            .is_ok()
    }

    /// The table [`defines`](Self::defines) reads, over one scalar.
    pub(super) fn takes(&self, ty: Option<Logical>, value: &Physical<'_>) -> bool {
        match self {
            // vitaminc's table: a kind with an equality domain.
            IndexSpec::Equality => domain_of(ty, value).is_some(),
            IndexSpec::Match(_) => ty.is_none() && matches!(value, Physical::Text(_)),
            IndexSpec::Ore | IndexSpec::Ope => ty.is_none() && ordered(value),
        }
    }
}

/// Whether CLLW ORE and OPE order this scalar: an integer of any width, a
/// float, text or bytes. Not a boolean, which would reveal which rows hold
/// `true`, and not a null. The caller has already refused a scalar under a
/// logical type: a decimal, date or timestamp's order term waits for
/// #1236.
fn ordered(value: &Physical<'_>) -> bool {
    match value {
        Physical::Int(_) | Physical::Float(_) | Physical::Text(_) | Physical::Bytes(_) => true,
        Physical::Null | Physical::Bool(_) => false,
    }
}

/// The options object of a match index's wire form: each key at most once,
/// each defaulting, and the whole checked against the scheme's bounds.
fn match_options(entries: &[(String, FfiValue)]) -> Result<MatchOptions, Error> {
    let unknown = || Error::bad_plan(Reason::UnknownOutput);
    let mut options = MatchOptions::default();
    let mut seen: Vec<&str> = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        if seen.contains(&key.as_str()) {
            return Err(Error::bad_plan(Reason::RepeatedKey));
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
                _ => return Err(unknown()),
            },
            ("downcase", FfiValue::Bool(downcase)) => options.downcase = *downcase,
            ("k", k) => options.k = integer(k)?,
            ("m", m) => options.m = integer(m)?,
            _ => return Err(unknown()),
        }
    }
    if options.validate().is_err() {
        return Err(unknown());
    }
    Ok(options)
}

/// A non-negative integer leaf of any width, as the target type, or
/// [`Error::Plan`] ([`Reason::UnknownOutput`]: it is a match option).
fn integer<T: TryFrom<u64>>(value: &FfiValue) -> Result<T, Error> {
    let wide = match value {
        FfiValue::Int32(v) => u64::try_from(*v).ok(),
        FfiValue::Int64(v) => u64::try_from(*v).ok(),
        FfiValue::UInt32(v) => Some(u64::from(*v)),
        FfiValue::UInt64(v) => Some(*v),
        _ => None,
    };
    wide.and_then(|v| T::try_from(v).ok())
        .ok_or(Error::bad_plan(Reason::UnknownOutput))
}

/// Derive one index term's frozen byte encoding.
///
/// # Examples
///
/// A probe for a value a binding decoded derives the bytes the typed path
/// derives for the same value under the same context:
///
/// ```
/// use stack_encrypt::dynamic::{context, term, FfiValue};
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
/// let probe = term(&keyset, &FfiValue::UInt32(34), &IndexSpec::Equality, ctx.clone()).await?;
/// let typed = keyset.equality_term(34u32, ctx).await?;
/// assert_eq!(probe, typed.into_bytes().to_vec());
/// # Ok::<(), stack_encrypt::dynamic::Error>(())
/// # }).unwrap();
/// ```
///
/// The record path runs the same derivation as an [`Index`] of a
/// [`ValueFrame`] field. It is local to the keyset cipher, so the await
/// settles a pending that has nothing to request.
///
/// # Errors
///
/// [`Error::Term`] if the value is not one scalar the index takes
/// ([`IndexSpec::defines`] is the table, and checking it first is how a
/// binding turns this into a boundary rejection). [`Error::Cipher`] if the
/// derivation itself fails: text with a code point unassigned in Unicode 16
/// ([`TermError::Normalize`]), or the one query value the engine refuses,
/// match text that cuts no token under the index's options
/// ([`TermError::EmptyTermText`](crate::sem::TermError::EmptyTermText)), whose filter would match every row. That
/// refusal is the query path's alone; the record path stores such a value
/// as the empty filter, which no query matches.
pub async fn term<'c, K, P, D>(
    cipher: &KeysetCipher<'_, K>,
    value: P,
    kind: &IndexSpec,
    context: NonEmpty<D>,
) -> Result<Vec<u8>, Error>
where
    K: DataKeySource + Sync + 'static,
    P: Encrypt,
    D: IntoPrfContext<'c>,
{
    derive(cipher, value, kind, context, Use::Query)?
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

/// What a derived term is for: a query refuses match text that cuts no
/// token, which a stored value keeps as the empty filter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Use {
    Query,
    Store,
}

/// Walk `value` to its one scalar and derive `kind`'s term there. Nothing
/// is requested: a term is derived by the keyset cipher's own PRF, so the
/// pending is ready when it is built.
///
/// # Errors
///
/// [`Error::Term`] if the value is not one scalar `kind` takes, and
/// [`Error::Cipher`] for a query's match text with no token or text the
/// index cannot normalize, as for [`term`].
pub(super) fn derive<'a, 'c, K: 'static, P, D>(
    cipher: &'a KeysetCipher<'_, K>,
    value: P,
    kind: &IndexSpec,
    context: NonEmpty<D>,
    purpose: Use,
) -> Result<Pending<'a, TermBytes, K>, Error>
where
    P: Encrypt,
    D: IntoPrfContext<'c>,
{
    value
        .visit(OneScalar::new(
            |ty: Option<Logical>, value: Physical<'_>| {
                scalar_term(cipher, kind, ty, value, context, purpose)
            },
        ))
        .map_err(|refused| {
            refused.0.unwrap_or(Error::Term {
                field: None,
                kind: kind.clone(),
            })
        })
}

/// The term of one scalar: [`IndexSpec::takes`] decides whether there is
/// one, and each arm is the operation a Rust caller would have named for
/// the scalar's type, so the bytes are the typed path's.
///
/// `None` is a scalar the index does not take; the caller names the index.
fn scalar_term<'a, 'c, K: 'static, D>(
    cipher: &'a KeysetCipher<'_, K>,
    kind: &IndexSpec,
    ty: Option<Logical>,
    value: Physical<'_>,
    context: NonEmpty<D>,
    purpose: Use,
) -> Result<Pending<'a, TermBytes, K>, Option<Error>>
where
    D: IntoPrfContext<'c>,
{
    if !kind.takes(ty, &value) {
        return Err(None);
    }
    let unnormalized = |error: NormalizeError| Some(Error::Cipher(TermError::from(error).into()));
    match kind {
        IndexSpec::Equality => {
            let normalized = normalize(ty, value).map_err(unnormalized)?;
            Ok(cipher
                .equality_term_normalized(normalized, context)
                .map(|term| TermBytes(term.into_bytes().to_vec())))
        }
        IndexSpec::Match(options) => {
            let Physical::Text(text) = value else {
                return Err(None);
            };
            if purpose == Use::Query {
                // The query chain's rule, from the same helper: options the
                // index cannot use, then text the index cannot normalize or
                // that cuts no token.
                let _tokens = QueryTokens::of_query(text, options)
                    .map_err(|error| Some(Error::Cipher(error.into())))?;
            }
            Ok(cipher
                .match_terms_under::<DefaultMatch>(text, context, options.clone())
                .map(|terms| TermBytes(terms.to_bytes())))
        }
        IndexSpec::Ore => ore_of(cipher, value, context).ok_or(None),
        IndexSpec::Ope => ope_of(cipher, value, context).ok_or(None),
    }
}

/// [`IndexSpec::Ore`] per scalar, each handed to the CLLW encryptor as the
/// Rust type the typed path would have named; `None` for a scalar it does
/// not order ([`ordered`]).
///
/// Text and bytes are copied out of the walk into a `Zeroizing` wrapper,
/// and the encryptor is handed the wrapper itself: the CLLW encryptors take
/// their value by `'static` ownership (the visitor carries it), so a bare
/// `String` or `Vec<u8>` would be freed with the plaintext still in it, in
/// a guest's linear memory, where the host can read it.
///
/// Text is ordered as its raw UTF-8, not in the Unicode 16 NFC that
/// equality and match terms use: `café` written precomposed and with a
/// combining accent is one value to `=` and two to an ordering. A known
/// gap, to close with block ORE (#1140).
fn ore_of<'a, 'c, K: 'static, D>(
    cipher: &'a KeysetCipher<'_, K>,
    value: Physical<'_>,
    context: NonEmpty<D>,
) -> Option<Pending<'a, TermBytes, K>>
where
    D: IntoPrfContext<'c>,
{
    Some(match value {
        Physical::Int(Int::I8(v)) => ore(cipher, v, context),
        Physical::Int(Int::I16(v)) => ore(cipher, v, context),
        Physical::Int(Int::I32(v)) => ore(cipher, v, context),
        Physical::Int(Int::I64(v)) => ore(cipher, v, context),
        Physical::Int(Int::I128(v)) => ore(cipher, v, context),
        Physical::Int(Int::U8(v)) => ore(cipher, v, context),
        Physical::Int(Int::U16(v)) => ore(cipher, v, context),
        Physical::Int(Int::U32(v)) => ore(cipher, v, context),
        Physical::Int(Int::U64(v)) => ore(cipher, v, context),
        Physical::Int(Int::U128(v)) => ore(cipher, v, context),
        Physical::Float(Float::F32(v)) => ore(cipher, v, context),
        Physical::Float(Float::F64(v)) => ore(cipher, v, context),
        Physical::Text(t) => ore(cipher, Zeroizing::new(t.to_owned()), context),
        Physical::Bytes(b) => ore(cipher, Zeroizing::new(b.to_vec()), context),
        _ => return None,
    })
}

/// [`IndexSpec::Ope`] per scalar; see [`ore_of`].
fn ope_of<'a, 'c, K: 'static, D>(
    cipher: &'a KeysetCipher<'_, K>,
    value: Physical<'_>,
    context: NonEmpty<D>,
) -> Option<Pending<'a, TermBytes, K>>
where
    D: IntoPrfContext<'c>,
{
    Some(match value {
        Physical::Int(Int::I8(v)) => ope(cipher, v, context),
        Physical::Int(Int::I16(v)) => ope(cipher, v, context),
        Physical::Int(Int::I32(v)) => ope(cipher, v, context),
        Physical::Int(Int::I64(v)) => ope(cipher, v, context),
        Physical::Int(Int::I128(v)) => ope(cipher, v, context),
        Physical::Int(Int::U8(v)) => ope(cipher, v, context),
        Physical::Int(Int::U16(v)) => ope(cipher, v, context),
        Physical::Int(Int::U32(v)) => ope(cipher, v, context),
        Physical::Int(Int::U64(v)) => ope(cipher, v, context),
        Physical::Int(Int::U128(v)) => ope(cipher, v, context),
        Physical::Float(Float::F32(v)) => ope(cipher, v, context),
        Physical::Float(Float::F64(v)) => ope(cipher, v, context),
        Physical::Text(t) => ope(cipher, Zeroizing::new(t.to_owned()), context),
        Physical::Bytes(b) => ope(cipher, Zeroizing::new(b.to_vec()), context),
        _ => return None,
    })
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

/// A sink that takes one scalar and hands it to `F`, and refuses anything
/// else: a sequence, a map or a passthrough has no term.
///
/// It refuses with [`Refused`], whose `None` is "not a scalar this index
/// takes" (the caller names the index) and whose `Some` is the error `F`
/// returned or the walk failed with.
pub(super) struct OneScalar<F>(F);

impl<F> OneScalar<F> {
    pub(super) fn new(f: F) -> Self {
        Self(f)
    }
}

/// Why a [`OneScalar`] walk stopped. A source that fails (an [`FfiValue`]
/// string that is not UTF-8, which its construction rules out) is `None`,
/// as a value with no term is.
pub(super) struct Refused(pub(super) Option<Error>);

impl SinkError for Refused {
    fn source(_: SourceError) -> Self {
        Self(None)
    }
}

impl<T, F> Sink for OneScalar<F>
where
    F: FnOnce(Option<Logical>, Physical<'_>) -> Result<T, Option<Error>>,
{
    type Ok = T;
    type Error = Refused;
    type Seq = NoContainer<T>;
    type Map = NoContainer<T>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<T, Refused> {
        (self.0)(ty, value).map_err(Refused)
    }

    fn seq(self, _: Option<usize>) -> Result<NoContainer<T>, Refused> {
        Err(Refused(None))
    }

    fn map(self, _: Option<usize>) -> Result<NoContainer<T>, Refused> {
        Err(Refused(None))
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<T, Refused> {
        Err(Refused(None))
    }
}

/// The container sinks a [`OneScalar`] never makes: it refuses a sequence
/// or a map before one exists, so this type has no values and its methods
/// cannot be called.
pub(super) enum NoContainer<T> {
    #[allow(dead_code)]
    Never(Infallible, PhantomData<T>),
}

impl<T> NoContainer<T> {
    fn unreachable(&self) -> ! {
        match *self {
            NoContainer::Never(never, _) => match never {},
        }
    }
}

impl<T> Sink for NoContainer<T> {
    type Ok = T;
    type Error = Refused;
    type Seq = Self;
    type Map = Self;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<T, Refused> {
        self.unreachable()
    }

    fn seq(self, _: Option<usize>) -> Result<Self, Refused> {
        self.unreachable()
    }

    fn map(self, _: Option<usize>) -> Result<Self, Refused> {
        self.unreachable()
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<T, Refused> {
        self.unreachable()
    }
}

impl<T> SeqSink for NoContainer<T> {
    type Ok = T;
    type Error = Refused;
    type Element<'s>
        = Self
    where
        Self: 's;

    fn element(&mut self) -> Result<Self, Refused> {
        self.unreachable()
    }

    fn end(self) -> Result<T, Refused> {
        self.unreachable()
    }
}

impl<T> MapSink for NoContainer<T> {
    type Ok = T;
    type Error = Refused;
    type Entry<'s>
        = Self
    where
        Self: 's;

    fn entry(&mut self, _: &str) -> Result<Self, Refused> {
        self.unreachable()
    }

    fn end(self) -> Result<T, Refused> {
        self.unreachable()
    }
}

/// A dynamic error, where an operation's pending can only carry the crate's.
/// A cipher error is already the crate's, and passes through unchanged, so a
/// term the scheme refused (text that does not normalize) keeps its kind;
/// boxing it would report it as an internal failure.
fn lifted(error: Error) -> crate::Error {
    match error {
        Error::Cipher(error) => error,
        other => crate::Error::Other(Box::new(other)),
    }
}

/// An [`IndexSpec`] is an [`Index`] of a [`ValueFrame`]: the index named as
/// data, over a plaintext whose type is known only when it arrives. Its
/// `operation` is [`term`]'s derivation wrapped as a description, which
/// walks the frame in place to its one scalar, so a field lowered from data
/// runs through the same `indexed()` and `zip` every other field does, and
/// its term is a [`TermBytes`]. A Rust chain over `ValueFrame` fields names
/// its indexes this way too (`(IndexSpec::Equality, IndexSpec::Ore)`), and is
/// then the same declaration as a data plan's.
///
/// A value the index does not take (a container, a boolean under ORE)
/// fails the description when it runs, with the dynamic [`Error::Term`]
/// inside [`crate::Error::Other`]; a plan lowered from data refuses it
/// before that, at its boundary ([`admits`](super::admits)).
impl Index<ValueFrame> for IndexSpec {
    type Term = TermBytes;
    fn spec(&self) -> IndexSpec {
        self.clone()
    }
    fn operation<'s, K: 'static, M: ConsumeSource<'s, ValueFrame>>(
        &self,
    ) -> Encryption<'s, ValueFrame, TermBytes, K, CallerContext, M> {
        let spec = self.clone();
        chosen(move |source: M::Source, cipher, cx: CallerContext| {
            let context = match cx.validated() {
                Ok(context) => context,
                Err(error) => return Pending::failed(cipher, error),
            };
            match derive(cipher, M::view(&source), &spec, context, Use::Store) {
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
    use crate::sem::TermError;
    use crate::{nonempty, StackCipher};
    use stack_kms::FakeDataKeySource;
    use vitaminc_aead::plaintext::Raw;
    use vitaminc_protected::Controlled;

    async fn cipher() -> StackCipher<FakeDataKeySource> {
        StackCipher::builder()
            .kms(FakeDataKeySource::new())
            .init()
            .await
            .expect("build cipher")
    }

    /// A pair the scheme refuses fails the run of `IndexSpec`'s public
    /// `Index<ValueFrame>` with the dynamic `Error::Term` inside the crate
    /// error, and requests nothing: the record path refuses such a pair at
    /// its boundary, a Rust caller running the index directly meets it here.
    #[tokio::test]
    async fn a_refused_pair_fails_the_index_when_it_runs() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let ctx = || CallerContext::from(nonempty!("users/age"));
        for (what, value, kind) in [
            (
                "a boolean under equality",
                FfiValue::Bool(true),
                IndexSpec::Equality,
            ),
            (
                "an integer under match",
                FfiValue::UInt32(34),
                default_match(),
            ),
            ("a boolean under ore", FfiValue::Bool(true), IndexSpec::Ore),
            (
                "a container under ope",
                FfiValue::Array(vec![FfiValue::UInt32(1)]),
                IndexSpec::Ope,
            ),
        ] {
            let refused = keyset
                .run(
                    Index::<ValueFrame>::operation::<FakeDataKeySource, crate::target::Owned>(
                        &kind,
                    ),
                    vf(value),
                    ctx(),
                )
                .await;
            match refused {
                Err(crate::Error::Other(inner)) => assert!(
                    matches!(
                        inner.downcast_ref::<Error>(),
                        Some(Error::Term { kind: refused_kind, .. }) if *refused_kind == kind
                    ),
                    "{what}: the lifted error names the index: {inner:?}"
                ),
                other => panic!("{what}: expected the lifted Error::Term, got {other:?}"),
            }
        }
    }

    /// A term the scheme refuses while a record is written keeps its kind:
    /// text that does not normalize (a code point unassigned in Unicode 16)
    /// under equality or match is the cipher's `TermError::Normalize`, which
    /// a guest reports as a term failure, not boxed as an internal error.
    #[tokio::test]
    async fn a_refused_term_in_a_record_keeps_its_kind() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        for kind in [IndexSpec::Equality, default_match()] {
            let refused = keyset
                .run(
                    Index::<ValueFrame>::operation::<FakeDataKeySource, crate::target::Owned>(
                        &kind,
                    ),
                    vf(s("a\u{0378}bc")),
                    CallerContext::from(nonempty!("users/bio")),
                )
                .await;
            assert!(
                matches!(
                    refused,
                    Err(crate::Error::Term(crate::sem::TermError::Normalize(_)))
                ),
                "{kind:?}: {refused:?}"
            );
        }
    }

    /// The query path refuses match text with no tokens; the record path,
    /// which runs the same derivation as an index of a `ValueFrame`, stores
    /// it as the empty filter. Same value, same options, two answers,
    /// because a query with no tokens would match every row and a stored
    /// value with none is matched by no query.
    #[tokio::test]
    async fn match_text_with_no_tokens_is_refused_as_a_query_and_stored_empty() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let ctx = context(s("users/bio")).expect("context");
        for text in ["", "  ", "hi"] {
            let refused = term(&keyset, &s(text), &default_match(), ctx.clone()).await;
            assert!(
                matches!(
                    refused,
                    Err(Error::Cipher(crate::Error::Term(TermError::EmptyTermText)))
                ),
                "{text:?} as a query: {refused:?}"
            );

            let stored: TermBytes = keyset
                .run(
                    Index::<ValueFrame>::operation::<FakeDataKeySource, crate::target::Owned>(
                        &default_match(),
                    ),
                    vf(s(text)),
                    CallerContext::from(nonempty!("users/bio")),
                )
                .await
                .unwrap_or_else(|error| panic!("{text:?} stores: {error}"));
            assert!(stored.as_bytes().is_empty(), "{text:?} is the empty filter");
        }
        // Text with a token is a query like any other.
        assert!(term(&keyset, &s("hello"), &default_match(), ctx)
            .await
            .is_ok());
    }

    /// Options the index cannot use are refused before the query's text is
    /// tokenised: an n-gram length of zero is `InvalidOptions`, not a panic
    /// in the tokenizer.
    #[tokio::test]
    async fn a_match_query_under_invalid_options_is_refused_not_tokenised() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let ctx = context(s("users/bio")).expect("context");
        let zero = IndexSpec::Match(MatchOptions {
            tokenizer: Tokenizer::Ngram { length: 0 },
            ..MatchOptions::default()
        });
        let refused = term(&keyset, &s("hello"), &zero, ctx).await;
        assert!(
            matches!(
                refused,
                Err(Error::Cipher(crate::Error::Term(
                    TermError::InvalidOptions(_)
                )))
            ),
            "{refused:?}"
        );
    }

    /// A `TermBytes` reads as the typed term's bytes, through every
    /// accessor: `as_bytes`, `as_ref` and `into_bytes` give the same
    /// 32 PRF bytes an `EqualityTerm` holds, for a term derived through
    /// `IndexSpec`'s `Index<ValueFrame>`.
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
                Index::<ValueFrame>::operation::<FakeDataKeySource, crate::target::Owned>(
                    &IndexSpec::Equality,
                ),
                vf(FfiValue::UInt32(34)),
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

    fn logical(ty: Logical, value: i128) -> ValueFrame {
        ValueFrame::of(Raw(Some(ty), Physical::Int(Int::I128(value)))).expect("in range")
    }

    fn decimal(mantissa: i128, scale: u8) -> ValueFrame {
        logical(Logical::Decimal { scale }, mantissa)
    }

    fn date(days: i128) -> ValueFrame {
        logical(Logical::Date, days)
    }

    fn instant(nanos: i128) -> ValueFrame {
        logical(
            Logical::Timestamp(vitaminc_aead::plaintext::TimeUnit::Nanos),
            nanos,
        )
    }

    fn vf(value: FfiValue) -> ValueFrame {
        ValueFrame::of(&value).expect("in the value model")
    }

    fn bytes(value: &[u8]) -> FfiValue {
        FfiValue::Bytes(vitaminc_protected::Protected::new(value.to_vec()))
    }

    /// One value of every scalar variant.
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

        /// The contract the derivation exists for: the bytes are the typed
        /// path's, so a probe from any language finds a Rust-written term.
        #[tokio::test]
        async fn derives_the_bytes_the_typed_path_derives() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
            let ks = &keyset;
            let dynamic = |value: FfiValue, kind: IndexSpec| {
                let ctx = ctx.clone();
                async move { term(ks, &value, &kind, ctx).await }
            };
            let eq = |t: crate::sem::EqualityTerm| t.into_bytes().to_vec();

            // Equality, per variant with an equality domain.
            macro_rules! equal {
                ($value:expr, $leaf:expr, $label:literal) => {
                    let typed = keyset.equality_term($value, nonempty!("users/x")).await;
                    assert_eq!(
                        dynamic($leaf, IndexSpec::Equality).await.expect("eq"),
                        eq(typed.expect("typed")),
                        concat!($label, " equality")
                    );
                };
            }
            equal!(-3i32, FfiValue::Int32(-3), "i32");
            equal!(-4i64, FfiValue::Int64(-4), "i64");
            equal!(34u32, FfiValue::UInt32(34), "u32");
            equal!(35u64, FfiValue::UInt64(35), "u64");
            equal!(1.5f32, FfiValue::Float32(1.5), "f32");
            equal!(2.5f64, FfiValue::Float64(2.5), "f64");
            equal!("alice".to_string(), s("alice"), "text");
            equal!(b"ab".to_vec(), bytes(b"ab"), "bytes");

            // Match, text only.
            let typed = keyset
                .match_terms::<DefaultMatch>("alice smith", nonempty!("users/x"))
                .await
                .expect("typed");
            assert_eq!(
                dynamic(s("alice smith"), default_match())
                    .await
                    .expect("match"),
                typed.to_bytes(),
                "text match"
            );

            // The ordering schemes take every scalar but a boolean; the
            // typed side is spelled once per variant because each is its
            // own type.
            macro_rules! ordered {
                ($value:expr, $leaf:expr, $label:literal) => {
                    let typed = keyset.ore_term($value, nonempty!("users/x")).await;
                    assert_eq!(
                        dynamic($leaf, IndexSpec::Ore).await.expect("ore"),
                        typed.expect("typed").as_ref().to_vec(),
                        concat!($label, " ore")
                    );
                    let typed = keyset.ope_term($value, nonempty!("users/x")).await;
                    assert_eq!(
                        dynamic($leaf, IndexSpec::Ope).await.expect("ope"),
                        typed.expect("typed").as_ref().to_vec(),
                        concat!($label, " ope")
                    );
                };
            }
            ordered!(-3i32, FfiValue::Int32(-3), "i32");
            ordered!(-4i64, FfiValue::Int64(-4), "i64");
            ordered!(34u32, FfiValue::UInt32(34), "u32");
            ordered!(35u64, FfiValue::UInt64(35), "u64");
            ordered!(1.5f32, FfiValue::Float32(1.5), "f32");
            ordered!(2.5f64, FfiValue::Float64(2.5), "f64");
            ordered!("alice".to_string(), s("alice"), "text");
            ordered!(b"ab".to_vec(), bytes(b"ab"), "bytes");
        }

        /// Equality normalizes: every integer width of one number is one
        /// term, and text in two Unicode forms of one string is one term,
        /// whichever path derives it.
        #[tokio::test]
        async fn equality_is_one_term_per_number_and_per_nfc_string() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
            let eq = |value: FfiValue| {
                let ctx = ctx.clone();
                let keyset = &keyset;
                async move {
                    term(keyset, &value, &IndexSpec::Equality, ctx)
                        .await
                        .expect("eq")
                }
            };
            let thirty_four = eq(FfiValue::UInt32(34)).await;
            for width in [
                FfiValue::Int32(34),
                FfiValue::Int64(34),
                FfiValue::UInt64(34),
            ] {
                assert_eq!(eq(width).await, thirty_four, "34 at every width");
            }
            assert_ne!(
                eq(FfiValue::Int64(-34)).await,
                thirty_four,
                "the sign counts"
            );
            assert_ne!(
                eq(FfiValue::Float64(34.0)).await,
                thirty_four,
                "a float is not the integer it equals"
            );
            let composed = eq(s("cafe\u{301}")).await;
            assert_eq!(composed, eq(s("caf\u{e9}")).await, "one string in NFC");
            assert_eq!(
                composed,
                keyset
                    .equality_term("caf\u{e9}", nonempty!("users/x"))
                    .await
                    .expect("typed")
                    .into_bytes()
                    .to_vec(),
                "the typed path normalizes too"
            );
        }

        /// A transport frame is walked in place to the term the typed path
        /// derives for the Rust value of the frame's own width: an `i8` is
        /// the `i8` term, a `u128` the `u128` term, under every index that
        /// takes an integer.
        #[tokio::test]
        async fn a_frame_derives_the_terms_its_value_does() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
            let derive = |frame: Vec<u8>, kind: IndexSpec| {
                let ctx = ctx.clone();
                let keyset = &keyset;
                async move {
                    let frame = vitaminc_aead::Frame::parse(&frame).expect("a frame");
                    term(keyset, frame, &kind, ctx).await.expect("derives")
                }
            };
            macro_rules! typed {
                ($value:expr, $label:literal) => {
                    let frame = vitaminc_aead::to_frame($value)
                        .expect("frames")
                        .risky_ref()
                        .to_vec();
                    assert_eq!(
                        derive(frame.clone(), IndexSpec::Equality).await,
                        keyset
                            .equality_term($value, nonempty!("users/x"))
                            .await
                            .expect("typed")
                            .into_bytes()
                            .to_vec(),
                        concat!($label, " eq")
                    );
                    assert_eq!(
                        derive(frame.clone(), IndexSpec::Ore).await,
                        keyset
                            .ore_term($value, nonempty!("users/x"))
                            .await
                            .expect("typed")
                            .as_ref()
                            .to_vec(),
                        concat!($label, " ore")
                    );
                    assert_eq!(
                        derive(frame, IndexSpec::Ope).await,
                        keyset
                            .ope_term($value, nonempty!("users/x"))
                            .await
                            .expect("typed")
                            .as_ref()
                            .to_vec(),
                        concat!($label, " ope")
                    );
                };
            }
            typed!(-8i8, "i8");
            typed!(-300i16, "i16");
            typed!(300u16, "u16");
            typed!(34u64, "u64");
            typed!(i128::MIN, "i128");
            typed!(u128::MAX, "u128");
            // The `UINT8` tag and its byte: no Rust source walks a `u8` as an
            // int, but a host's frame can carry one, and it is the `u8` term.
            let frame = vec![vitaminc_aead::tags::UINT8, 200];
            assert_eq!(
                derive(frame.clone(), IndexSpec::Ore).await,
                keyset
                    .ore_term(200u8, nonempty!("users/x"))
                    .await
                    .expect("typed")
                    .as_ref()
                    .to_vec()
            );
            assert_eq!(
                derive(frame.clone(), IndexSpec::Ope).await,
                keyset
                    .ope_term(200u8, nonempty!("users/x"))
                    .await
                    .expect("typed")
                    .as_ref()
                    .to_vec()
            );
            assert_eq!(
                derive(frame, IndexSpec::Equality).await,
                derive(
                    vitaminc_aead::to_frame(200u64)
                        .expect("frames")
                        .risky_ref()
                        .to_vec(),
                    IndexSpec::Equality
                )
                .await,
                "one equality term per number, whatever its width"
            );
            // A date, a timestamp and a decimal have equality terms only,
            // the ones their frame's own value derives.
            for value in [date(19_782), instant(-1), decimal(-150, 2)] {
                assert_eq!(
                    derive(value.risky_ref().to_vec(), IndexSpec::Equality).await,
                    term(&keyset, &value, &IndexSpec::Equality, ctx.clone())
                        .await
                        .expect("derives"),
                );
            }
        }

        /// vitaminc-normalize's baseline: a decimal's scale is normalised,
        /// so `1.5`, `1.50` and `1.500` are one term, and a timestamp's term
        /// is truncated to the microsecond, so two instants in one
        /// microsecond are one term and the next microsecond is another.
        /// The ciphertext keeps both exactly; only the term folds them. A
        /// date is not its day count, nor a decimal the integer it equals.
        #[tokio::test]
        async fn equality_follows_vitaminc_for_decimals_and_timestamps() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
            let eq = |value: ValueFrame| {
                let ctx = ctx.clone();
                let keyset = &keyset;
                async move {
                    term(keyset, &value, &IndexSpec::Equality, ctx)
                        .await
                        .expect("eq")
                }
            };
            let one_and_a_half = eq(decimal(15, 1)).await;
            assert_eq!(eq(decimal(150, 2)).await, one_and_a_half, "1.50 is 1.5");
            assert_eq!(eq(decimal(1500, 3)).await, one_and_a_half, "1.500 is 1.5");
            assert_ne!(eq(decimal(-15, 1)).await, one_and_a_half, "the sign counts");
            assert_ne!(eq(decimal(15, 2)).await, one_and_a_half, "0.15 is not 1.5");
            assert_eq!(
                eq(decimal(0, 0)).await,
                eq(decimal(0, 4)).await,
                "0 is 0.0000"
            );
            let micro = 1_760_662_923_123_456_000;
            let at = eq(instant(micro)).await;
            assert_eq!(eq(instant(micro + 999)).await, at, "one microsecond");
            assert_ne!(eq(instant(micro + 1_000)).await, at, "the next microsecond");
            assert_ne!(eq(instant(micro - 1)).await, at, "the microsecond before");
            assert_ne!(eq(date(1)).await, eq(date(2)).await, "two days");
            let thirty_four = eq(ValueFrame::of(34u32).expect("a value")).await;
            assert_ne!(
                eq(decimal(34, 0)).await,
                thirty_four,
                "a decimal is not its integer"
            );
            assert_ne!(
                eq(date(34)).await,
                thirty_four,
                "a date is not its day count"
            );
            for width in [
                ValueFrame::of(34i8).expect("a value"),
                ValueFrame::of(34i128).expect("a value"),
                ValueFrame::of(34u128).expect("a value"),
            ] {
                assert_eq!(eq(width).await, thirty_four, "34 at every width");
            }
        }

        #[test]
        fn defines_is_true() {
            for (label, leaf) in every_scalar() {
                let not_bool = !matches!(leaf, FfiValue::Bool(_));
                assert_eq!(
                    IndexSpec::Ore.defines(&leaf),
                    not_bool,
                    "{label} takes an ore term exactly when it is not a boolean"
                );
                assert_eq!(
                    IndexSpec::Ope.defines(&leaf),
                    not_bool,
                    "{label} takes an ope term exactly when it is not a boolean"
                );
                assert_eq!(
                    IndexSpec::Equality.defines(&leaf),
                    not_bool,
                    "{label} takes an equality term exactly when it has a domain"
                );
                assert_eq!(
                    default_match().defines(&leaf),
                    matches!(leaf, FfiValue::String(_)),
                    "{label} takes a match term exactly when it is text"
                );
            }
        }
    }

    mod given_a_pair_the_scheme_refuses {
        use super::*;

        /// `term` refuses exactly what `defines` refuses, with the error the
        /// table would have let a binding raise at its boundary.
        #[tokio::test]
        async fn term_is_error_term_naming_the_kind() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
            let refused = [
                ("a bool", FfiValue::Bool(true), IndexSpec::Equality),
                ("a bool", FfiValue::Bool(true), default_match()),
                ("a u32", FfiValue::UInt32(34), default_match()),
                ("bytes", bytes(b"ab"), default_match()),
                ("a bool", FfiValue::Bool(true), IndexSpec::Ore),
                ("a bool", FfiValue::Bool(false), IndexSpec::Ope),
            ];
            for (label, leaf, kind) in refused {
                assert!(!kind.defines(&leaf), "{label} must not take a {kind} term");
                let result = term(&keyset, &leaf, &kind, ctx.clone()).await;
                assert!(
                    matches!(&result, Err(Error::Term { kind: k, .. }) if *k == kind),
                    "{label} asked for a {kind} term must be refused as that kind: {result:?}"
                );
            }
        }

        /// A decimal, a date and a timestamp have an equality term, from
        /// vitaminc, and no order term yet: their order encodings wait for
        /// new cllw-ore and ore-rs releases (#1236), and the engine does not
        /// shim around cllw-ore 0.5.
        #[tokio::test]
        async fn a_decimal_date_or_timestamp_has_no_order_term_yet() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
            for leaf in [decimal(150, 2), date(19_782), instant(7)] {
                for kind in [IndexSpec::Ore, IndexSpec::Ope] {
                    assert!(!kind.defines(&leaf), "{kind}");
                    assert!(matches!(
                        term(&keyset, &leaf, &kind, ctx.clone()).await,
                        Err(Error::Term { .. })
                    ));
                }
                assert!(IndexSpec::Equality.defines(&leaf));
                assert!(term(&keyset, &leaf, &IndexSpec::Equality, ctx.clone())
                    .await
                    .is_ok());
            }
        }

        /// Text with a code point unassigned in Unicode 16 has a domain but
        /// no normal form, so equality and match refuse it when they derive.
        #[tokio::test]
        async fn text_that_does_not_normalize_is_refused_when_derived() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
            for kind in [IndexSpec::Equality, default_match()] {
                let unassigned = s("a\u{378}b");
                assert!(kind.defines(&unassigned), "{kind} takes text");
                let result = term(&keyset, &unassigned, &kind, ctx.clone()).await;
                assert!(
                    matches!(
                        result,
                        Err(Error::Cipher(crate::Error::Term(TermError::Normalize(
                            NormalizeError::UnassignedCodePoint
                        ))))
                    ),
                    "{kind}: {result:?}"
                );
            }
        }
    }

    mod given_a_value_that_is_not_a_scalar {
        use super::*;

        #[tokio::test]
        async fn term_is_error_term_naming_the_kind() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let ctx = context(s("users/x")).expect("context");
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
                    assert!(!kind.defines(&value), "{label} has no {kind} term");
                    let result = term(&keyset, &value, &kind, ctx.clone()).await;
                    assert!(
                        matches!(&result, Err(Error::Term { kind: k, .. }) if *k == kind),
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
                let error = IndexSpec::from_value(&wire).expect_err(label);
                let reason = if label == "an option twice" {
                    Reason::RepeatedKey
                } else {
                    Reason::UnknownOutput
                };
                assert!(
                    matches!(error, Error::Plan { field: None, .. }),
                    "{label}: {error:?}"
                );
                assert_eq!(error.reason(), Some(reason), "{label}");
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
            let text = || s("Alice Smith");
            let wide = term(
                &keyset,
                &text(),
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
            let default = term(&keyset, &text(), &default_match(), ctx)
                .await
                .expect("default");
            assert_ne!(wide, default, "other options derive other terms");
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
            Index::<String>::spec(&Match),
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
        let spec = Index::<String>::spec(&Match);
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
