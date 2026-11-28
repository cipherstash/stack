//! One value as one ciphertext, for a value whose type is known only at
//! run time.
//!
//! [`KeysetCipher::encrypt`] encrypts one value of a Rust type into one
//! [`Ciphertext`], and [`KeysetCipher::decrypt`] reads it back. A language
//! binding has no Rust type to name. It holds a value as a transport frame
//! ([`Frame`]), and knows the value's kind only when the code runs. This
//! module is the same pair of operations over a frame.
//!
//! - [`encrypt`] seals the one scalar a frame holds. The result is the
//!   [`Ciphertext`] that `keyset.encrypt` returns for the same value: the
//!   same leaf, under the same key request and the same context. So a value
//!   that one language encrypts, every other language decrypts.
//! - [`decrypt`] opens a ciphertext into an [`OwnedFrame`] that holds one
//!   scalar.
//!
//! Each has a form that takes a context ([`encrypt_with_context`],
//! [`decrypt_with_context`]) and a form that takes many values and makes
//! one key request ([`encrypt_all`], [`decrypt_all`], and the two
//! `_all_with_context` forms).
//!
//! # The declared kind
//!
//! Each function takes an optional [`ValueKind`]: the kind the caller
//! declares for the value.
//!
//! On encrypt, a declared kind is the kind the value is sealed as. A number
//! of another width or kind is converted when the conversion is exact, by
//! the rules of [`read`](super::read), which a record's typed field uses
//! too. So a JavaScript `34`, which arrives as a float, seals as the
//! integer `34` when the caller declares `uint64`. With no declared kind,
//! the scalar is sealed as it arrived.
//!
//! On decrypt, a declared kind is the kind the value must open as. Nothing
//! is converted: a value stored as another kind is refused. With no
//! declared kind, the value comes back as it was sealed.
//!
//! # A JSON document
//!
//! The kind [`ValueKind::Json`] is a JSON document. On encrypt, the frame
//! holds the document's JSON text, in a text leaf or a bytes leaf. The
//! engine checks the text by its own JSON rules and seals the document as
//! [`JsonPlaintext`] is sealed, so the ciphertext is the one
//! `keyset.encrypt(JsonPlaintext)` returns. On decrypt, the frame holds
//! the document's JSON text in a bytes leaf, as a record's `json` field
//! opens ([`json_frame`](super::json_frame)).
//!
//! `json` is a declared kind, and not a stored one. A document is stored
//! as a text leaf that holds its JSON text, which is how a `string` is
//! stored too. So `string` and `json` share one stored form, and a kind
//! check cannot tell them apart:
//!
//! - A sealed document opens as `string`. The frame holds the JSON text
//!   that was sealed.
//! - A sealed string opens as `json` when its text is a JSON document. The
//!   string `42` is one, and so is `"ada"` with its quotes. The string
//!   `ada` is not, and is refused.
//!
//! Decrypt as `json` checks that the text parses by the engine's JSON
//! rules. It then returns the document as the engine writes it, which is
//! the text a document is sealed as: no whitespace between tokens, and
//! each number in its shortest form. So for a value that was sealed as a
//! string, the text that comes back can differ from the text that was
//! sealed.
//!
//! # What is refused
//!
//! A [`Ciphertext`] holds one scalar. So [`encrypt`] refuses an array, an
//! object, a passthrough and a null before any key is requested. The typed
//! call has no form for a null either: `Option<T>` is not an
//! [`OpaqueEncode`](crate::OpaqueEncode) type. Store an absent value as a
//! database `NULL`, or seal it in a record whose field declares how
//! ([`NullMode`](super::NullMode)).
//!
//! [`encrypt`] also refuses JavaScript's `undefined`, whatever kind is
//! declared. `undefined` is most often a property name spelt wrong, and no
//! typed call could read it back.
//!
//! A scalar of a logical type that this build does not know has no kind.
//! The frame and the leaf carry such a type by its id, so that a value of
//! a newer type survives an older build. With no declared kind, it is
//! sealed as it arrived, and it opens only with no declared kind. With a
//! declared kind, it is refused.
//!
//! A refusal says which kind of value was found, and never the value.
//!
//! [`KeysetCipher::encrypt`]: crate::KeysetCipher::encrypt
//! [`KeysetCipher::decrypt`]: crate::KeysetCipher::decrypt

use vitaminc_aead::frame::{Frame, OwnedFrame};
use vitaminc_aead::plaintext::{Logical, Physical};
use vitaminc_aead::{Encrypt, IntoContext};

use super::kind::convert;
use super::term::OneScalar;
use super::{read_json, Error, JsonValueError, Reason, ValueKind};
use crate::json::inputs::json_reason;
use crate::json::JsonPlaintext;
use crate::target::core::encrypt_opaque;
use crate::target::{CipherRef, Pending, ScalarContext};
use crate::{Ciphertext, ContextPiece, DecryptFrom, KeysetCipher};

/// Encrypt the one scalar `value` holds as one [`Ciphertext`], with the
/// empty context.
///
/// The result is the ciphertext [`KeysetCipher::encrypt`] returns for the
/// same value: `keyset.decrypt::<T>` opens it, and so does [`decrypt`].
/// `kind` is the kind the caller declares for the value, or `None` to seal
/// the scalar as it arrived. The [module docs](self) say how a declared
/// kind converts a value, and how a JSON document is sealed.
///
/// The frame is read here, before this returns. The pending request holds
/// only the value as it will be sealed, in a buffer that is wiped. The
/// frame stays the caller's, to wipe when the caller is done with it. An
/// [`OwnedFrame`] wipes itself when it drops.
///
/// ```
/// use stack_encrypt::dynamic::{frame::OwnedFrame, value, ValueKind};
/// use stack_encrypt::StackCipher;
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
/// // the environment, or from the profile that `npx stash auth login` writes.
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// // A binding holds the value as a frame. A JavaScript number is a float.
/// let age = OwnedFrame::of(34.0f64)?;
///
/// // The caller declares the kind, so the value is sealed as the integer.
/// let stored = value::encrypt(&keyset, age.frame(), Some(ValueKind::UInt64))?.await?;
///
/// // The typed call reads it, as it reads a ciphertext it made itself.
/// let typed: u64 = keyset.decrypt(stored.clone()).await?;
/// assert_eq!(typed, 34);
///
/// // So does the run-time call, into a frame of the declared kind.
/// let opened = value::decrypt(&keyset, stored, Some(ValueKind::UInt64)).await?;
/// assert_eq!(opened.frame(), OwnedFrame::of(34u64)?.frame());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// # Errors
///
/// [`Error::Source`], decided here, before any key is requested:
///
/// - [`Reason::Array`], [`Reason::Object`], [`Reason::Passthrough`] or
///   [`Reason::Null`] for a value that is not one scalar. A typed null is a
///   null.
/// - [`Reason::Undefined`] for JavaScript's `undefined`, with a declared
///   kind or with none.
/// - [`Reason::FieldType`] for a value that is not of the declared kind and
///   does not convert to it exactly.
/// - [`Reason::JsonSyntax`], [`Reason::JsonDuplicateKey`] or
///   [`Reason::JsonIntegerRange`] for text that is not a document, under
///   the kind [`ValueKind::Json`].
///
/// The error names no field and holds nothing of the value. A failure of
/// the pending request is the engine's [`Error`](crate::Error), as it is
/// for [`KeysetCipher::encrypt`].
///
/// [`KeysetCipher::encrypt`]: crate::KeysetCipher::encrypt
pub fn encrypt<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    value: Frame<'_>,
    kind: Option<ValueKind>,
) -> Result<Pending<'a, Ciphertext, K>, Error> {
    seal(keyset, value, kind, ().into_context())
}

/// [`encrypt`], authenticating `context`, as
/// [`KeysetCipher::encrypt_with_context`] does. Decrypting needs the same
/// context.
///
/// ```
/// use stack_encrypt::dynamic::{frame::OwnedFrame, value};
/// use stack_encrypt::StackCipher;
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
/// // the environment, or from the profile that `npx stash auth login` writes.
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// let email = OwnedFrame::of("ada@example.com")?;
/// let stored =
///     value::encrypt_with_context(&keyset, email.frame(), None, ("users", "email"))?.await?;
///
/// let typed: String = keyset
///     .decrypt_with_context(stored, ("users", "email"))
///     .await?;
/// assert_eq!(typed, "ada@example.com");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// # Errors
///
/// As [`encrypt`]. A context that cannot be used fails the pending
/// request, as it does for the typed call.
///
/// [`KeysetCipher::encrypt_with_context`]: crate::KeysetCipher::encrypt_with_context
pub fn encrypt_with_context<'a, 'c, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    value: Frame<'_>,
    kind: Option<ValueKind>,
    context: impl IntoContext<'c>,
) -> Result<Pending<'a, Ciphertext, K>, Error> {
    seal(keyset, value, kind, context.into_context().into_owned())
}

/// Encrypt each of `values` as a [`Ciphertext`] of its own, with the empty
/// context, in one key request.
///
/// The ciphertexts come back in the order of the values. Each value has
/// its own data key and is authenticated on its own, as the elements of a
/// `Vec` are when the typed call encrypts one into a `Vec<Ciphertext>`.
/// `kind` is declared for every value. No values make no key request.
///
/// To encrypt values of different declared kinds in one key request, call
/// [`encrypt`] for each and merge the results with
/// [`Pending::all`](crate::Pending::all).
///
/// ```
/// use stack_encrypt::dynamic::{frame::OwnedFrame, value, ValueKind};
/// use stack_encrypt::StackCipher;
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
/// // the environment, or from the profile that `npx stash auth login` writes.
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// let emails = [OwnedFrame::of("ada@example.com")?, OwnedFrame::of("grace@example.com")?];
/// let stored = value::encrypt_all(
///     &keyset,
///     emails.iter().map(OwnedFrame::frame),
///     Some(ValueKind::String),
/// )?
/// .await?;
/// assert_eq!(stored.len(), 2);
///
/// let opened = value::decrypt_all(&keyset, stored, Some(ValueKind::String)).await?;
/// assert_eq!(opened[1].frame(), emails[1].frame());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// # Errors
///
/// As [`encrypt`], for the first value that is refused. Nothing is
/// requested for the values before it.
pub fn encrypt_all<'a, 'f, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    values: impl IntoIterator<Item = Frame<'f>>,
    kind: Option<ValueKind>,
) -> Result<Pending<'a, Vec<Ciphertext>, K>, Error> {
    seal_all(keyset, values, kind, ().into_context())
}

/// [`encrypt_all`], authenticating `context` for every value.
///
/// # Errors
///
/// As [`encrypt_all`]. A context that cannot be used fails the pending
/// request.
pub fn encrypt_all_with_context<'a, 'f, 'c, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    values: impl IntoIterator<Item = Frame<'f>>,
    kind: Option<ValueKind>,
    context: impl IntoContext<'c>,
) -> Result<Pending<'a, Vec<Ciphertext>, K>, Error> {
    seal_all(keyset, values, kind, context.into_context().into_owned())
}

/// Decrypt a [`Ciphertext`] that was sealed with the empty context, into a
/// frame that holds its one scalar.
///
/// It opens what [`encrypt`] and [`KeysetCipher::encrypt`] seal. `kind` is
/// the kind the value must open as, or `None` to take the value as it was
/// sealed. With [`ValueKind::Json`], the frame holds the document's JSON
/// text in a bytes leaf.
///
/// `string` and `json` share one stored form, a text leaf. So a sealed
/// document opens as `string`, and a sealed string whose text is a JSON
/// document opens as `json`. The [module docs](self#a-json-document) say
/// what `json` checks and returns.
///
/// Pass `&keyset` to open only a ciphertext of that keyset: a ciphertext
/// of another keyset is refused before any key is retrieved. Pass
/// `&cipher` to open a ciphertext of any keyset the client can use.
///
/// The frame is plaintext. It wipes its buffer when it drops.
///
/// With no declared kind, a ciphertext that holds a null opens as the null
/// frame. [`encrypt`] seals no null, but
/// [`KeysetCipher::encrypt_tree`](crate::KeysetCipher::encrypt_tree) does.
///
/// ```
/// use stack_encrypt::dynamic::{frame::OwnedFrame, value, ValueKind};
/// use stack_encrypt::{Error, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
/// // the environment, or from the profile that `npx stash auth login` writes.
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// // A ciphertext the typed call made.
/// let stored = keyset.encrypt(String::from("ada@example.com")).await?;
///
/// // It opens as the kind it was sealed as.
/// let email = value::decrypt(&keyset, stored.clone(), Some(ValueKind::String)).await?;
/// assert_eq!(email.frame(), OwnedFrame::of("ada@example.com")?.frame());
///
/// // It does not open as another kind. The error names the kind that was
/// // expected, and nothing about the value.
/// let refused = value::decrypt(&keyset, stored, Some(ValueKind::Int64)).await;
/// assert!(matches!(refused, Err(Error::OpenedType { expected: "int64" })));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// # Errors
///
/// The pending request fails with the engine's [`Error`](crate::Error), as
/// [`KeysetCipher::decrypt`] does:
/// [`ForeignKeyset`](crate::Error::ForeignKeyset) before any key is
/// retrieved, a key provider's error, or
/// [`Aead`](crate::Error::Aead) for a wrong context or an altered
/// ciphertext.
///
/// A value that was stored as another kind than `kind` is
/// [`OpenedType`](crate::Error::OpenedType). So is text that is not a JSON
/// document, opened as `json`. The error names the kind that was expected.
/// It never says what the value opened as. An array or an object is
/// refused the same way, before any key is retrieved: a ciphertext never
/// holds one.
///
/// [`KeysetCipher::encrypt`]: crate::KeysetCipher::encrypt
/// [`KeysetCipher::decrypt`]: crate::KeysetCipher::decrypt
pub fn decrypt<'a, K: 'static>(
    cipher_ref: impl Into<CipherRef<'a, K>>,
    ciphertext: Ciphertext,
    kind: Option<ValueKind>,
) -> Pending<'a, OwnedFrame, K> {
    open(cipher_ref.into(), ciphertext, kind, ().into_context())
}

/// [`decrypt`], under the context the value was encrypted with, as
/// [`KeysetCipher::decrypt_with_context`] does.
///
/// # Errors
///
/// As [`decrypt`]. Another context than the one the value was sealed with
/// fails the pending request.
///
/// [`KeysetCipher::decrypt_with_context`]: crate::KeysetCipher::decrypt_with_context
pub fn decrypt_with_context<'a, 'c, K: 'static>(
    cipher_ref: impl Into<CipherRef<'a, K>>,
    ciphertext: Ciphertext,
    kind: Option<ValueKind>,
    context: impl IntoContext<'c>,
) -> Pending<'a, OwnedFrame, K> {
    open(
        cipher_ref.into(),
        ciphertext,
        kind,
        context.into_context().into_owned(),
    )
}

/// Decrypt each of `ciphertexts` that was sealed with the empty context,
/// in one key request for each keyset they were sealed under.
///
/// The frames come back in the order of the ciphertexts. `kind` is the
/// kind every value must open as. No ciphertexts make no key request.
///
/// # Errors
///
/// As [`decrypt`], for the first ciphertext that fails. The values opened
/// before it are wiped.
pub fn decrypt_all<'a, K: 'static>(
    cipher_ref: impl Into<CipherRef<'a, K>>,
    ciphertexts: Vec<Ciphertext>,
    kind: Option<ValueKind>,
) -> Pending<'a, Vec<OwnedFrame>, K> {
    open_all(cipher_ref.into(), ciphertexts, kind, ().into_context())
}

/// [`decrypt_all`], under the context every value was encrypted with.
///
/// # Errors
///
/// As [`decrypt_all`].
pub fn decrypt_all_with_context<'a, 'c, K: 'static>(
    cipher_ref: impl Into<CipherRef<'a, K>>,
    ciphertexts: Vec<Ciphertext>,
    kind: Option<ValueKind>,
    context: impl IntoContext<'c>,
) -> Pending<'a, Vec<OwnedFrame>, K> {
    open_all(
        cipher_ref.into(),
        ciphertexts,
        kind,
        context.into_context().into_owned(),
    )
}

/// Check that `value` is one scalar a ciphertext can hold.
///
/// # Errors
///
/// [`Error::Source`] with the reason that names what was found: an array,
/// an object, a null, a passthrough or `undefined`.
fn one_scalar(value: Frame<'_>) -> Result<(), Error> {
    let found = match value.kind() {
        Some(ValueKind::Array) => Reason::Array,
        Some(ValueKind::Object) => Reason::Object,
        Some(_) => return Ok(()),
        // A value of no kind is a null, a passthrough, `undefined`, or a
        // scalar of a logical type this build does not know.
        None if value.is_null() => Reason::Null,
        None if value.has_passthrough() => Reason::Passthrough,
        None if is_undefined(value) => Reason::Undefined,
        // The leaf format carries a logical type it does not know, so that
        // a value of a newer type survives an older build. It is one
        // scalar, and it seals as it arrived.
        None => return Ok(()),
    };
    Err(Error::bad_source(found))
}

/// Whether `value` is JavaScript's `undefined`.
fn is_undefined(value: Frame<'_>) -> bool {
    value
        .visit(OneScalar::new(|ty: Option<Logical>, _: Physical<'_>| {
            Ok(ty == Some(Logical::Undefined))
        }))
        .unwrap_or(false)
}

/// Plan the seal of one value under `context`, as the typed call plans it:
/// the value is walked into the same operation, so the leaf is the same.
fn seal<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    value: Frame<'_>,
    kind: Option<ValueKind>,
    context: ContextPiece<'static>,
) -> Result<Pending<'a, Ciphertext, K>, Error> {
    one_scalar(value)?;
    let sealed = match kind {
        None => encrypt_opaque(value, keyset, context),
        Some(ValueKind::Json) => {
            // A document crosses as text or bytes, so nothing is converted.
            let document = read_json(value).map_err(not_a_document)?;
            // The document is sealed through a borrow and wiped when it
            // drops here, as the typed call's owned document is.
            encrypt_opaque(&document, keyset, context)
        }
        // The conversion also refuses a value that is not of the declared
        // kind. A converted value is wiped when it drops.
        Some(kind) => match convert(kind, value)? {
            Some(converted) => encrypt_opaque(converted.frame(), keyset, context),
            None => encrypt_opaque(value, keyset, context),
        },
    };
    Ok(sealed.try_map(Ciphertext::from_tree))
}

/// [`seal`] for each value, merged into one request.
fn seal_all<'a, 'f, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    values: impl IntoIterator<Item = Frame<'f>>,
    kind: Option<ValueKind>,
    context: ContextPiece<'static>,
) -> Result<Pending<'a, Vec<Ciphertext>, K>, Error> {
    // A refused value returns here. The pending requests of the values
    // before it are dropped, and each wipes the plaintext it planned.
    let sealed = values
        .into_iter()
        .map(|value| seal(keyset, value, kind, context.clone()))
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(Pending::all(keyset, sealed))
}

/// The refusal of a value that is not a document under the `json` kind.
fn not_a_document(error: JsonValueError) -> Error {
    Error::bad_source(match error {
        JsonValueError::NotText => Reason::FieldType,
        JsonValueError::Text(error) => json_reason(error),
    })
}

/// The refusal of a value that opened as another kind than the one
/// declared. It names the declared kind alone.
fn not_opened_as(kind: ValueKind) -> crate::Error {
    crate::Error::OpenedType {
        expected: kind.name(),
    }
}

/// Whether a ciphertext can hold a value of `kind`. A ciphertext holds one
/// scalar, so it holds no array and no object.
fn is_scalar_kind(kind: ValueKind) -> bool {
    !matches!(kind, ValueKind::Array | ValueKind::Object)
}

/// Open one ciphertext under `context`, as the typed call opens it into an
/// [`OwnedFrame`], and check the value against `kind`.
fn open<'a, K: 'static>(
    cipher_ref: CipherRef<'a, K>,
    ciphertext: Ciphertext,
    kind: Option<ValueKind>,
    context: ContextPiece<'static>,
) -> Pending<'a, OwnedFrame, K> {
    if let Some(kind) = kind.filter(|kind| !is_scalar_kind(*kind)) {
        return Pending::failed(cipher_ref, not_opened_as(kind));
    }
    let opened =
        OwnedFrame::decrypt_from_with_context(ciphertext, cipher_ref, ScalarContext::from(context));
    match kind {
        None => opened,
        Some(kind) => opened.try_map(move |value| opened_as(kind, value)),
    }
}

/// [`open`] for each ciphertext, merged into one request.
fn open_all<'a, K: 'static>(
    cipher_ref: CipherRef<'a, K>,
    ciphertexts: Vec<Ciphertext>,
    kind: Option<ValueKind>,
    context: ContextPiece<'static>,
) -> Pending<'a, Vec<OwnedFrame>, K> {
    if let Some(kind) = kind.filter(|kind| !is_scalar_kind(*kind)) {
        return Pending::failed(cipher_ref, not_opened_as(kind));
    }
    let opened = Vec::<OwnedFrame>::decrypt_from_with_context(
        ciphertexts,
        cipher_ref,
        ScalarContext::from(context),
    );
    match kind {
        None => opened,
        // A value that fails here drops the frames around it, and each
        // frame wipes its buffer when it drops.
        Some(kind) => opened.try_map(move |values| {
            values
                .into_iter()
                .map(|value| opened_as(kind, value))
                .collect()
        }),
    }
}

/// The opened `value` as a value of `kind`: the value itself, or for a
/// document its JSON text in a bytes leaf.
///
/// # Errors
///
/// [`crate::Error::OpenedType`] naming `kind`, for a value of another
/// kind. A frame that is refused is dropped, which wipes it.
fn opened_as(kind: ValueKind, value: OwnedFrame) -> Result<OwnedFrame, crate::Error> {
    if kind == ValueKind::Json {
        return document_frame(&value);
    }
    if kind.holds(value.frame().kind()) {
        Ok(value)
    } else {
        Err(not_opened_as(kind))
    }
}

/// The document a sealed JSON value holds, as a `json` field opens: its
/// JSON text in a bytes leaf.
///
/// # Errors
///
/// [`crate::Error::OpenedType`] for a value that is not a text leaf holding
/// a document. The typed call's `JsonPlaintext` refuses the same values.
fn document_frame(value: &OwnedFrame) -> Result<OwnedFrame, crate::Error> {
    let document = value
        .visit(OneScalar::new(
            |ty: Option<Logical>, value: Physical<'_>| match (ty, value) {
                (None, Physical::Text(text)) => JsonPlaintext::parse(text).map_err(|_| None),
                _ => Err(None),
            },
        ))
        .map_err(|_| not_opened_as(ValueKind::Json))?;
    super::json_frame(document.value())
}
