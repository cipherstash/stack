//! Encrypt and decrypt one value whose type is only known when the code
//! runs.
//!
//! [`KeysetCipher::encrypt`] encrypts one value of a Rust type into one
//! [`Ciphertext`]. [`KeysetCipher::decrypt`] decrypts that ciphertext into a
//! Rust type. This documentation names those two methods the typed calls. A
//! language binding has no Rust type to name. So this module has the same
//! two operations for a value that arrives as a frame.
//!
//! # Terms
//!
//! - A *frame* is one value written as bytes, in the format that the engine
//!   reads. A [`Frame`] borrows those bytes. An [`OwnedFrame`] owns them,
//!   and wipes them when it is dropped.
//! - A *scalar* is one value that has no parts: text, a number, a boolean,
//!   bytes, a date, a timestamp, a decimal, or a UUID.
//! - A *kind* is the name of what a value is, such as `string`, `int64`, or
//!   `timestamp`. [`ValueKind`] lists the kinds.
//! - A *leaf* is the encrypted form of one scalar or of one null. A
//!   [`Ciphertext`] contains exactly one leaf.
//! - A *context* is data that is authenticated with a value. The
//!   ciphertext does not store the context, so decrypting needs the same
//!   context.
//! - A *key request* is one request to the key service for data keys.
//! - A *refusal* is an error that a function returns for a value it does not
//!   accept.
//!
//! # The functions
//!
//! - [`encrypt`] encrypts the one scalar in a frame. The typed
//!   `keyset.decrypt` decrypts the result. So every language can decrypt a
//!   value that one language encrypted.
//! - [`decrypt`] decrypts a ciphertext into an [`OwnedFrame`] of one scalar.
//! - [`encrypt_with_context`] and [`decrypt_with_context`] do the same with
//!   a context.
//!
//! # Many values in one key request
//!
//! Each call returns a [`Pending`]. A `Pending` is a prepared call. The key
//! request of a `Pending` is not sent until the `Pending` is awaited.
//!
//! To encrypt or decrypt many values, make one call for each value. Then
//! merge the results with [`Pending::all`]. Awaiting the merged call makes
//! one key request for each keyset, and returns the results in the order of
//! the calls.
//!
//! Each value has its own declared kind and its own context. So one merged
//! call can contain values of different kinds. The examples on [`encrypt`]
//! and [`decrypt`] show how.
//!
//! # The declared kind
//!
//! Each function takes an optional [`ValueKind`]. That is the declared kind:
//! the kind that the caller says the value has.
//!
//! When [`encrypt`] has a declared kind, it stores the value as that kind.
//! `encrypt` converts a number of another width or kind when the conversion
//! is exact. The conversion rules are those of [`read`](super::read), the
//! function that reads a typed field of a record.
//!
//! For example, a JavaScript `34` arrives as a float. `encrypt` stores it as
//! the integer `34` when the caller declares `uint64`. With no declared
//! kind, `encrypt` stores the scalar as it arrived.
//!
//! When [`decrypt`] has a declared kind, the value must have been stored as
//! that kind. `decrypt` converts nothing, and refuses a value that was
//! stored as another kind. With no declared kind, `decrypt` returns the
//! value as it was stored.
//!
//! # A JSON document
//!
//! The kind [`ValueKind::Json`] is a JSON document.
//!
//! [`encrypt`] takes the JSON text of the document, as a text value or a
//! bytes value in the frame. `encrypt` checks the text by the engine's JSON
//! rules. `encrypt` then stores the document as
//! `keyset.encrypt(JsonPlaintext)` stores a [`JsonPlaintext`].
//!
//! [`decrypt`] returns the JSON text of the document as a bytes value in the
//! frame. A `json` field of a record decrypts to the same form
//! ([`json_frame`](super::json_frame)).
//!
//! `json` is a declared kind and not a stored kind. The engine stores a
//! document as its JSON text, in the same stored form as a `string`. So a
//! check of the stored kind cannot distinguish `string` from `json`:
//!
//! - An encrypted document decrypts as `string`. The frame contains the JSON
//!   text that was stored.
//! - An encrypted string decrypts as `json` when its text is a JSON
//!   document. The string `42` is a document. So is `"ada"` with its quotes.
//!   The string `ada` is not a document, so `decrypt` refuses it.
//!
//! [`decrypt`] with the kind `json` checks that the text parses by the
//! engine's JSON rules. `decrypt` then returns the document as the engine
//! writes it: with no whitespace between tokens, and with each number in its
//! shortest form. So when a value was encrypted as a string, the text that
//! `decrypt` returns as `json` can differ from the text that was encrypted.
//!
//! # What is refused
//!
//! A [`Ciphertext`] contains one scalar. So [`encrypt`] refuses an array, an
//! object, a passthrough, and a null. A passthrough is a value that a record
//! stores without encrypting it. `encrypt` returns each refusal before it
//! requests any key.
//!
//! The typed call cannot encrypt a null either: `Option<T>` is not an
//! [`OpaqueEncode`](crate::OpaqueEncode) type. Store an absent value as a
//! database `NULL`. Or encrypt it in a record, where the field declares how
//! a null is stored ([`NullMode`](super::NullMode)).
//!
//! [`encrypt`] also refuses JavaScript's `undefined`, with any declared kind
//! or with none. An `undefined` value is most often a misspelt property
//! name. No typed call could decrypt it.
//!
//! A logical type is a meaning that the frame format gives to a plain
//! scalar, such as a date stored as an integer. A scalar can have a logical
//! type that this build does not define. Such a scalar has no kind. The frame
//! format and the leaf format record an unknown logical type by its numeric
//! id. So an older build can store and return a value of a type that a newer
//! build added.
//!
//! - With no declared kind, [`encrypt`] stores such a scalar as it arrived.
//!   [`decrypt`] returns it only when no kind is declared.
//! - With a declared kind, [`encrypt`] refuses such a scalar.
//!
//! A refusal names the kind of value that was found. A refusal never
//! contains the value.
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

/// Encrypt the one scalar in `value` as one [`Ciphertext`], with the empty
/// context.
///
/// [`KeysetCipher::decrypt`] and [`decrypt`] both decrypt the result. `kind`
/// is the kind that the caller declares for the value. Pass `None` to store
/// the scalar as it arrived. The [module docs](self) describe how a declared
/// kind converts a value, and how a JSON document is stored.
///
/// `encrypt` reads the frame before it returns. The pending call keeps only
/// the value in the form that will be encrypted, in a buffer that is wiped.
/// The caller still owns the frame, and wipes it when the caller no longer
/// needs it. An [`OwnedFrame`] wipes its bytes when it is dropped.
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
/// // A binding has the value as a frame. A JavaScript number is a float.
/// let age = OwnedFrame::of(34.0f64)?;
///
/// // The caller declares the kind, so the value is stored as an integer.
/// let stored = value::encrypt(&keyset, age.frame(), Some(ValueKind::UInt64))?.await?;
///
/// // The typed call decrypts it.
/// let typed: u64 = keyset.decrypt(stored.clone()).await?;
/// assert_eq!(typed, 34);
///
/// // `value::decrypt` decrypts it too, into a frame of the declared kind.
/// let opened = value::decrypt(&keyset, stored, Some(ValueKind::UInt64)).await?;
/// assert_eq!(opened.frame(), OwnedFrame::of(34u64)?.frame());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// # Many values in one key request
///
/// Call `encrypt` for each value, then merge the pending calls with
/// [`Pending::all`]. Awaiting the merged call makes one key request for
/// every value. No key is requested before that. The ciphertexts come back
/// in the order of the calls.
///
/// Each value gets its own data key. Each value is authenticated separately.
/// Each call takes its own declared kind, so one merged call can contain
/// values of different kinds.
///
/// `encrypt` returns `Err` for a refused value before any call is merged. So
/// a set of values with one refused value requests no key.
///
/// ```
/// use stack_encrypt::dynamic::{frame::OwnedFrame, value, ValueKind};
/// use stack_encrypt::{Pending, StackCipher};
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
/// // Three values, each with the kind the caller declares for it.
/// let values = [
///     (OwnedFrame::of(34.0f64)?, Some(ValueKind::UInt64)),
///     (OwnedFrame::of("ada@example.com")?, Some(ValueKind::String)),
///     (OwnedFrame::of(true)?, None),
/// ];
///
/// // One call for each value. A refused value returns here, before any
/// // key request.
/// let mut calls = Vec::new();
/// for (frame, kind) in &values {
///     calls.push(value::encrypt(&keyset, frame.frame(), *kind)?);
/// }
///
/// // One key request for all three.
/// let stored = Pending::all(&keyset, calls).await?;
/// assert_eq!(stored.len(), 3);
///
/// let age: u64 = keyset.decrypt(stored[0].clone()).await?;
/// assert_eq!(age, 34);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// # Errors
///
/// `encrypt` returns [`Error::Value`] before it requests any key. The reason
/// in the error is one of these:
///
/// - [`Reason::Array`], [`Reason::Object`], [`Reason::Passthrough`], or
///   [`Reason::Null`] for a value that is not one scalar. A typed null is a
///   null.
/// - [`Reason::Undefined`] for JavaScript's `undefined`, with a declared
///   kind or with none.
/// - [`Reason::FieldType`] for a value of another kind that does not convert
///   exactly to the declared kind.
/// - [`Reason::JsonSyntax`], [`Reason::JsonDuplicateKey`], or
///   [`Reason::JsonIntegerRange`] for text that is not a JSON document, when
///   the declared kind is [`ValueKind::Json`].
///
/// The error names no field and contains no part of the value. When the
/// pending call fails, the error is the engine's [`Error`](crate::Error), as
/// it is for [`KeysetCipher::encrypt`].
///
/// [`KeysetCipher::encrypt`]: crate::KeysetCipher::encrypt
/// [`KeysetCipher::decrypt`]: crate::KeysetCipher::decrypt
pub fn encrypt<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    value: Frame<'_>,
    kind: Option<ValueKind>,
) -> Result<Pending<'a, Ciphertext, K>, Error> {
    seal(keyset, value, kind, ().into_context())
}

/// Encrypt as [`encrypt`] does, and authenticate `context` with the value.
///
/// [`KeysetCipher::encrypt_with_context`] does the same for a typed value.
/// Decrypting needs the same context.
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
/// The errors of [`encrypt`]. A context that cannot be used fails the
/// pending call, as it does for the typed call.
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

/// Decrypt a [`Ciphertext`] that was encrypted with the empty context. The
/// result is a frame that contains the one scalar.
///
/// `decrypt` decrypts a ciphertext from [`encrypt`] or from
/// [`KeysetCipher::encrypt`]. `kind` is the kind that the value must have
/// been stored as. Pass `None` to take the value as it was stored. With
/// [`ValueKind::Json`], the frame contains the JSON text of the document as
/// a bytes value.
///
/// `string` and `json` have one stored form. So an encrypted document
/// decrypts as `string`. An encrypted string whose text is a JSON document
/// decrypts as `json`. The [section on a JSON document](self#a-json-document)
/// describes what `json` checks and returns.
///
/// Pass `&keyset` to decrypt only a ciphertext of that keyset. `decrypt`
/// then refuses a ciphertext of another keyset before it retrieves any key.
/// Pass `&cipher` to decrypt a ciphertext of any keyset that the client can
/// use.
///
/// The frame is plaintext. An [`OwnedFrame`] wipes its bytes when it is
/// dropped.
///
/// With no declared kind, a ciphertext of a null decrypts as the null frame.
/// [`encrypt`] never encrypts a null.
/// [`KeysetCipher::encrypt_tree`](crate::KeysetCipher::encrypt_tree) can
/// encrypt one.
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
/// // A ciphertext that the typed call made.
/// let stored = keyset.encrypt(String::from("ada@example.com")).await?;
///
/// // The ciphertext decrypts as the kind it was stored as.
/// let email = value::decrypt(&keyset, stored.clone(), Some(ValueKind::String)).await?;
/// assert_eq!(email.frame(), OwnedFrame::of("ada@example.com")?.frame());
///
/// // The ciphertext does not decrypt as another kind. The error names the
/// // expected kind, and nothing about the value.
/// let refused = value::decrypt(&keyset, stored, Some(ValueKind::Int64)).await;
/// assert!(matches!(refused, Err(Error::OpenedType { expected: "int64" })));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// # Many values in one key request
///
/// Call `decrypt` for each ciphertext, then merge the pending calls with
/// [`Pending::all`]. Awaiting the merged call makes one key request for each
/// keyset that the ciphertexts were encrypted under. The frames come back in
/// the order of the calls. Each call takes its own declared kind.
///
/// Pass the same cipher or keyset to `Pending::all` as to each `decrypt`. If
/// one value fails, the merged call fails with the error of that value. The
/// frames that were decrypted before that value are dropped. A dropped frame
/// wipes its bytes.
///
/// ```
/// use stack_encrypt::dynamic::{frame::OwnedFrame, value, ValueKind};
/// use stack_encrypt::{Pending, StackCipher};
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
/// // Two ciphertexts of different kinds, as a database returns them.
/// let stored = [
///     (keyset.encrypt(34u64).await?, Some(ValueKind::UInt64)),
///     (keyset.encrypt(String::from("ada@example.com")).await?, Some(ValueKind::String)),
/// ];
///
/// // One call for each ciphertext, with the kind it must decrypt as.
/// let calls: Vec<_> = stored
///     .into_iter()
///     .map(|(ciphertext, kind)| value::decrypt(&keyset, ciphertext, kind))
///     .collect();
///
/// // One key request for both.
/// let opened = Pending::all(&keyset, calls).await?;
/// assert_eq!(opened[0].frame(), OwnedFrame::of(34u64)?.frame());
/// assert_eq!(opened[1].frame(), OwnedFrame::of("ada@example.com")?.frame());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// # Errors
///
/// The pending call fails with the engine's [`Error`](crate::Error), as
/// [`KeysetCipher::decrypt`] does:
///
/// - [`ForeignKeyset`](crate::Error::ForeignKeyset) for a ciphertext of
///   another keyset, before any key is retrieved.
/// - The error of a key provider.
/// - [`Aead`](crate::Error::Aead) for a wrong context or an altered
///   ciphertext.
/// - [`OpenedType`](crate::Error::OpenedType) for a value that was stored as
///   another kind than `kind`.
/// - [`OpenedType`](crate::Error::OpenedType) for text that is not a JSON
///   document, when `kind` is `json`.
///
/// `OpenedType` names the kind that was expected. `OpenedType` never says
/// what kind the value had. A ciphertext never contains an array or an
/// object. So `decrypt` fails the same way for those two kinds, before any
/// key is retrieved.
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

/// Decrypt as [`decrypt`] does, with the context that the value was
/// encrypted with.
///
/// [`KeysetCipher::decrypt_with_context`] does the same for a typed value.
///
/// # Errors
///
/// The errors of [`decrypt`]. A context other than the one that the value
/// was encrypted with fails the pending call.
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

/// Check that `value` is one scalar that a ciphertext can contain.
///
/// # Errors
///
/// [`Error::Value`]. The reason names what was found: an array, an object, a
/// null, a passthrough, or `undefined`.
fn one_scalar(value: Frame<'_>) -> Result<(), Error> {
    let found = match value.kind() {
        Some(ValueKind::Array) => Reason::Array,
        Some(ValueKind::Object) => Reason::Object,
        Some(_) => return Ok(()),
        // A value of no kind is a null, a passthrough, `undefined`, or a
        // scalar of a logical type that this build does not define.
        None if value.is_null() => Reason::Null,
        None if value.has_passthrough() => Reason::Passthrough,
        None if is_undefined(value) => Reason::Undefined,
        // The leaf format records a logical type that this build does not
        // define. So an older build can store a value of a newer type. Such
        // a value is one scalar. `seal` stores it as it arrived.
        None => return Ok(()),
    };
    Err(Error::bad_value(found))
}

/// Whether `value` is JavaScript's `undefined`.
fn is_undefined(value: Frame<'_>) -> bool {
    value
        .visit(OneScalar::new(|ty: Option<Logical>, _: Physical<'_>| {
            Ok(ty == Some(Logical::Undefined))
        }))
        .unwrap_or(false)
}

/// Plan the encryption of one value under `context`, as the typed call plans
/// it. Both calls write the value into the same operation, so the leaf has
/// the same form.
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
            // A document arrives as text or bytes, so nothing is converted.
            let document = read_json(value).map_err(not_a_document)?;
            // The document is encrypted through a borrow. The document is
            // wiped when it is dropped here, as the typed call's owned
            // document is.
            encrypt_opaque(&document, keyset, context)
        }
        // The conversion also refuses a value that is not of the declared
        // kind. A converted value is wiped when it is dropped.
        Some(kind) => match convert(kind, value).map_err(of_one_value)? {
            Some(converted) => encrypt_opaque(converted.frame(), keyset, context),
            None => encrypt_opaque(value, keyset, context),
        },
    };
    Ok(sealed.try_map(Ciphertext::from_tree))
}

/// Turn a refusal that the shared conversion made for a record field into
/// the refusal of one value. The reason stays the same. No field is named.
fn of_one_value(error: Error) -> Error {
    match error.reason() {
        Some(reason) => Error::bad_value(reason),
        None => error,
    }
}

/// The refusal of a value that is not a document, when the declared kind is
/// `json`.
fn not_a_document(error: JsonValueError) -> Error {
    Error::bad_value(match error {
        JsonValueError::NotText => Reason::FieldType,
        JsonValueError::Text(error) => json_reason(error),
    })
}

/// The error for a value that was stored as another kind than the declared
/// kind. The error names only the declared kind.
fn not_opened_as(kind: ValueKind) -> crate::Error {
    crate::Error::OpenedType {
        expected: kind.name(),
    }
}

/// Whether a ciphertext can contain a value of `kind`. A ciphertext contains
/// one scalar, so it never contains an array or an object.
fn is_scalar_kind(kind: ValueKind) -> bool {
    !matches!(kind, ValueKind::Array | ValueKind::Object)
}

/// Decrypt one ciphertext under `context` into an [`OwnedFrame`], as the
/// typed call does. Then check the value against `kind`.
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

/// Return the decrypted `value` as a value of `kind`. For a document, that
/// is the JSON text as a bytes value. For every other kind, that is the
/// value itself.
///
/// # Errors
///
/// [`crate::Error::OpenedType`] that names `kind`, for a value of another
/// kind. A refused frame is dropped, and a dropped frame wipes its bytes.
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

/// The document in a decrypted JSON value, in the form that a `json` field
/// decrypts to: the JSON text as a bytes value.
///
/// # Errors
///
/// [`crate::Error::OpenedType`] for a value that is not text that contains a
/// document. The typed call's `JsonPlaintext` refuses the same values.
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
