//! Encrypt a whole value as one ciphertext with [`OpaqueBlob`].
//!
//! Wrap a struct, map, or `Vec` in `OpaqueBlob` to encrypt all of it as one
//! [`Ciphertext`], under one data key. Decrypt it by naming
//! `OpaqueBlob<T>` as the result type.
//!
//! You must name the wrapper. [`KeysetCipher::encrypt`] encrypts only a
//! scalar, such as a `String` or an integer, and a struct passed to it
//! does not compile. The crate has no `Serialize` fallback, because a
//! fallback would choose the stored bytes of every struct without the
//! caller asking.
//!
//! ```
//! use serde::{Deserialize, Serialize};
//! use stack_encrypt::{OpaqueBlob, StackCipher};
//! use zeroize::Zeroize;
//!
//! #[derive(Serialize, Deserialize, Zeroize, PartialEq, Debug)]
//! struct Profile {
//!     name: String,
//!     age: u32,
//!     tags: Vec<String>,
//!     nickname: Option<String>,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//!
//! let profile = Profile {
//!     name: "Ada Lovelace".into(),
//!     age: 36,
//!     tags: vec!["maths".into(), "engines".into()],
//!     nickname: Some("ada".into()),
//! };
//! // `encrypt` takes ownership of the value, and wipes it before it
//! // returns the pending request.
//! let ciphertext = keyset
//!     .encrypt_with_context(OpaqueBlob::new(profile), ("users", "profile"))
//!     .await?;
//!
//! let opened: OpaqueBlob<Profile> = keyset
//!     .decrypt_with_context(ciphertext, ("users", "profile"))
//!     .await?;
//! assert_eq!(opened.get().name, "Ada Lovelace");
//! assert_eq!(opened.into_inner().tags.len(), 2);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! A blob is opaque. You cannot query anything inside it, and you decrypt
//! all of it or none of it. Use something else for these needs:
//!
//! - To encrypt each field of a struct as its own ciphertext, use the
//!   structural API ([`KeysetCipher::encrypt_tree`] and the derives).
//! - To encrypt many values in one request, use a batch
//!   ([`Pending::all`](crate::Pending::all)) or a collection (see
//!   [Collections](#collections)).
//! - To search inside a JSON document, use the [`json`](crate::json) index.
//!
//! # Collections
//!
//! The two ways to combine `Vec` and `OpaqueBlob` give different results:
//!
//! - A `Vec<OpaqueBlob<T>>` is a collection of blobs. It encrypts into a
//!   `Vec<Ciphertext>`, one ciphertext per element, through
//!   [`EncryptInto`](crate::EncryptInto). The keys for every element are
//!   requested together, and each element decrypts on its own. This suits
//!   one blob per database row. The [crate docs on
//!   collections](crate#collections) give the rules.
//! - An `OpaqueBlob<Vec<T>>` is one blob that contains the whole `Vec`. It
//!   encrypts into one `Ciphertext`.
//!
//! # The stored format
//!
//! The value is encoded with version 1 of Vitamin C's **storage profile**
//! (`vitaminc_aead_frame::storage`). The encoded bytes are sealed as one
//! **bytes leaf** of the ordinary [`SealedValue`] v1 envelope. A blob adds
//! no second envelope, no new kind of key request and no new AAD. The
//! ciphertext is the same as sealing a `Vec<u8>` that contains the encoded
//! bytes.
//!
//! The storage profile is a binary encoding that describes its own
//! structure. It uses the sealed leaf's scalar tags and the transport
//! frame's containers. It adds four things that stored bytes need:
//!
//! - a header that names the profile and its version
//! - a marker for an `Option` that is `Some`
//! - map keys that keep their kind
//! - a promise that a version's bytes never change meaning
//!
//! The specification is `STORAGE.md` in the `vitaminc-aead-frame` crate.
//! Every implementation must pass its golden corpus of test vectors. The Go
//! SDK writes and reads the same profile through `vcffi`, so a Go opaque
//! struct and a Rust `OpaqueBlob<T>` are one stored format. See [Go](#go)
//! for the type rules.
//!
//! Every blob starts with [`HEADER`]: the ASCII bytes `VCS`, then the
//! version byte, [`VERSION`]. The header is part of the plaintext, so it is
//! encrypted with the value and covered by the leaf's AEAD tag. The header
//! is what tells a blob apart from other bytes, and one version from
//! another. Nothing about a blob, including its version, is visible before
//! it is decrypted.
//!
//! ## Supported types
//!
//! To encrypt, `T` must implement `serde::Serialize` and [`Zeroize`]. To
//! decrypt, `T` must implement `serde::de::DeserializeOwned` and `Zeroize`.
//! [Cleanup](#cleanup) explains why `Zeroize` is needed. Each serde type is
//! written as follows:
//!
//! | serde type                         | Written as                                          |
//! |------------------------------------|-----------------------------------------------------|
//! | `bool`                             | bool                                                |
//! | `i8` to `i128`, `u8` to `u128`     | an integer of that exact width                      |
//! | `f32`, `f64`                       | a float of that width, by its bits, so NaN is kept  |
//! | `char`, `&str`, `String`           | text, in UTF-8                                      |
//! | bytes, with `serde_bytes`          | bytes. A `Vec<u8>` without `serde_bytes` is an array of `u8` |
//! | `()`, a unit struct, `None`        | null                                                |
//! | `Some(v)`                          | a presence marker, then `v`                         |
//! | a sequence, tuple or tuple struct  | an array                                            |
//! | a struct                           | an object, keyed by field name                      |
//! | a map                              | a map. Keys must be integers, text or bytes         |
//! | an enum                            | externally tagged: a unit variant is its name, and any other variant is an object with one entry |
//!
//! Encryption refuses these values with [`BlobError::Unwritable`]:
//!
//! - nesting deeper than 128 levels
//! - text or bytes longer than `u32::MAX`
//! - a map key that is not an integer, text, or bytes
//! - a repeated map key
//! - a container whose declared length differs from the number of
//!   children it wrote
//! - a value whose own `Serialize` fails
//!
//! The profile stores plain scalars only. A date, a timestamp, a decimal,
//! or a UUID is stored as whatever its serde impl writes. That is usually
//! text, not the matching kind of sealed leaf.
//!
//! The encoding is not canonical, so compare values, not blobs. Equal
//! values of different types write different bytes (`1u8` and `1u32`). A
//! `HashMap` writes its entries in its iteration order. A reader accepts
//! some forms that no writer produces.
//!
//! ## Versions and schema changes
//!
//! [`VERSION`] is the version of the storage profile, not of your
//! application. It covers the byte format and the serde mapping together.
//! Version 1 is frozen: no release changes what a version 1 blob reads as.
//!
//! A reader that meets a version it cannot read returns
//! [`BlobError::UnsupportedVersion`]. A damaged blob gives a different
//! error. So "upgrade the reader" and "the data is damaged" are separate
//! errors. A new version will arrive in two steps: first a
//! release that reads it, then a later release that writes it. This
//! crate's changelog will say which version each release writes.
//!
//! Your own schema changes through `T`. Serde's attributes decide how an
//! old blob reads into a new `T`:
//!
//! | Change to `T`                               | An old blob                                          |
//! |---------------------------------------------|------------------------------------------------------|
//! | Add a field with `#[serde(default)]`        | reads, with the default                              |
//! | Add a field without a default               | is refused with [`BlobError::Mismatch`]              |
//! | Remove a field                              | reads, unless `T` denies unknown fields              |
//! | Rename a field                              | reads with `#[serde(alias = "…")]`                   |
//! | Change `F` to `Option<F>`                   | reads as `Some`                                      |
//! | Change `Option<F>` to `F`                   | is refused if the blob holds `Some`                  |
//! | Add an enum variant                         | reads. An older reader refuses the new variant       |
//! | Widen an integer                            | reads. A narrower integer reads only values that fit |
//!
//! If your application needs to tell its own versions apart, store that in
//! the value, as a version field or an enum of versions. The blob header
//! does not change when `T` changes.
//!
//! ## Decryption errors
//!
//! Decryption **checks the ciphertext before it decodes the blob**. The
//! leaf is opened and authenticated first. Only then does the
//! storage profile's reader see the bytes.
//!
//! A wrong context is usually refused before that. ZeroKMS binds each data
//! key to the context it was created under, and refuses to return the key
//! for any other context. That refusal is [`Error::Kms`]. Nothing is
//! decrypted.
//!
//! After the key is returned, these errors are possible:
//!
//! - [`Error::Aead`]: the leaf did not open. The bytes were changed, or the
//!   key is wrong. In tests, a key source that ignores contexts
//!   (`FakeDataKeySource`) also gives this error for a wrong context. The
//!   blob was never read.
//! - [`Error::OpenedType`]: the leaf opened, but it is not a bytes leaf.
//!   For example, it was sealed as a `String` or an integer. The same error
//!   happens the other way round: a blob decrypted as a `String` or an
//!   integer is refused.
//! - [`Error::Blob`]: the leaf opened as bytes, but the bytes are not a
//!   blob that `T` reads. The bytes might not be a blob at all
//!   ([`BlobError::NotABlob`]). The blob might be a later version
//!   ([`BlobError::UnsupportedVersion`]) or break a rule of version 1
//!   ([`BlobError::Malformed`]). Or the blob might be valid but not a `T`
//!   ([`BlobError::Mismatch`]).
//!
//! A blob is sealed as a plain bytes leaf. Nothing in the leaf marks it as
//! a blob, so two cases are not refused by type:
//!
//! - A blob decrypted as a `Vec<u8>` succeeds, and returns the encoded
//!   blob. Nothing wipes that `Vec<u8>` on drop.
//! - A `Vec<u8>` decrypted as an `OpaqueBlob<T>` reaches the blob reader.
//!   The reader returns an [`Error::Blob`] unless the bytes are a blob.
//!
//! The AEAD still binds the context in both cases, so neither case lets a
//! caller read data they could not read before.
//!
//! [`Error::OpenedType`] and [`Error::Blob`] refuse a ciphertext that is
//! authentic. Neither error means the data was tampered with. Each means
//! the data was written as something else. Only [`Error::Aead`] and
//! [`Error::Kms`] leave the ciphertext's authenticity unknown.
//!
//! The reader checks the whole blob before `T`'s `Deserialize` sees any of
//! it. Every length is checked against the end of the blob, so a forged
//! length allocates nothing. A `Deserialize` impl never builds part of a
//! value from a malformed blob.
//!
//! No error names a text value or a map key. A mismatch names the declared
//! field it is about.
//!
//! Two errors can include a number from the data.
//! [`BlobError::UnsupportedVersion`] includes the blob's version byte. A
//! mismatch can include the length of a sequence. Only a caller with the
//! key can cause either error.
//!
//! ## What the ciphertext reveals
//!
//! A blob's ciphertext shows the length of the encoded value. The leaf is
//! encrypted with AES-256-GCM. AES-256-GCM keeps the plaintext's length. The
//! storage profile adds no padding. So the ciphertext is the encoded length
//! plus a fixed overhead.
//!
//! The encoded length depends on the value:
//!
//! - the length of each string
//! - the number of elements in each sequence and map
//! - whether each `Option` is `Some`, written as a marker and the value, or
//!   `None`, written as one null byte
//!
//! For example, two profiles that differ only in whether a nickname is
//! present seal to ciphertexts of different lengths. A `String` scalar
//! shows its length in the same way. If the size of a value must not be
//! visible, your application must pad it, for example with a fixed-length
//! field of its own.
//!
//! Serde's derived impls are not constant time. The profile's writer and
//! reader are not constant time either. Encoding takes time that depends
//! on the value, as serializing any value does.
//!
//! The cryptography is Vitamin C's. This module does not change it. The module's code runs
//! only on plaintext the caller already has. It runs before the value is
//! sealed, or after the value is opened.
//!
//! ## Cleanup
//!
//! On encrypt, these steps happen before `encrypt` returns the pending
//! request:
//!
//! 1. The owned conversion moves the `OpaqueBlob<T>` into a [`Protected`].
//! 2. The value is encoded into a [`Buffer`]. The writer wipes each old
//!    allocation as the buffer grows. It writes a `Display` value straight
//!    into the blob. If writing fails, it wipes what it wrote.
//! 3. The buffer is copied into the leaf, then dropped and wiped.
//! 4. The source is wiped through `T: Zeroize`. This also happens when
//!    encoding fails.
//!
//! The pending request contains no plaintext from the caller.
//!
//! On decrypt, the opened bytes are held in a `Protected` buffer while the
//! reader runs. The buffer is wiped when the reader returns, whether it
//! returns a value or an error. The reader borrows text and bytes from that
//! buffer instead of copying them.
//!
//! The decrypted `OpaqueBlob<T>` stores its `T` in a [`Zeroizing`], so
//! **the value is wiped when the blob is dropped**. [`into_inner`] returns the
//! `Zeroizing<T>`, not a bare `T`, so the value is still wiped on drop after
//! it leaves the blob. `Zeroizing<T>` derefs to `T`. If you move the `T`
//! out of the guard, with `mem::take` for example, you are responsible for
//! wiping it.
//!
//! [`into_inner`]: OpaqueBlob::into_inner
//!
//! One gap comes from serde and is not closed here. A derived
//! `Deserialize` might read some fields and then refuse a later one. It
//! then drops the fields it built as ordinary values, without
//! `T::zeroize`, because no `T` was ever built to wipe. The reader checks
//! the blob first, so this happens only for a valid blob of another shape
//! ([`BlobError::Mismatch`]), never for a malformed one.
//!
//! The bytes those fields were copied from are wiped with the buffer. A
//! field that wipes itself on drop closes the gap for that field. Examples
//! are a `Zeroizing<String>` field, or a type that derives `ZeroizeOnDrop`.
//!
//! A Rust move does not erase memory. A `Copy` field leaves its bytes
//! where it was moved from. Compiler temporaries are not wiped. This module
//! wipes the owned source, the encoded buffer, the opened buffer, and the
//! library's own copies. It cannot wipe every byte the program's stack
//! once held.
//!
//! # Go
//!
//! The Go SDK's opaque struct uses this format. An opaque struct is a
//! `stashgen` declaration with one `value` field, sealed as a storage blob
//! under the context `<context>/value`. A Rust program opens such a column
//! with `decrypt_with_context::<OpaqueBlob<T>>(ct, ("<context>", "value"))`.
//! `T`'s serde field names must match the Go struct's `vc` tags.
//!
//! Go reads a Rust-written blob in the same way, when the field types
//! correspond:
//!
//! - A Rust `Option<T>` is a Go `*T`. Go refuses a Rust `Some` read into a
//!   field that is not a pointer. Go also refuses a Rust `None` read into a
//!   slice, so an optional `Vec<T>` must be a Go `*[]T`.
//! - Rust must write a byte string as bytes, with
//!   `#[serde(with = "serde_bytes")]`, not as a sequence of `u8`. Go writes
//!   a `[]byte` and a UUID as bytes. Each side refuses the other side's
//!   form.
//! - Go writes a nil slice or map as an empty one. A Rust
//!   `Option<Vec<T>>` reads it as `Some` of an empty `Vec`, not `None`. This
//!   is the only pairing that changes a value without an error.
//! - Go writes a non-nil pointer as the bare value. Rust writes every
//!   `Some` with its marker. An optional field reads both forms.
//!
//! A type mismatch is [`BlobError::Mismatch`] in Rust and `ErrMismatch` in
//! Go.
//!
//! [`Error::Aead`]: crate::Error::Aead
//! [`Error::Kms`]: crate::Error::Kms
//! [`Error::OpenedType`]: crate::Error::OpenedType
//! [`Error::Blob`]: crate::Error::Blob
//! [`KeysetCipher::encrypt`]: crate::KeysetCipher::encrypt
//! [`KeysetCipher::encrypt_tree`]: crate::KeysetCipher::encrypt_tree
//! [`Ciphertext`]: crate::Ciphertext
//! [`SealedValue`]: crate::SealedValue

use std::fmt;

use serde::de::DeserializeOwned;
use serde::Serialize;
use vitaminc_aead_frame::serde::PathSegment;
use vitaminc_aead_frame::storage::{self, ErrorKind};
use vitaminc_protected::{Buffer, Controlled, Protected};
use zeroize::{Zeroize, Zeroizing};

use crate::scalar::sealed;
use crate::target::Pending;
use crate::{CipherText, Ciphertext, ContextPiece, KeysetCipher, OpaqueDecode, OpaqueEncode};
use crate::{SealedValue, StackCipher};

/// The four bytes every blob starts with: `VCS`, then [`VERSION`]. Inside
/// the plaintext, so encrypted and authenticated with the value.
pub const HEADER: [u8; 4] = storage::HEADER;

/// The storage profile version this release writes, and the only one it
/// reads. A blob of a later version is [`BlobError::UnsupportedVersion`].
pub const VERSION: u8 = storage::VERSION;

/// A whole value, encrypted as one opaque [`Ciphertext`].
///
/// Wrap the value to encrypt it (`keyset.encrypt(OpaqueBlob::new(v))`)
/// and name the wrapper to decrypt it
/// (`keyset.decrypt::<OpaqueBlob<T>>(ct)`), then [`into_inner`]. The
/// module docs give the format, its errors, what it reveals and what is
/// cleaned up.
///
/// The value is held in a [`Zeroizing`], so the wrapper wipes it when it
/// is dropped, and [`into_inner`] returns the `Zeroizing<T>` rather than a
/// bare `T`. `Zeroizing<T>` derefs to `T`, so `opened.into_inner().name`
/// reads a field and the value is still wiped when the guard is dropped.
///
/// `Debug` prints no plaintext. The wrapper has no serde impls of its own,
/// so that a blob is never written by accident where a `T` was meant.
///
/// [`into_inner`]: OpaqueBlob::into_inner
#[derive(Clone, PartialEq, Eq, Default)]
pub struct OpaqueBlob<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> OpaqueBlob<T> {
    /// Wrap a value to encrypt it whole.
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The value, still guarded: it is wiped when the returned
    /// `Zeroizing<T>` is dropped.
    pub fn into_inner(self) -> Zeroizing<T> {
        self.0
    }

    /// A borrow of the value.
    pub fn get(&self) -> &T {
        &self.0
    }

    /// A mutable borrow of the value.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> From<T> for OpaqueBlob<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize> fmt::Debug for OpaqueBlob<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueBlob(***)")
    }
}

impl<T: Zeroize> Zeroize for OpaqueBlob<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Serialize + Zeroize> OpaqueBlob<T> {
    /// The value as a storage blob: the plaintext the ciphertext seals,
    /// starting with [`HEADER`]. Returned in a [`Buffer`], and wiped when it
    /// is dropped. Encrypting does this itself; it is here for a caller that
    /// needs the bytes, to check them against another writer's, say.
    ///
    /// # Errors
    ///
    /// [`BlobError::Unwritable`] for a value the profile cannot hold.
    pub fn encode(&self) -> Result<Buffer, BlobError> {
        storage::to_vec(&*self.0).map_err(BlobError::Unwritable)
    }
}

impl<T: DeserializeOwned + Zeroize> OpaqueBlob<T> {
    /// Read a value from a storage blob: what decrypting does to the opened
    /// bytes. The caller's `bytes` are borrowed and not wiped; the opened
    /// buffer decrypting reads from is.
    ///
    /// # Errors
    ///
    /// One [`BlobError`] per class: not a blob, a later version, malformed,
    /// or a well-formed blob that is not a `T`.
    pub fn decode(bytes: &[u8]) -> Result<Self, BlobError> {
        storage::from_slice::<T>(bytes)
            .map(Self::new)
            .map_err(|error| BlobError::reading(error, bytes))
    }
}

impl<T: Serialize + Zeroize + Send + 'static> sealed::Encode for OpaqueBlob<T> {
    fn seal<'a, K: 'static>(
        &self,
        cipher: &'a KeysetCipher<'_, K>,
        context: ContextPiece<'static>,
    ) -> Pending<'a, Ciphertext, K> {
        // Refuse a context no request could carry before the value is
        // encoded, as a scalar is: no plaintext copy is made for a request
        // that cannot be sent, and the refusal is the same as a scalar's.
        if let Err(error) = crate::Descriptor::from_piece(&context).check() {
            return Pending::failed(cipher, error);
        }
        let blob = match self.encode() {
            Ok(blob) => blob,
            Err(error) => return Pending::failed(cipher, error.into()),
        };
        // Planned as one bytes leaf, synchronously: the plaintext is copied
        // into the pending's own guarded leaf here, and `blob` is wiped when
        // this returns. The caller's source is wiped by the owned conversion
        // that called us.
        crate::target::core::encrypt_opaque(blob.risky_ref().as_slice(), cipher, context)
            .try_map(Ciphertext::from_tree)
    }
}
impl<T: Serialize + Zeroize + Send + 'static> OpaqueEncode for OpaqueBlob<T> {}

impl<T: DeserializeOwned + Zeroize + Send + 'static> sealed::Decode for OpaqueBlob<T> {
    fn open<'a, K: 'static>(
        leaf: SealedValue,
        cipher: &'a StackCipher<K>,
        context: ContextPiece<'static>,
    ) -> Pending<'a, Self, K> {
        // Authenticate first: the leaf opens as bytes, into a `Protected`
        // buffer, and only then is it read as a blob. A leaf of another kind
        // is `OpenedType`; a leaf that does not open is `Aead`. The buffer
        // is wiped when `try_map`'s closure returns, value or refusal.
        crate::target::core::open_opaque::<Protected<Vec<u8>>, K, _>(
            CipherText::Single(leaf),
            cipher,
            context,
        )
        .try_map(|bytes| Self::decode(bytes.risky_ref()).map_err(crate::Error::from))
    }
}
impl<T: DeserializeOwned + Zeroize + Send + 'static> OpaqueDecode for OpaqueBlob<T> {}

/// Why an [`OpaqueBlob`] could not be written, or why an authentic
/// ciphertext did not read as one. Each class of refusal has its own
/// variant and code. The storage profile's own error is kept as the
/// source. It names kinds and declared field names, never a text value or
/// a map key.
///
/// On decrypt, every variant means the ciphertext **was authentic**: the
/// leaf opened under its key and context before the blob was read. See
/// [Decryption errors](self#decryption-errors) in the module docs.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum BlobError {
    /// The value cannot be written as a storage blob: nested deeper than
    /// 128 levels, text or bytes too long for a `u32` length, a map key
    /// that is not an integer, text or bytes, a repeated key, or a value its
    /// own `Serialize` refused. Raised before any key is requested.
    #[error("the value cannot be written as a storage blob")]
    #[diagnostic(
        code(stack_encrypt::blob_unwritable),
        help("A blob holds serde's data model with integer, text or bytes map keys, distinct keys, and at most 128 levels of nesting. The source error names the kind refused and the declared field it is under.")
    )]
    Unwritable(#[source] storage::Error),
    /// The ciphertext opened as bytes, but they do not start with
    /// [`HEADER`]'s magic: the value was sealed as plain bytes, not as a
    /// blob.
    #[error("the ciphertext opened, but it does not hold a storage blob")]
    #[diagnostic(
        code(stack_encrypt::blob_not_a_blob),
        help("The ciphertext is authentic and holds bytes that are not a storage blob. Open it as the type it was sealed as; a `Vec<u8>` sealed through the structural API is not an `OpaqueBlob`.")
    )]
    NotABlob,
    /// The ciphertext opened and holds a blob of a storage version this
    /// build does not read. The blob is not corrupt: a later release reads
    /// it, so the reader needs upgrading.
    #[error("the ciphertext opened, but it holds a storage blob of version {version}, which this build does not read")]
    #[diagnostic(
        code(stack_encrypt::blob_unsupported_version),
        help("Upgrade stack-encrypt to a release that reads this storage version. The ciphertext is authentic and the blob is intact.")
    )]
    UnsupportedVersion {
        /// The version byte the blob carries.
        version: u8,
    },
    /// The ciphertext opened and holds a blob of a version this build
    /// reads, whose body breaks a rule of that version: truncated, trailing
    /// bytes, an unknown tag, a repeated key, nested too deep. Found before
    /// the type reads anything.
    #[error("the ciphertext opened, but its storage blob is malformed")]
    #[diagnostic(
        code(stack_encrypt::blob_malformed),
        help("The ciphertext is authentic, so the blob was written this way: by a writer that does not follow the storage profile, or by sealing bytes that happen to start with its header. It cannot be read by any version 1 reader.")
    )]
    Malformed(#[source] storage::Error),
    /// The ciphertext opened and holds a well-formed blob, but not a value
    /// of the type it was opened as: a missing field, text where a number
    /// was expected, an unknown variant, an integer that does not fit. The
    /// value was written as another type, or an older or newer shape of
    /// this one.
    #[error("the ciphertext opened and holds a storage blob, but not a value of the type it was opened as")]
    #[diagnostic(
        code(stack_encrypt::blob_mismatch),
        help("The ciphertext is authentic. Open it as the type it was written as, or make the type read the old shape (`#[serde(default)]`, `#[serde(alias = \"…\")]`, an `Option`). The source error names the declared field the refusal is about, never the value.")
    )]
    Mismatch(#[source] storage::Error),
}

impl BlobError {
    /// The profile's refusal of `bytes`, in this crate's classes.
    fn reading(error: storage::Error, bytes: &[u8]) -> Self {
        match error.kind() {
            ErrorKind::NotABlob => Self::NotABlob,
            ErrorKind::UnsupportedVersion => Self::UnsupportedVersion {
                // The reader found a header and refused its version, so the
                // byte is there; the fallback is for a reader that changes
                // its mind about what counts as a header.
                version: bytes.get(HEADER.len() - 1).copied().unwrap_or(0),
            },
            ErrorKind::Mismatch => Self::Mismatch(error),
            // The reader never says `Unwritable`. A class a later profile
            // release adds is one this build has no reading for, which is
            // what a malformed blob is to it.
            ErrorKind::Malformed | ErrorKind::Unwritable | _ => Self::Malformed(error),
        }
    }

    /// The declared field names and positions from the blob's root to the
    /// node the refusal is about, as the source error records them. A map
    /// key, which is data, is never among them: such an entry is recorded
    /// by its position.
    fn path(error: &storage::Error) -> serde_json::Value {
        error
            .path()
            .iter()
            .map(|segment| match segment {
                PathSegment::Key(key) => serde_json::Value::from(key.as_str()),
                PathSegment::Index(index) => serde_json::Value::from(*index),
                PathSegment::Entry(index) => serde_json::json!({ "entry": index }),
            })
            .collect()
    }
}

impl crate::ErrorPayload for BlobError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        use crate::diagnostic::payload;
        match self {
            Self::Unwritable(error) | Self::Malformed(error) | Self::Mismatch(error) => {
                payload([("path", Self::path(error))])
            }
            Self::NotABlob => serde_json::Map::new(),
            Self::UnsupportedVersion { version } => payload([
                ("version", (*version).into()),
                ("supported", VERSION.into()),
            ]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorPayload;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Zeroize, PartialEq, Debug)]
    struct Pair {
        left: String,
        right: u32,
    }

    #[test]
    fn a_blob_starts_with_the_header_and_reads_back() {
        let pair = OpaqueBlob::new(Pair {
            left: "l".into(),
            right: 7,
        });
        let blob = pair.encode().unwrap();
        assert_eq!(&blob.risky_ref()[..4], &HEADER);
        assert_eq!(HEADER, *b"VCS\x01");
        assert_eq!(OpaqueBlob::<Pair>::decode(blob.risky_ref()).unwrap(), pair);
    }

    #[test]
    fn every_class_of_refusal_is_its_own_variant() {
        let blob = OpaqueBlob::new(Pair {
            left: "l".into(),
            right: 7,
        })
        .encode()
        .unwrap();
        let read = |bytes: &[u8]| OpaqueBlob::<Pair>::decode(bytes).unwrap_err();

        assert!(matches!(read(b""), BlobError::NotABlob));
        assert!(matches!(read(b"VC"), BlobError::NotABlob));
        assert!(matches!(read(b"{\"left\":\"l\"}"), BlobError::NotABlob));
        let later = read(b"VCS\x02\x00");
        assert!(matches!(
            later,
            BlobError::UnsupportedVersion { version: 2 }
        ));
        assert_eq!(later.payload()["version"], 2);
        assert_eq!(later.payload()["supported"], 1);
        assert!(matches!(
            read(&blob.risky_ref()[..blob.risky_ref().len() - 1]),
            BlobError::Malformed(_)
        ));
        assert!(matches!(read(b"VCS\x01\xff"), BlobError::Malformed(_)));

        // A well-formed blob of another shape names the declared field.
        #[derive(Serialize, Zeroize)]
        struct Renamed {
            left: String,
            wrong: u32,
        }
        let renamed = OpaqueBlob::new(Renamed {
            left: "l".into(),
            wrong: 7,
        })
        .encode()
        .unwrap();
        let mismatch = read(renamed.risky_ref());
        assert!(matches!(mismatch, BlobError::Mismatch(_)));
        let shown = format!("{mismatch} / {:?}", mismatch.payload());
        assert!(!shown.contains("\"l\""), "{shown}");
    }

    #[test]
    fn debug_shows_no_plaintext() {
        let blob = OpaqueBlob::new(Pair {
            left: "secret".into(),
            right: 7,
        });
        assert_eq!(format!("{blob:?}"), "OpaqueBlob(***)");
    }

    #[test]
    fn an_unwritable_value_is_refused_with_its_path() {
        use std::collections::BTreeMap;
        #[derive(Serialize, Zeroize)]
        struct Keyed {
            #[zeroize(skip)]
            by_float: BTreeMap<String, Vec<u8>>,
            #[zeroize(skip)]
            deep: serde_json::Value,
        }
        let mut deep = serde_json::Value::Null;
        for _ in 0..130 {
            deep = serde_json::Value::Array(vec![deep]);
        }
        let value = OpaqueBlob::new(Keyed {
            by_float: BTreeMap::new(),
            deep,
        });
        let error = value.encode().unwrap_err();
        assert!(matches!(error, BlobError::Unwritable(_)));
        assert_eq!(error.payload()["path"][0], "deep");
    }
}
