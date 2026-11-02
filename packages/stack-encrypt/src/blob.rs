//! A whole value as one ciphertext: [`OpaqueBlob`].
//!
//! The scalar API ([`KeysetCipher::encrypt`]) seals one scalar as one
//! [`Ciphertext`], and deliberately refuses everything else: a struct, a
//! `Vec`, a map. There is no `Serialize` fallback, because a fallback would
//! decide the stored bytes of every composite silently. `OpaqueBlob<T>` is
//! the explicit way to say "encrypt this whole value as one ciphertext":
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
//! let cipher = StackCipher::builder()
//!     .kms(stack_encrypt::kms::FakeDataKeySource::new())
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
//! // One ciphertext, one data key, one leaf: `encrypt` consumes the value
//! // and wipes it before the pending request is returned.
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
//! What this is not: it is not the structural API, which seals a struct as
//! a tree of leaves, one data key and one ciphertext per field
//! ([`KeysetCipher::encrypt_tree`], the derives); it is not a batch, which
//! is many values and many ciphertexts in one request
//! ([`Pending::all`](crate::Pending::all)); and it is not a searchable
//! document ([`json`](crate::json)). A blob is one opaque value: nothing
//! inside it can be queried, and it is read back whole or not at all.
//!
//! # The codec
//!
//! The value is encoded with Vitamin C's **storage profile**, version 1
//! (`vitaminc_aead_frame::storage`), and the encoded bytes are sealed as
//! one **bytes leaf** of the ordinary [`SealedValue`] v1 envelope. Nothing
//! else is new: no second envelope, no new key request, no new AAD. The
//! encoded blob is what the ciphertext would hold if the caller had sealed
//! a `Vec<u8>` holding those bytes.
//!
//! The profile is a self-describing binary encoding built from the sealed
//! leaf's own scalar tags and the transport frame's containers, with four
//! things added for bytes that are kept: a header naming the profile and
//! its version, a marker for a present `Option`, map keys that keep their
//! kind, and a compatibility commitment. Its specification is normative and
//! lives with the crate that implements it (`STORAGE.md` in
//! `vitaminc-aead-frame`), pinned by a golden corpus every implementation
//! must pass. The Go SDK writes and reads the same profile through `vcffi`:
//! a Go opaque struct and a Rust `OpaqueBlob<T>` are one stored format.
//!
//! Every blob starts with [`HEADER`]: the ASCII bytes `VCS`, then the
//! version byte [`VERSION`]. The header is inside the plaintext, so it is
//! encrypted with the value and authenticated by the leaf's AEAD tag: it is
//! the authenticated discriminator that tells a blob from any other bytes
//! leaf, and its version from any later one. Nothing about a blob, its
//! version included, is visible before decryption.
//!
//! ## Supported types
//!
//! `T` is any `serde::Serialize` type to encrypt and any
//! `serde::de::DeserializeOwned` type to decrypt, in both cases also
//! [`Zeroize`] (see [Cleanup](#cleanup)). The mapping is serde's data
//! model, with these rules:
//!
//! | serde                              | blob node                                           |
//! |------------------------------------|-----------------------------------------------------|
//! | `bool`                             | bool                                                |
//! | `i8`…`i128`, `u8`…`u128`           | an integer of that exact width (`u8` is admitted)   |
//! | `f32`, `f64`                       | a float of that width, by its bits (NaN kept)       |
//! | `char`, `&str`, `String`           | text (UTF-8)                                        |
//! | bytes (`serde_bytes`)              | bytes; a `Vec<u8>` without it is an array of `u8`   |
//! | `()`, unit struct, `None`          | null                                                |
//! | `Some(v)`                          | a presence marker, then `v`                         |
//! | sequence, tuple, tuple struct      | array                                               |
//! | struct                             | object, by field name                               |
//! | map                                | map; keys must be integers, text or bytes           |
//! | enum                               | externally tagged: a unit variant is its name, any other an object of one entry |
//!
//! Refused when writing ([`BlobError::Unwritable`]): nesting deeper than
//! 128 levels, text or bytes longer than `u32::MAX`, a map key of another
//! kind, a repeated key, a container whose declared length is not the
//! number of children it wrote, or a value its own `Serialize` refused.
//! The profile carries plain scalars only: the logical types the sealed
//! leaf has (a date, a timestamp, a decimal, a UUID) are carried as what
//! their serde impls write (text, usually), not as those leaf kinds.
//!
//! Blobs are not canonical. Equal values of different types write
//! different bytes (`1u8` and `1u32`), a `HashMap` writes in its iteration
//! order, and a reader accepts forms a writer does not produce. Compare
//! values, not blobs.
//!
//! ## Versioning and schema evolution
//!
//! [`VERSION`] names the byte grammar and the serde mapping together. It is
//! the profile's version, not the application's, and version 1 is frozen:
//! no release changes what a version 1 blob reads as. A reader meeting a
//! version it does not read reports [`BlobError::UnsupportedVersion`],
//! distinct from a corrupt blob, so "upgrade the reader" and "the data is
//! damaged" are different errors. A new version will be introduced in two
//! steps, readers first, writers later, and this crate's changelog will say
//! which version a release writes.
//!
//! The application's own schema evolves through the type, and serde's
//! attributes govern what an old blob does against a new `T`:
//!
//! | Change to `T`                               | An old blob                                          |
//! |---------------------------------------------|------------------------------------------------------|
//! | Add a field with `#[serde(default)]`        | reads, with the default                              |
//! | Add a field without a default               | is refused: [`BlobError::Mismatch`]                  |
//! | Remove a field                              | reads, unless `T` denies unknown fields              |
//! | Rename a field                              | reads with `#[serde(alias = "…")]`                   |
//! | `F` to `Option<F>`                          | reads as `Some`                                      |
//! | `Option<F>` to `F`                          | is refused if the blob held `Some`                   |
//! | Add an enum variant                         | reads; an older reader refuses the new variant       |
//! | Widen an integer                            | reads; narrowing reads only values that fit          |
//!
//! An application that needs to tell its own versions apart carries that in
//! the value (a version field, or an enum of versions). The blob header
//! never changes because `T` did.
//!
//! ## Decode errors, and when they can occur
//!
//! Decryption **authenticates before it decodes**. The leaf opens first,
//! under its key and context; only then does the profile's reader see the
//! bytes. So the errors tell three things apart:
//!
//! - [`Error::Aead`]: the leaf did not open. Wrong key, wrong context, or
//!   altered bytes; the blob was never looked at.
//! - [`Error::OpenedType`]: the leaf opened but is not a bytes leaf: it was
//!   sealed as a `String` or an integer, say, not as a blob.
//! - [`Error::Blob`]: the leaf opened as bytes and they are not a blob this
//!   type reads: not a blob at all ([`BlobError::NotABlob`]), a later
//!   version ([`BlobError::UnsupportedVersion`]), a blob that breaks a rule
//!   of version 1 ([`BlobError::Malformed`]), or a well-formed blob that is
//!   not a `T` ([`BlobError::Mismatch`]).
//!
//! All three are refusals of an authentic ciphertext, so an `Error::Blob`
//! never says the data was tampered with; it says the data was written as
//! something else. The whole blob is validated before `T`'s `Deserialize`
//! sees any of it: every length is checked against the end of the blob, so
//! a forged length allocates nothing, and a `Deserialize` impl never builds
//! part of a value from a malformed blob. No refusal names a value or a map
//! key; a mismatch names the declared field it is about.
//!
//! ## What the ciphertext reveals
//!
//! The leaf is AES-256-GCM, which keeps the plaintext's length, and the
//! profile adds no padding. A blob ciphertext is therefore the encoded
//! length plus a fixed overhead, and the encoded length is a function of
//! the value: the length of each string, the number of elements in each
//! sequence and map, and whether each `Option` is `Some` (the marker and
//! the value) or `None` (one null byte). Two profiles that differ only in
//! a nickname being present seal to ciphertexts of different lengths. This
//! is the same disclosure a `String` scalar makes of its length; a value
//! whose size must not be visible needs padding the application adds, as a
//! fixed-length field of its own.
//!
//! Neither serde's derived impls nor the profile's writer and reader are
//! constant time, and nothing here claims otherwise. Encoding takes time
//! that depends on the value, as serializing any value does. The
//! cryptography is Vitamin C's and is unchanged; what this module adds runs
//! before the seal and after the open, on plaintext the caller already
//! holds.
//!
//! ## Cleanup
//!
//! On encrypt, the owned `OpaqueBlob<T>` is guarded in [`Protected`] by the
//! owned conversion before anything runs, encoded through a borrow into a
//! buffer the profile's writer returns `Protected` (it grows into fresh
//! allocations and wipes the old ones, writes a `Display` value straight
//! into the blob, and wipes what it wrote if writing fails), and that
//! buffer is planned into the leaf and dropped, wiped, before `encrypt`
//! returns its pending. The source is wiped through `T: Zeroize` at the
//! same point, on success and on an encoding refusal alike. Nothing of the
//! plaintext travels in the pending.
//!
//! On decrypt, the opened bytes are held `Protected` while the reader runs,
//! and wiped when it returns, whether it returned a value or a refusal. The
//! reader borrows text and bytes from that buffer rather than copying them.
//! The value it returns is an ordinary owned `OpaqueBlob<T>`: the caller
//! owns it, and **nothing wipes it on drop**. `T: Zeroize` is the bound
//! that makes wiping possible, not a guard that performs it. To have the
//! result wiped when it is dropped, decrypt to `Zeroizing<OpaqueBlob<T>>`
//! ([`OpaqueDecode`] is implemented for `Zeroizing`
//! of any decodable type), or give `T` a `Drop` of its own.
//!
//! One limit is a property of serde, and is stated rather than solved: a
//! derived `Deserialize` that has read some fields and then refuses a later
//! one drops the fields it built as ordinary values, without `T::zeroize`,
//! because no `T` ever existed to wipe. The profile's up-front validation
//! means this happens only for a well-formed blob of another shape
//! ([`BlobError::Mismatch`]), never for a malformed one, and the bytes
//! those fields were copied from are wiped with the buffer. A type whose
//! fields are themselves wiped on drop (`Zeroizing<String>`, a
//! `#[derive(ZeroizeOnDrop)]` type) closes it for those fields.
//!
//! A Rust move is not an erasure: a `Copy` field leaves its bytes where it
//! was moved from, and compiler temporaries are not wiped. The promise here
//! covers the owned source, the encoded buffer, the opened buffer and the
//! library's own copies, not every byte a program's stack once held.
//!
//! # Go
//!
//! The Go SDK's opaque struct (a `stashgen` declaration with one `value`
//! field, sealed as a storage blob under the context `<context>/value`) is
//! this format: a Rust program opens such a column with
//! `decrypt_with_context::<OpaqueBlob<T>>(ct, ("<context>", "value"))`,
//! with `T`'s serde field names matching the Go struct's `vc` tags, and
//! Go reads a Rust-written blob the same way. Two qualifications, both the
//! Go writer's: a nil slice or map is written as an empty one, and a
//! non-nil pointer is written as the bare value (Rust writes every `Some`
//! with its marker; both readers read either form).
//!
//! [`Error::Aead`]: crate::Error::Aead
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
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

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
/// `Debug` prints no plaintext. The wrapper is an ordinary owned value:
/// it is not wiped on drop (decrypt to `Zeroizing<OpaqueBlob<T>>` for
/// that), and it has no serde impls of its own, so that a blob is never
/// written by accident where a `T` was meant.
///
/// [`into_inner`]: OpaqueBlob::into_inner
#[derive(Clone, PartialEq, Eq, Default)]
pub struct OpaqueBlob<T>(T);

impl<T> OpaqueBlob<T> {
    /// Wrap a value to encrypt it whole.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The value.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// A borrow of the value.
    pub const fn get(&self) -> &T {
        &self.0
    }

    /// A mutable borrow of the value.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> From<T> for OpaqueBlob<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Debug for OpaqueBlob<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueBlob(***)")
    }
}

impl<T: Zeroize> Zeroize for OpaqueBlob<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Serialize> OpaqueBlob<T> {
    /// The value as a storage blob: the plaintext the ciphertext seals,
    /// starting with [`HEADER`]. Returned `Protected`, and wiped when it is
    /// dropped. Encrypting does this itself; it is here for a caller that
    /// needs the bytes, to check them against another writer's, say.
    ///
    /// # Errors
    ///
    /// [`BlobError::Unwritable`] for a value the profile cannot hold.
    pub fn encode(&self) -> Result<Protected<Vec<u8>>, BlobError> {
        storage::to_vec(&self.0).map_err(BlobError::Unwritable)
    }
}

impl<T: DeserializeOwned> OpaqueBlob<T> {
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
            .map(Self)
            .map_err(|error| BlobError::reading(error, bytes))
    }
}

impl<T: Serialize + Zeroize + Send + 'static> sealed::Encode for OpaqueBlob<T> {
    fn seal<'a, K: 'static>(
        &self,
        cipher: &'a KeysetCipher<'_, K>,
        context: ContextPiece<'static>,
    ) -> Pending<'a, Ciphertext, K> {
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

/// Why an [`OpaqueBlob`] could not be written, or an authenticated
/// ciphertext did not read as one. One variant per class of refusal, each
/// with its own code, and none names a value: the profile's own errors
/// name kinds and declared field names only, and are kept as the source.
///
/// On decrypt, every variant means the ciphertext **was authentic**: the
/// leaf opened under its key and context before the blob was looked at.
/// See the [module docs](self#decode-errors-and-when-they-can-occur).
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
        let other = OpaqueBlob::new(Pair {
            left: "l".into(),
            right: 7,
        });
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
        drop(other);
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
