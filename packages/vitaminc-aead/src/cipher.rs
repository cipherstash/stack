use std::any::Any;
use std::borrow::Cow;

use vitaminc_protected::{Controlled, Protected};

use crate::{Encrypt, IntoAad};

/// An error that provides **no information** about the failure.
/// It is crucial when returning an error from a cipher operation
/// that does not reveal any details about the failure as this can lead to side channel attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unspecified;

impl std::fmt::Display for Unspecified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unspecified error")
    }
}

impl std::error::Error for Unspecified {}

/// A driver of an encryption operation, analogous to serde's `Serializer`.
///
/// `Cipher` defines the entry points an [`Encrypt`](crate::Encrypt) implementation
/// can use to encrypt itself. Concrete implementations (e.g. an AES-256-GCM
/// cipher) decide how plaintext is sealed and what ciphertext container is
/// produced via [`Ok`](Cipher::Ok).
///
/// The trait supports three modes:
/// - raw byte plaintext, via [`encrypt_bytes_vec`](Cipher::encrypt_bytes_vec) /
///   [`encrypt_bytes_array`](Cipher::encrypt_bytes_array);
/// - structured sequences, via [`encrypt_seq`](Cipher::encrypt_seq) returning
///   a [`SeqCipher`];
/// - structured maps, via [`encrypt_map`](Cipher::encrypt_map) returning a
///   [`MapCipher`].
pub trait Cipher: Sized {
    /// The encrypted output produced by this cipher (e.g. a structured
    /// ciphertext container holding nonce + ciphertext + tag).
    type Ok;
    /// The error type returned on cipher failure. Implementations should keep
    /// this opaque — see [`Unspecified`].
    type Error;
    /// The payload type carried by [`passthrough`](Cipher::passthrough)
    /// values.
    ///
    /// Rust-native ciphers typically use `Box<dyn Any + Send + 'static>`:
    /// callers box on the way in and downcast on the way out. Ciphers
    /// targeting an FFI boundary instead use an owned host-value type (e.g. a
    /// converted JS value), carried value-in/value-out without the cipher ever
    /// inspecting it.
    type Passthrough;
    /// The sub-cipher returned by [`encrypt_seq`](Cipher::encrypt_seq).
    type SeqCipher: SeqCipher<Ok = Self::Ok, Error = Self::Error, Passthrough = Self::Passthrough>;
    /// The sub-cipher returned by [`encrypt_map`](Cipher::encrypt_map).
    type MapCipher: MapCipher<Ok = Self::Ok, Error = Self::Error, Passthrough = Self::Passthrough>;

    /// Encrypt the given byte vector with the supplied associated data.
    ///
    /// The plaintext is taken as `Protected<Vec<u8>>` so the chain of custody
    /// — and the zeroize-on-drop guarantee — survives the trait boundary.
    /// Implementations should keep the value inside `Protected` for the
    /// duration of the encryption and let it drop (and wipe) at end of scope.
    fn encrypt_bytes_vec<'a, A>(
        self,
        data: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>;

    /// Encrypt a fixed-size byte array. The default implementation forwards to
    /// [`encrypt_bytes_vec`](Cipher::encrypt_bytes_vec).
    ///
    /// As with [`encrypt_bytes_vec`](Cipher::encrypt_bytes_vec), the plaintext
    /// is taken inside `Protected` so the stack array is wiped on drop after
    /// `to_vec` has copied its contents onto the heap.
    fn encrypt_bytes_array<'a, const N: usize, A>(
        self,
        data: Protected<[u8; N]>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        // Borrow the protected array so it stays owned by `data` and is
        // wiped by ZeroizeOnDrop at end of scope. A `risky_unwrap` here
        // would partially-move out of `data`, skipping its Drop and
        // leaving the bare `[u8; N]` on the stack — see issue #170.
        let copy = Protected::new(data.risky_ref().to_vec());
        self.encrypt_bytes_vec(copy, aad)
    }

    /// Begin encrypting a sequence of values under `aad`. `size_hint` lets the
    /// implementation preallocate when known.
    ///
    /// The AAD is captured **once**, here, and applies to every element and to
    /// the empty marker. Sub-cipher methods therefore take no AAD of their
    /// own: there is no second place to supply it, so an element and its
    /// container can never end up sealed under different AAD.
    fn encrypt_seq<'a, A>(self, size_hint: Option<usize>, aad: A) -> Self::SeqCipher
    where
        A: IntoAad<'a>;

    /// Begin encrypting a map of key/value pairs under `aad`, captured once —
    /// see [`encrypt_seq`](Cipher::encrypt_seq).
    fn encrypt_map<'a, A>(self, aad: A) -> Self::MapCipher
    where
        A: IntoAad<'a>;

    /// Encrypt a present optional value. Default forwards to the inner value's
    /// [`Encrypt`] impl — the `Some` discriminator is implicit in the structural
    /// shape of the ciphertext (any non-`None` variant means `Some`).
    fn encrypt_some<'a, T, A>(self, value: T, aad: A) -> Result<Self::Ok, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
    {
        value.encrypt_with_aad(self, aad)
    }

    /// Encrypt the absent case of an optional value. Must produce a
    /// cryptographically authenticated marker — distinguishable from any
    /// `Some(_)` ciphertext and bound to `aad` so it cannot be forged.
    ///
    /// Implementations must seal the marker against
    /// [`Aad::for_none`](crate::Aad::for_none) of the caller's AAD (and the
    /// decrypt side must verify the sealed plaintext is empty under the same
    /// derivation), so a `Some(_)` leaf sealed under the bare AAD can never
    /// be re-tagged as an authenticated absence.
    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>;

    /// Pass a value through the cipher's output container **without**
    /// encrypting it. Intended for fields that need to survive the encryption
    /// envelope in the clear (e.g. a schema version tag).
    ///
    /// The value has the cipher's [`Passthrough`](Cipher::Passthrough) type,
    /// stored opaquely and returned as-is by the corresponding
    /// [`Decipher::decrypt_passthrough`].
    ///
    /// # ⚠️ Non-sensitive data only
    ///
    /// Passthrough values travel **in the clear** alongside the ciphertext,
    /// and — unlike map keys — are not authenticated either. Do not use this
    /// for secret-bearing data such as keys, plaintexts, or credentials —
    /// there is no encryption, no zeroize discipline applied to the payload,
    /// and no guarantee about when the storage is freed. For secrets, use
    /// [`encrypt_with_aad`](crate::Encrypt::encrypt_with_aad) (via the
    /// [`Encrypt`](crate::Encrypt) trait) or wrap in
    /// [`vitaminc_protected::Protected`].
    fn passthrough(self, value: Self::Passthrough) -> Result<Self::Ok, Self::Error>;

    /// Pass a **type-erased** value through the output container without
    /// encrypting it — the entry point for self-describing
    /// [`Encrypt`](crate::Encrypt) implementations that cannot name this
    /// cipher's [`Passthrough`](Cipher::Passthrough) currency at the call
    /// site.
    ///
    /// A tree-shaped, dynamically typed value (e.g. `FfiValue`) implements
    /// `Encrypt` generically over *every* cipher, so its impl has no way to
    /// construct a specific cipher's currency — the trait method signature
    /// forbids the extra bound (`impl has stricter requirements than trait`).
    /// This method closes that gap: the value is delivered as
    /// `Box<dyn Any + Send>`, and each cipher decides how to absorb it. A
    /// Rust-native cipher whose currency *is* `Box<dyn Any + Send>` stores the
    /// box directly; a cipher with an owned currency downcasts it (returning an
    /// error for a foreign payload type). The decrypt-side counterpart is
    /// [`DecipherVisitor::visit_passthrough`](crate::DecipherVisitor::visit_passthrough).
    ///
    /// # ⚠️ Non-sensitive data only
    ///
    /// Identical contract to [`passthrough`](Cipher::passthrough): the value
    /// travels **in the clear** and is **not authenticated**. Never route
    /// secret-bearing data through it.
    fn passthrough_boxed(
        self,
        value: Box<dyn Any + Send + 'static>,
    ) -> Result<Self::Ok, Self::Error>;
}

/// Sub-cipher driving the encryption of a sequence of values.
///
/// Obtained from [`Cipher::encrypt_seq`], which fixes the AAD for the whole
/// sequence. Each element is encrypted with
/// [`encrypt_next`](SeqCipher::encrypt_next); the caller finalises the sequence
/// with [`end`](SeqCipher::end) to produce the cipher's `Ok` output.
pub trait SeqCipher: Sized {
    /// The final encrypted output produced by [`end`](SeqCipher::end).
    type Ok;
    /// The error type for sequence operations.
    type Error;
    /// The passthrough payload type — matches the parent
    /// [`Cipher::Passthrough`].
    type Passthrough;

    /// Encrypt the next element in the sequence, returning the updated cipher.
    ///
    /// The element is sealed against the AAD supplied to
    /// [`Cipher::encrypt_seq`].
    fn encrypt_next<T>(self, data: T) -> Result<Self, Self::Error>
    where
        T: Encrypt;

    /// Append a passthrough (unencrypted) element to the sequence.
    ///
    /// See [`Cipher::passthrough`] — passthrough values are non-sensitive by
    /// design and must not carry secret data.
    fn passthrough_next(self, value: Self::Passthrough) -> Result<Self, Self::Error>;

    /// Finalise the sequence and return the produced ciphertext container.
    ///
    /// Implementations must authenticate the sequence's AAD even when no
    /// encrypted elements were appended. Otherwise an empty sequence used as a
    /// map value would not authenticate the map entry's derived AAD, allowing
    /// its cleartext key to be renamed without detection. The empty marker
    /// must be sealed against
    /// [`Aad::for_empty_sequence`](crate::Aad::for_empty_sequence) of that AAD.
    ///
    /// A sequence whose elements are all passthrough must be **rejected**:
    /// passthrough elements authenticate nothing, so such a container would
    /// carry no tag binding the AAD at all — decrypt implementations must
    /// likewise refuse to open one.
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

/// Sub-cipher driving the encryption of a map of key/value pairs.
///
/// Obtained from [`Cipher::encrypt_map`], which fixes the AAD for the whole
/// map. Keys are not encrypted; values are. The expected call order is
/// key → value → key → value → … → `end`, or use the
/// [`encrypt_entry`](MapCipher::encrypt_entry) convenience method.
///
/// Keys may be `&'static str` or owned `String`s (anything
/// `Into<Cow<'static, str>>`), so maps with runtime-derived keys — e.g. values
/// crossing an FFI boundary — can be encrypted as well as decrypted.
///
/// # Key authentication
///
/// Keys travel in the clear, but they are **not** unauthenticated:
/// implementations must bind each entry's key into the AAD its value is sealed
/// against, via [`Aad::for_map_entry`](crate::Aad::for_map_entry). Swapping or
/// renaming keys in a stored ciphertext therefore causes the affected values to
/// fail decryption. [`MapAccess`](crate::MapAccess) implementations perform the
/// symmetric binding on decrypt.
///
/// The exception is [`passthrough_entry`](MapCipher::passthrough_entry): a
/// passthrough value is neither encrypted nor authenticated, so nothing seals
/// its key either.
pub trait MapCipher: Sized {
    /// The final encrypted output produced by [`end`](MapCipher::end).
    type Ok;
    /// The error type for map operations.
    type Error;
    /// The passthrough payload type — matches the parent
    /// [`Cipher::Passthrough`].
    type Passthrough;

    /// Record the next key. Keys are stored in the clear — only values are
    /// encrypted — but each key is bound into its value's AAD (see the
    /// trait-level *Key authentication* notes).
    ///
    /// Must be followed by exactly one [`encrypt_value`](MapCipher::encrypt_value)
    /// before the next `encrypt_key` or [`end`](MapCipher::end). Calling
    /// `encrypt_key` twice with no intervening `encrypt_value` is a trait-contract
    /// violation; implementations should return an error rather than silently
    /// dropping the first key.
    fn encrypt_key<K>(self, key: K) -> Result<Self, Self::Error>
    where
        K: Into<Cow<'static, str>>;

    /// Encrypt the value associated with the most recently supplied key.
    ///
    /// Implementations **must not** seal the value against the map's AAD
    /// directly: they must bind the pending key alongside it via
    /// [`Aad::for_map_entry`](crate::Aad::for_map_entry), so that key and value
    /// are cryptographically inseparable in the stored ciphertext.
    fn encrypt_value<T>(self, value: T) -> Result<Self, Self::Error>
    where
        T: Encrypt;

    /// Convenience for [`encrypt_key`](MapCipher::encrypt_key) followed by
    /// [`encrypt_value`](MapCipher::encrypt_value).
    fn encrypt_entry<K, T>(self, key: K, value: T) -> Result<Self, Self::Error>
    where
        K: Into<Cow<'static, str>>,
        T: Encrypt,
        Self: Sized,
    {
        self.encrypt_key(key).and_then(|mc| mc.encrypt_value(value))
    }

    /// Insert a passthrough (unencrypted) entry under `key`. Equivalent to
    /// [`encrypt_key`](MapCipher::encrypt_key) followed by storing the value
    /// without AEAD treatment.
    ///
    /// See [`Cipher::passthrough`] — passthrough values are non-sensitive by
    /// design and must not carry secret data. Neither the value nor its key is
    /// authenticated.
    fn passthrough_entry<K>(self, key: K, value: Self::Passthrough) -> Result<Self, Self::Error>
    where
        K: Into<Cow<'static, str>>;

    /// Finalise the map and return the produced ciphertext container.
    ///
    /// Implementations must authenticate the map's AAD even when no encrypted
    /// entries were appended. Otherwise an empty map used as a map value would
    /// not authenticate the outer entry's derived AAD, allowing its cleartext
    /// key to be renamed without detection. The empty marker must be sealed
    /// against [`Aad::for_empty_map`](crate::Aad::for_empty_map) of that AAD.
    ///
    /// A map whose entries are all passthrough must be **rejected** — see
    /// [`SeqCipher::end`].
    fn end(self) -> Result<Self::Ok, Self::Error>;
}
