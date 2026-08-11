//! [`Element`], a wrapper that encrypts and decrypts a value *as a sequence
//! element* — one row of a logical collection — without the collection being
//! present in the call.
//!
//! # Why
//!
//! Sequence elements are sealed against
//! [`Aad::for_sequence_element`](crate::Aad::for_sequence_element) of the
//! caller's AAD, not the bare AAD, so the container shape is authenticated
//! (a `Single` cannot be rewrapped as a one-element `Sequence`, nor an
//! element re-homed to top level). The consequence for database-shaped
//! workloads is that a row batch-encrypted as part of a `Vec` cannot later
//! be decrypted alone under the bare AAD — the derivation would not match.
//!
//! `Element` moves that derivation into the type system. A row is *always*
//! an element of its table's collection; how many rows a call touches is
//! incidental. Wrapping the row in `Element` states that fact once, on both
//! sides:
//!
//! - **Decrypt**: a single row fetched from storage decrypts with the same
//!   caller AAD used for the whole collection — `Element<Row>` derives the
//!   element AAD internally.
//! - **Encrypt**: a row inserted alone is sealed exactly as batch encryption
//!   of a `Vec` would have sealed it, so single-row inserts and whole-`Vec`
//!   reads interchange freely.
//!
//! Retrieval *multiplicity* between "fetched alone" and "one element of a
//! `Vec` read" is deliberately not authenticated, matching the existing
//! stance on element order (see
//! [`Aad::for_sequence_element`](crate::Aad::for_sequence_element)): both are
//! caller obligations, not authenticated facts.
//!
//! # ⚠️ Wrap the row, not the collection
//!
//! `Vec<Element<T>>` compiles, round-trips symmetrically, and is almost never
//! what you want: it seals under a *double* element derivation
//! (`for_sequence_element(for_sequence_element(aad))`), so its ciphertexts do
//! not interchange with `Vec<T>`'s. The mistake fails closed — decryption
//! across the two shapes fails authentication, it never decrypts wrongly —
//! but the intended usage is `Vec<T>` for batches and `Element<T>` for a
//! lone row.
//!
//! # Example
//!
//! ```ignore
//! // Batch write: rows sealed as sequence elements.
//! let ct = vec![row1, row2].encrypt_with_aad(&cipher, Aad::from_slice(b"users"))?;
//!
//! // Single-row read: same caller AAD, Element derives the rest.
//! let row: Element<HashMap<String, String>> =
//!     cipher.decrypt_with_aad(row_ct, Aad::from_slice(b"users"))?;
//!
//! // Single-row write: interchangeable with the batch above.
//! let ct = Element(row3).encrypt_with_aad(&cipher, Aad::from_slice(b"users"))?;
//! ```

use crate::{
    cipher::Cipher,
    decipher::{Decipher, Decrypt},
    encrypt::Encrypt,
    IntoAad,
};

/// A value encrypted and decrypted as a sequence element, independent of the
/// sequence — see the [module docs](self) for when and why.
///
/// The wrapper adds nothing to the ciphertext: `Element(x)` produces bytes
/// identical to what `x` would have produced as an element of an encrypted
/// `Vec` under the same caller AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Element<T>(pub T);

impl<T> Element<T> {
    /// Consume the wrapper, returning the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for Element<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Encrypt for Element<T>
where
    T: Encrypt,
{
    /// Seals the inner value under
    /// [`Aad::for_sequence_element`](crate::Aad::for_sequence_element) of the
    /// caller's AAD — byte-identical to what `Vec` encryption binds per
    /// element.
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        self.0
            .encrypt_with_aad(cipher, aad.into_aad().for_sequence_element())
    }
}

impl<'c, T> Decrypt<'c> for Element<T>
where
    T: Decrypt<'c> + 'c,
{
    /// Verifies the inner value against
    /// [`Aad::for_sequence_element`](crate::Aad::for_sequence_element) of the
    /// caller's AAD — the derivation `Vec` decryption applies per element.
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        D::map_ok(
            T::decrypt_with_aad(decipher, aad.into_aad().for_sequence_element()),
            Element,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{MockCipher, MockDecipher};
    use crate::Aad;

    #[test]
    fn encrypt_binds_the_sequence_element_derivation() {
        let cipher = MockCipher::new();
        let ct = Element("row")
            .encrypt_with_aad(&cipher, "users")
            .expect("encryption should succeed");

        // The inner value reaches the cipher unchanged...
        assert_eq!(ct, b"row");
        // ...bound against `for_sequence_element` of the caller's AAD, never
        // the bare AAD.
        let expected = Aad::from_slice(b"users").for_sequence_element();
        assert_eq!(cipher.captured_aad(), expected.as_bytes());
        assert_ne!(cipher.captured_aad(), b"users");
    }

    #[test]
    fn encrypt_with_no_aad_derives_from_the_empty_aad() {
        // `encrypt` supplies empty AAD; the wrapper must still derive — an
        // `Element` sealed with no caller AAD is an element of the anonymous
        // collection, not a bare value.
        let cipher = MockCipher::new();
        Element("row")
            .encrypt(&cipher)
            .expect("encryption should succeed");

        let expected = Aad::empty().for_sequence_element();
        assert_eq!(cipher.captured_aad(), expected.as_bytes());
        assert_ne!(cipher.captured_aad(), Aad::empty().as_bytes());
    }

    #[test]
    fn decrypt_binds_the_same_derivation_and_rewraps() {
        let decipher = MockDecipher::new(b"row");
        let got: Element<String> =
            Element::decrypt_with_aad(&decipher, "users").expect("decryption should succeed");

        // The inner value comes back wrapped...
        assert_eq!(got, Element("row".to_string()));
        // ...after being verified against the same derivation encrypt binds.
        let expected = Aad::from_slice(b"users").for_sequence_element();
        assert_eq!(decipher.captured_aad(), expected.as_bytes());
    }

    #[test]
    fn encrypt_and_decrypt_bind_identical_aad() {
        // The round-trip property at the AAD layer, independent of any real
        // cipher: both sides must present byte-identical derived AAD or
        // nothing an `Element` seals would ever open.
        let cipher = MockCipher::new();
        Element("row")
            .encrypt_with_aad(&cipher, "users")
            .expect("encryption should succeed");

        let decipher = MockDecipher::new(b"row");
        let _: Element<String> =
            Element::decrypt_with_aad(&decipher, "users").expect("decryption should succeed");

        assert_eq!(cipher.captured_aad(), decipher.captured_aad());
    }
}
