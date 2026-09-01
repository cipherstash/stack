use super::Decrypt;
use crate::{Decipher, DecipherVisitor, IntoAad, MapAccess, SeqAccess, Unspecified};
use std::collections::HashMap;
use vitaminc_protected::{AsProtectedRef, Controlled, Equatable, Protected};
use zeroize::Zeroize;

impl<'c> Decrypt<'c> for Vec<u8> {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        // The caller asked for a bare `Vec<u8>` — the unwrap is the explicit
        // extraction boundary where ownership leaves the cipher pipeline.
        // Everything up to it is the wrapped path below.
        D::map_ok(
            Self::decrypt_protected(decipher, aad),
            Controlled::risky_unwrap,
        )
    }

    /// The decipher already hands the plaintext over as `Protected<Vec<u8>>`;
    /// a caller who wants it wrapped gets that value as-is, never unwrapped.
    fn decrypt_protected<'a, D, A>(decipher: D, aad: A) -> D::Ok<Protected<Self>>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct ProtectedBytesVisitor;
        impl<'c> DecipherVisitor<'c> for ProtectedBytesVisitor {
            type Value = Protected<Vec<u8>>;
            fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
                Ok(data)
            }
        }
        decipher.decrypt_bytes(ProtectedBytesVisitor, aad)
    }
}

impl<'c> Decrypt<'c> for String {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        // The caller asked for a bare `String` — the unwrap is the extraction
        // boundary; validation and conversion happen on the wrapped path.
        D::map_ok(
            Self::decrypt_protected(decipher, aad),
            Controlled::risky_unwrap,
        )
    }

    /// The buffer is validated through a reference and converted with
    /// [`Controlled::map`], which moves the same heap allocation into the
    /// `String` — the plaintext never leaves custody, and an invalid buffer
    /// stays inside its `Protected` to be wiped on drop. (A plain
    /// `String::from_utf8(vec)` would move the buffer into `FromUtf8Error`
    /// on failure, which frees it unwiped.)
    fn decrypt_protected<'a, D, A>(decipher: D, aad: A) -> D::Ok<Protected<Self>>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct ProtectedStringVisitor;
        impl<'c> DecipherVisitor<'c> for ProtectedStringVisitor {
            type Value = Protected<String>;
            fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
                if std::str::from_utf8(data.risky_ref()).is_err() {
                    return Err(Unspecified);
                }
                Ok(data.map(|bytes| String::from_utf8(bytes).expect("validated as UTF-8 above")))
            }
        }
        decipher.decrypt_bytes(ProtectedStringVisitor, aad)
    }
}

/// Copy a decrypted buffer into a fixed-size array **inside a fresh
/// `Protected`**, leaving the source buffer inside its own `Protected` so
/// both are wiped on drop. The destination array is allocated already
/// wrapped and filled in place via [`Controlled::update_with_ref`], so no
/// bare copy of the plaintext sits on the stack at any point.
/// (`Vec<u8>: TryInto<[u8; N]>` would drop the vector unwiped.)
fn array_from_protected<const N: usize>(
    data: &Protected<Vec<u8>>,
) -> Result<Protected<[u8; N]>, Unspecified> {
    if data.risky_ref().len() != N {
        return Err(Unspecified);
    }
    let mut out = Protected::new([0u8; N]);
    out.update_with_ref(data.as_protected_ref(), |out, bytes: &Vec<u8>| {
        out.copy_from_slice(bytes)
    });
    Ok(out)
}

impl<'c, const N: usize> Decrypt<'c> for [u8; N] {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        // The caller asked for a bare array — the unwrap is the extraction
        // boundary; the copy itself happens on the wrapped path.
        D::map_ok(
            Self::decrypt_protected(decipher, aad),
            Controlled::risky_unwrap,
        )
    }

    /// The array is built directly inside a fresh `Protected` from the
    /// wrapped buffer; no bare copy sits on the stack between the two.
    fn decrypt_protected<'a, D, A>(decipher: D, aad: A) -> D::Ok<Protected<Self>>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct ProtectedArrayVisitor<const N: usize>;
        impl<'c, const N: usize> DecipherVisitor<'c> for ProtectedArrayVisitor<N> {
            type Value = Protected<[u8; N]>;
            fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
                array_from_protected(&data)
            }
        }
        decipher.decrypt_bytes(ProtectedArrayVisitor::<N>, aad)
    }
}

impl<'c> Decrypt<'c> for u32 {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct U32Visitor;
        impl<'c> DecipherVisitor<'c> for U32Visitor {
            type Value = u32;
            fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
                // Copy into a wrapped array so the buffer stays in custody;
                // the unwrap is the extraction boundary for the bare `u32`.
                let bytes = array_from_protected::<4>(&data)?;
                Ok(u32::from_le_bytes(bytes.risky_unwrap()))
            }
        }
        decipher.decrypt_bytes(U32Visitor, aad)
    }
}

impl<'c, T> Decrypt<'c> for Vec<T>
where
    T: Decrypt<'c> + 'c,
{
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct VecVisitor<T>(std::marker::PhantomData<T>);
        impl<'c, T> DecipherVisitor<'c> for VecVisitor<T>
        where
            T: Decrypt<'c> + 'c,
        {
            type Value = Vec<T>;
            fn visit_seq<A: SeqAccess<'c>>(self, mut seq: A) -> Result<Self::Value, Unspecified> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<T>().map_err(|_| Unspecified)? {
                    items.push(item);
                }
                Ok(items)
            }
        }
        decipher.decrypt_seq(VecVisitor(std::marker::PhantomData), aad)
    }
}

impl<'c, T> Decrypt<'c> for HashMap<String, T>
where
    T: Decrypt<'c> + 'c,
{
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct HashMapVisitor<T>(std::marker::PhantomData<T>);
        impl<'c, T> DecipherVisitor<'c> for HashMapVisitor<T>
        where
            T: Decrypt<'c> + 'c,
        {
            type Value = HashMap<String, T>;
            fn visit_map<A: MapAccess<'c>>(self, mut map: A) -> Result<Self::Value, Unspecified> {
                let mut entries = HashMap::new();
                while let Some((key, value)) = map.next_entry::<T>().map_err(|_| Unspecified)? {
                    entries.insert(key, value);
                }
                Ok(entries)
            }
        }
        decipher.decrypt_map(HashMapVisitor(std::marker::PhantomData), aad)
    }
}

impl<'c, T> Decrypt<'c> for Protected<T>
where
    T: Decrypt<'c> + Zeroize + 'c,
{
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        // Mirrors the `Encrypt` side: `T` decides how to arrive wrapped.
        // Byte leaves keep the decipher's `Protected<Vec<u8>>` intact;
        // everything else decrypts bare and is wrapped by the default.
        T::decrypt_protected(decipher, aad)
    }
}

impl<'c, T> Decrypt<'c> for Equatable<T>
where
    // `Send` is required by the `Decrypt: Send` supertrait and is load-bearing,
    // not over-tightening. Unlike the sibling `Protected` impl — which bounds
    // `T: Decrypt`, transitively giving `T: Send` — this impl bounds the
    // flattened `T::Inner: Decrypt`, which only proves `T::Inner: Send`. `T`
    // itself is otherwise unconstrained (`Controlled` has no `Send` supertrait),
    // so `T: Send` is not implied and must be stated for `map_ok`'s `U: Send`
    // requirement (and the impl's own `Send`) to hold.
    T: Controlled + Send + 'c,
    T::Inner: Decrypt<'c> + 'c,
{
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        // Decrypt the innermost value, then rebuild both wrapper layers
        // (`Equatable<Protected<_>>`) via `init_from_inner` — the mirror of the
        // `Encrypt` impl, which unwraps them. The AAD is threaded through to the
        // inner decrypt so the binding matches what the `Encrypt` impl sealed.
        D::map_ok(
            <T::Inner as Decrypt<'c>>::decrypt_with_aad(decipher, aad),
            Equatable::init_from_inner,
        )
    }
}

impl<'c, T> Decrypt<'c> for Option<T>
where
    T: Decrypt<'c> + 'c,
{
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        decipher.decrypt_option::<T, _>(aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockDecipher;
    use crate::Aad;

    // `array_from_protected` is the one length check between the decipher's
    // variable-length buffer and a fixed-size array. These pin both halves of
    // it — the copy and the rejection — through the bare and wrapped `[u8; N]`
    // paths, in this crate, so a mutation here is caught without depending on
    // the real-cipher tests in `vitaminc-encrypt`.

    #[test]
    fn array_from_protected_copies_the_bytes_exactly() {
        let data = Protected::new(vec![7u8, 42, 0, 255]);
        let out: Protected<[u8; 4]> = array_from_protected(&data).expect("length matches");
        assert_eq!(out.risky_ref(), &[7, 42, 0, 255]);
    }

    #[test]
    fn array_from_protected_rejects_short_and_long_buffers() {
        let short = Protected::new(vec![1u8, 2, 3]);
        assert!(array_from_protected::<4>(&short).is_err());

        let long = Protected::new(vec![1u8, 2, 3, 4, 5]);
        assert!(array_from_protected::<4>(&long).is_err());
    }

    #[test]
    fn bare_array_decrypts_the_payload_bytes() {
        let decipher = MockDecipher::new(vec![9u8, 8, 7]);
        let out: [u8; 3] = <[u8; 3]>::decrypt_with_aad(&decipher, Aad::empty()).expect("decrypt");
        assert_eq!(out, [9, 8, 7]);
    }

    #[test]
    fn bare_array_rejects_a_length_mismatch() {
        let decipher = MockDecipher::new(vec![9u8, 8, 7]);
        assert_eq!(
            <[u8; 2]>::decrypt_with_aad(&decipher, Aad::empty()),
            Err(Unspecified)
        );
    }

    #[test]
    fn protected_array_decrypts_the_payload_bytes_wrapped() {
        let decipher = MockDecipher::new(vec![3u8, 2, 1, 0]);
        let out = <[u8; 4]>::decrypt_protected(&decipher, Aad::empty()).expect("decrypt");
        assert_eq!(out.risky_ref(), &[3, 2, 1, 0]);
    }

    #[test]
    fn protected_array_rejects_a_length_mismatch() {
        let decipher = MockDecipher::new(vec![3u8, 2, 1, 0]);
        assert!(<[u8; 8]>::decrypt_protected(&decipher, Aad::empty()).is_err());
    }

    #[test]
    fn protected_vec_decrypts_the_payload_bytes_wrapped() {
        let decipher = MockDecipher::new(vec![5u8, 6]);
        let out = <Vec<u8>>::decrypt_protected(&decipher, Aad::empty()).expect("decrypt");
        assert_eq!(out.risky_ref(), &[5, 6]);
    }
}
