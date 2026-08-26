use super::Decrypt;
use crate::{Decipher, DecipherVisitor, IntoAad, MapAccess, SeqAccess, Unspecified};
use std::collections::HashMap;
use vitaminc_protected::{Controlled, Equatable, Protected};
use zeroize::Zeroize;

impl<'c> Decrypt<'c> for Vec<u8> {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct BytesVisitor;
        impl<'c> DecipherVisitor<'c> for BytesVisitor {
            type Value = Vec<u8>;
            fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
                // The caller asked for a bare `Vec<u8>` — this is the
                // explicit extraction boundary where ownership leaves the
                // cipher pipeline.
                Ok(data.risky_unwrap())
            }
        }
        decipher.decrypt_bytes(BytesVisitor, aad)
    }
}

impl<'c> Decrypt<'c> for String {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct StringVisitor;
        impl<'c> DecipherVisitor<'c> for StringVisitor {
            type Value = String;
            fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
                String::from_utf8(data.risky_unwrap()).map_err(|_| Unspecified)
            }
        }
        decipher.decrypt_bytes(StringVisitor, aad)
    }
}

impl<'c, const N: usize> Decrypt<'c> for [u8; N] {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct ArrayVisitor<const N: usize>;
        impl<'c, const N: usize> DecipherVisitor<'c> for ArrayVisitor<N> {
            type Value = [u8; N];
            fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
                data.risky_unwrap().try_into().map_err(|_| Unspecified)
            }
        }
        decipher.decrypt_bytes(ArrayVisitor::<N>, aad)
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
                let bytes: [u8; 4] = data.risky_unwrap().try_into().map_err(|_| Unspecified)?;
                Ok(u32::from_le_bytes(bytes))
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
        D::map_ok(
            T::decrypt_with_aad(decipher, aad),
            Protected::init_from_inner,
        )
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
