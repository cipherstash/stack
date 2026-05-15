use super::{Decipher, DecipherVisitor, Decrypt, MapAccess, SeqAccess};
use crate::Unspecified;
use std::collections::HashMap;
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

impl<'c> Decrypt<'c> for Vec<u8> {
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
        struct BytesVisitor;
        impl<'c> DecipherVisitor<'c> for BytesVisitor {
            type Value = Vec<u8>;
            fn visit_bytes_vec(self, data: Vec<u8>) -> Result<Self::Value, Unspecified> {
                Ok(data)
            }
        }
        decipher.decrypt_bytes(BytesVisitor)
    }
}

impl<'c> Decrypt<'c> for String {
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
        struct StringVisitor;
        impl<'c> DecipherVisitor<'c> for StringVisitor {
            type Value = String;
            fn visit_bytes_vec(self, data: Vec<u8>) -> Result<Self::Value, Unspecified> {
                String::from_utf8(data).map_err(|_| Unspecified)
            }
        }
        decipher.decrypt_bytes(StringVisitor)
    }
}

impl<'c, const N: usize> Decrypt<'c> for [u8; N] {
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
        struct ArrayVisitor<const N: usize>;
        impl<'c, const N: usize> DecipherVisitor<'c> for ArrayVisitor<N> {
            type Value = [u8; N];
            fn visit_bytes_vec(self, data: Vec<u8>) -> Result<Self::Value, Unspecified> {
                data.try_into().map_err(|_| Unspecified)
            }
        }
        decipher.decrypt_bytes(ArrayVisitor::<N>)
    }
}

impl<'c> Decrypt<'c> for u32 {
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
        struct U32Visitor;
        impl<'c> DecipherVisitor<'c> for U32Visitor {
            type Value = u32;
            fn visit_bytes_vec(self, data: Vec<u8>) -> Result<Self::Value, Unspecified> {
                let bytes: [u8; 4] = data.try_into().map_err(|_| Unspecified)?;
                Ok(u32::from_le_bytes(bytes))
            }
        }
        decipher.decrypt_bytes(U32Visitor)
    }
}

impl<'c, T> Decrypt<'c> for Vec<T>
where
    T: Decrypt<'c> + 'c,
{
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
        struct VecVisitor<T>(std::marker::PhantomData<T>);
        impl<'c, T> DecipherVisitor<'c> for VecVisitor<T>
        where
            T: Decrypt<'c> + Send + 'c,
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
        decipher.decrypt_seq(VecVisitor(std::marker::PhantomData))
    }
}

impl<'c, T> Decrypt<'c> for HashMap<String, T>
where
    T: Decrypt<'c> + 'c,
{
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
        struct HashMapVisitor<T>(std::marker::PhantomData<T>);
        impl<'c, T> DecipherVisitor<'c> for HashMapVisitor<T>
        where
            T: Decrypt<'c> + Send + 'c,
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
        decipher.decrypt_map(HashMapVisitor(std::marker::PhantomData))
    }
}

impl<'c, T> Decrypt<'c> for Protected<T>
where
    T: Decrypt<'c> + Zeroize + 'c,
{
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
        D::map_ok(T::decrypt(decipher), Protected::init_from_inner)
    }
}
