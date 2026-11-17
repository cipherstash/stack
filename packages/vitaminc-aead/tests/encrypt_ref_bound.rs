//! A borrowed plaintext can be bounded on in generic code while its type
//! is still being inferred. `for<'a> &'a T: Encrypt` used to overflow the
//! trait solver (`E0275`) wherever `T` was inferred, because it tried
//! `&Option<U>`, `&Option<Option<U>>`, ... without end.

use std::collections::{BTreeMap, HashMap};

use vitaminc_aead::{Encrypt, EncryptRef};
use vitaminc_protected::{AsProtectedRef, Protected, ProtectedRef};

fn by_hrtb<T: ?Sized>(_: &T) -> Option<usize>
where
    for<'a> &'a T: Encrypt,
{
    <&T as Encrypt>::DEPTH
}

fn by_ref<T: ?Sized + EncryptRef>(value: &T) -> Option<usize> {
    fn depth<P: Encrypt>(_: P) -> Option<usize> {
        P::DEPTH
    }
    depth(value.lend())
}

/// A caller that only learns `T` after the bound is registered.
fn later<T: EncryptRef>() -> impl Fn(&T) -> Option<usize> {
    |value| by_ref(value)
}

#[test]
fn a_higher_ranked_bound_holds_with_its_type_inferred() {
    assert_eq!(by_hrtb(&42i32), Some(0));
    assert_eq!(by_hrtb(&String::from("x")), Some(0));
    assert_eq!(by_hrtb(&vec![Some(1u16)]), Some(1));
    assert_eq!(by_hrtb(&[7u8; 4]), Some(0));
    let nested = String::from("x");
    assert_eq!(by_hrtb(&&nested), Some(0));
}

/// The slice, map and `Protected` impls were the ones that overflowed: each
/// is checked here so that a regression in any one fails.
#[test]
fn a_higher_ranked_bound_holds_for_slices_maps_and_protected_values() {
    assert_eq!(by_hrtb(&[1u32, 2][..]), Some(1), "a slice");
    assert_eq!(
        by_hrtb(&BTreeMap::from([("k", Some(1i32))])),
        Some(1),
        "a BTreeMap"
    );
    assert_eq!(
        by_hrtb(&HashMap::from([("k", vec![1i64])])),
        Some(2),
        "a HashMap"
    );
    let protected = Protected::new(7u32);
    assert_eq!(by_hrtb(&protected), Some(0), "a Protected value");
    assert_eq!(by_hrtb(&&protected), Some(0), "a borrowed Protected value");
    let secret = Protected::new(String::from("x"));
    let view: ProtectedRef<'_, String> = secret.as_protected_ref();
    assert_eq!(by_hrtb(&view), Some(0), "a ProtectedRef");
    assert_eq!(
        by_hrtb(&vec![Protected::new(vec![1u8])]),
        Some(1),
        "a Vec of Protected values"
    );
}

#[test]
fn an_encrypt_ref_bound_holds_with_its_type_inferred() {
    assert_eq!(by_ref(&42i32), Some(0));
    assert_eq!(by_ref("x"), Some(0));
    assert_eq!(by_ref(&Some(vec![1u16])), Some(1));
    assert_eq!(later()(&7u64), Some(0));
}
