//! `Scalar`, the encrypt-side marker for a source whose walk is exactly one
//! leaf: the counterpart of `FromScalar`.
//!
//! The marker is only worth having if it agrees with the walk, so for every
//! type that carries it these tests pin both halves of the contract: its
//! `DEPTH` is `depth::SCALAR`, and planning a value of it yields one leaf.
//! The generic impls (`[u8; N]`, `&&T`, `Protected<T>`, `ProtectedRef<T>`)
//! cannot assert their depth where they are written, so the named `const`s
//! here do it at concrete types. The compile-fail half, that a container,
//! an `Option` and a derived struct do not carry the marker, lives in
//! `tests/ui/scalar/`.

// The borrows are the point: each one picks the reference impl.
#![allow(clippy::needless_borrows_for_generic_args)]

use std::convert::Infallible;

use vitaminc_aead::plaintext::{depth, Bytes, Raw};
use vitaminc_aead::{plan, CipherText, Encrypt, Int, Physical, Scalar};
use vitaminc_protected::{AsProtectedRef, Protected, ProtectedRef};

/// What a caller that must seal exactly one leaf asks for, and what it gets:
/// the type says it is a scalar, and the walk agrees.
fn one_leaf<S: Scalar>(value: S) {
    assert_eq!(S::DEPTH, depth::SCALAR);
    let tree = plan::<_, Infallible, _>(value, "aad").expect("a scalar always plans");
    assert!(matches!(tree, CipherText::Single(_)), "not one leaf");
}

// The agreement check for the generic impls, at concrete types.
const _: () = assert!(depth::is_scalar(<[u8; 3] as Encrypt>::DEPTH));
const _: () = assert!(depth::is_scalar(<&[u8; 3] as Encrypt>::DEPTH));
const _: () = assert!(depth::is_scalar(<&&i32 as Encrypt>::DEPTH));
const _: () = assert!(depth::is_scalar(<Protected<String> as Encrypt>::DEPTH));
const _: () = assert!(depth::is_scalar(<&Protected<Vec<u8>> as Encrypt>::DEPTH));
const _: () = assert!(depth::is_scalar(
    <ProtectedRef<'static, str> as Encrypt>::DEPTH
));
const _: () = assert!(depth::is_scalar(
    <&ProtectedRef<'static, [u8]> as Encrypt>::DEPTH
));

#[test]
fn primitives_are_scalars() {
    one_leaf(true);
    one_leaf(&false);
    one_leaf(1.5f32);
    one_leaf(&1.5f32);
    one_leaf(2.5f64);
    one_leaf(&2.5f64);
}

#[test]
fn every_integer_but_u8_is_a_scalar() {
    one_leaf(1i8);
    one_leaf(&1i8);
    one_leaf(1i16);
    one_leaf(&1i16);
    one_leaf(1i32);
    one_leaf(&1i32);
    one_leaf(1i64);
    one_leaf(&1i64);
    one_leaf(1i128);
    one_leaf(&1i128);
    one_leaf(1u16);
    one_leaf(&1u16);
    one_leaf(1u32);
    one_leaf(&1u32);
    one_leaf(1u64);
    one_leaf(&1u64);
    one_leaf(1u128);
    one_leaf(&1u128);
}

#[test]
fn text_and_byte_leaves_are_scalars() {
    one_leaf("hi");
    one_leaf(String::from("hi"));
    one_leaf(&String::from("hi"));
    one_leaf(&[1u8, 2][..]);
    one_leaf(vec![1u8, 2]);
    one_leaf(&vec![1u8, 2]);
    one_leaf([1u8, 2, 3]);
    one_leaf(&[1u8, 2, 3]);
    one_leaf(Bytes(&[1, 2]));
    one_leaf(&Bytes(&[1, 2]));
    one_leaf(Raw(None, Physical::Int(Int::U16(7))));
    one_leaf(&Raw(None, Physical::Null));
}

#[test]
fn a_borrow_of_a_scalar_borrow_is_a_scalar() {
    one_leaf(&&42i32);
    one_leaf(&&"hi");
}

#[test]
fn protected_forms_of_a_scalar_are_scalars() {
    one_leaf(Protected::new(String::from("hi")));
    one_leaf(&Protected::new(vec![1u8, 2]));
    one_leaf(Protected::new(42i64));

    let text = Protected::new(String::from("hi"));
    let borrowed: ProtectedRef<'_, String> = text.as_protected_ref();
    one_leaf(&borrowed);
    one_leaf(borrowed);

    let bytes = Protected::new([1u8, 2, 3]);
    one_leaf(bytes.as_protected_ref());
}

#[cfg(feature = "chrono")]
#[test]
fn chrono_types_are_scalars() {
    use chrono::{DateTime, NaiveDate, Utc};
    use vitaminc_aead::Timestamp;

    let date = NaiveDate::from_ymd_opt(2024, 2, 29).expect("valid");
    one_leaf(date);
    one_leaf(&date);
    let instant = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("valid");
    one_leaf(instant);
    one_leaf(&instant);
    let stamp = Timestamp::new(instant).expect("not a leap second");
    one_leaf(&stamp);
    one_leaf(stamp);
}

#[cfg(feature = "rust_decimal")]
#[test]
fn a_decimal_is_a_scalar() {
    let value = rust_decimal::Decimal::new(1234, 2);
    one_leaf(value);
    one_leaf(&value);
}

#[cfg(feature = "uuid")]
#[test]
fn a_uuid_is_a_scalar() {
    let id = uuid::Uuid::from_bytes([7; 16]);
    one_leaf(id);
    one_leaf(&id);
}

// `trybuild` launches rustc and inspects the filesystem, neither of which can
// run inside Miri's isolated interpreter.
#[cfg(not(miri))]
#[test]
fn containers_and_options_are_not_scalars() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/scalar/*.rs");
}
