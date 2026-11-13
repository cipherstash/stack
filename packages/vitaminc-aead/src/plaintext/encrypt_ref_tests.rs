//! `EncryptRef` and `Lent`: a borrowed plaintext walks exactly as `&T`
//! does, generic code can bound on it, and a passthrough is lent rather
//! than copied.

use std::collections::{BTreeMap, HashMap};

use vitaminc_protected::{AsProtectedRef, Protected};

use super::record::{record, Event, Owned, Record};
use super::{Encrypt, EncryptRef, Sink, Tee};

/// Generic over a borrowed plaintext, bounded on `EncryptRef` alone.
fn lent<T: ?Sized + EncryptRef>(value: &T) -> Vec<Event> {
    record(value.lend()).expect("records")
}

#[test]
fn a_lent_value_walks_as_its_borrow() {
    macro_rules! same {
        ($($value:expr),+ $(,)?) => {$({
            let value = $value;
            assert_eq!(lent(&value), record(&value).expect("records"));
        })+};
    }
    same!(
        42i32,
        1.5f64,
        true,
        String::from("text"),
        vec![1u8, 2],
        [7u8; 4],
        vec![1u32, 2],
        vec![String::from("a"), String::from("b")],
        Some(3u64),
        None::<u64>,
        None::<String>,
        vec![vec![1i64], vec![]],
        vec![Some(1u16), None],
        BTreeMap::from([("k", vec![1i16])]),
        HashMap::from([("k", Some(2i32))]),
        Protected::new(String::from("pw")),
    );
    assert_eq!(lent("text"), record("text").expect("records"));
    assert_eq!(lent(&b"ab"[..]), record(&b"ab"[..]).expect("records"));
}

#[test]
fn the_borrowed_constants_are_the_borrows() {
    fn agree<T: ?Sized + EncryptRef>()
    where
        for<'a> &'a T: Encrypt,
    {
        assert_eq!(T::REF_DEPTH, <&T as Encrypt>::DEPTH);
        assert_eq!(T::REF_FIXED, <&T as Encrypt>::FIXED);
        assert_eq!(<super::Lent<'_, T> as Encrypt>::DEPTH, T::REF_DEPTH);
        assert_eq!(<super::Lent<'_, T> as Encrypt>::FIXED, T::REF_FIXED);
    }
    agree::<i64>();
    agree::<str>();
    agree::<Option<i32>>();
    agree::<Vec<Option<String>>>();
    agree::<Protected<u32>>();
    assert_eq!(i64::REF_FIXED, <&i64 as Encrypt>::FIXED);
    assert!(
        i64::REF_FIXED.is_some(),
        "a fixed-width scalar keeps its type"
    );
}

/// A borrowed `None` of a fixed-width type is still a typed null.
#[test]
fn a_lent_none_is_typed() {
    let none: Option<i64> = None;
    assert!(matches!(lent(&none).as_slice(), [Event::TypedNull(_)]));
}

/// A passthrough is lent to every sink a `Tee` feeds, so a subtree that
/// cannot be cloned still reaches both, and each sees the same walk.
#[test]
fn a_tee_lends_a_passthrough_it_cannot_clone() {
    struct NotClone(u32);
    impl Encrypt for &NotClone {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            self.0.visit(sink)
        }
    }

    let (mut left, mut right) = (Vec::new(), Vec::new());
    Tee(Record(&mut left), Record(&mut right))
        .passthrough(&NotClone(7))
        .expect("ok");
    assert_eq!(left, right);
    assert_eq!(left.first(), Some(&Event::Passthrough));
    assert_eq!(left[1..], record(7u32).expect("records")[..]);
}

/// A protected borrow lends what it wraps.
#[test]
fn a_protected_borrow_lends_what_it_wraps() {
    let owner = Protected::new(String::from("pw"));
    assert_eq!(
        record(owner.as_protected_ref()).expect("records"),
        [Event::Scalar(None, Owned::Text("pw".into()))]
    );
    assert_eq!(lent(&owner), record(&owner).expect("records"));
}
