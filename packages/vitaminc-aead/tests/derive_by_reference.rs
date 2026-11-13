//! A derived struct walks by reference wherever a container holds it: a
//! generic one whose type parameter sits in a container, and one with a
//! lifetime, inside a `Vec` or `Option`, with that lifetime shorter than
//! `'static`.

use std::collections::BTreeMap;

use vitaminc_aead::{to_frame, Encrypt, EncryptRef};
use vitaminc_protected::Controlled;

fn frame<P: Encrypt>(value: P) -> Vec<u8> {
    to_frame(value).expect("frames").risky_ref().to_vec()
}

/// Generic code over a borrowed plaintext, as an index layer writes it.
fn lent<T: ?Sized + EncryptRef>(value: &T) -> Vec<u8> {
    frame(value.lend())
}

#[derive(Clone, Encrypt)]
struct Bag<T> {
    items: Vec<T>,
    maybe: Option<T>,
    named: BTreeMap<String, T>,
}

#[test]
fn a_generic_struct_walks_by_reference_with_its_parameter_in_containers() {
    let bag = Bag {
        items: vec![1u32, 2],
        maybe: None,
        named: BTreeMap::from([("a".to_string(), 3u32)]),
    };
    assert_eq!(frame(&bag), frame(bag.clone()));
    assert_eq!(lent(&bag), frame(bag.clone()));
    assert_eq!(<&Bag<u32> as Encrypt>::DEPTH, <Bag<u32> as Encrypt>::DEPTH);
    assert_eq!(lent(&vec![bag.clone()]), frame(vec![bag]));
}

#[derive(Encrypt)]
struct Named<'a> {
    name: &'a str,
}

#[derive(Encrypt)]
struct Roster<'a> {
    items: Vec<Named<'a>>,
    maybe: Option<Named<'a>>,
}

#[test]
fn a_struct_with_a_lifetime_walks_by_reference_inside_containers() {
    // Not `'static`: the borrow ends with this test.
    let name = String::from("Ada");
    let roster = Roster {
        items: vec![Named { name: &name }],
        maybe: Some(Named { name: &name }),
    };
    let by_ref = frame(&roster);
    assert_eq!(lent(&roster), by_ref);
    assert_eq!(
        frame(Roster {
            items: vec![Named { name: &name }],
            maybe: Some(Named { name: &name }),
        }),
        by_ref
    );
    assert_eq!(
        lent(&vec![Named { name: &name }]),
        frame(vec![Named { name: &name }])
    );
    assert_eq!(
        lent(&Some(Named { name: &name })),
        frame(Some(Named { name: &name }))
    );
}
