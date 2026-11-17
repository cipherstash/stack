//! A derived struct walks by reference wherever a container holds it: a
//! generic one whose type parameter sits in a container, and one with a
//! lifetime, inside a `Vec` or `Option`, with that lifetime shorter than
//! `'static`. A passthrough field is lent in either walk, so its type need
//! only be a source by reference.

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

/// A cleartext label that is a source only by reference.
struct Label(String);

impl Encrypt for &Label {
    const DEPTH: Option<usize> = vitaminc_aead::plaintext::depth::SCALAR;
    fn visit<S: vitaminc_aead::Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, vitaminc_aead::Physical::Text(&self.0))
    }
}

#[derive(Encrypt)]
struct Labelled {
    #[aead(passthrough)]
    label: Label,
    secret: String,
}

#[derive(Encrypt)]
struct Tagged<T> {
    #[aead(passthrough)]
    tag: T,
    secret: String,
}

/// A passthrough field is lent to the sink by value and by reference
/// alike, so its type need only be a source by reference: the owned walk
/// neither counts its depth nor discards it by value.
#[test]
fn a_passthrough_field_need_only_be_a_source_by_reference() {
    let labelled = || Labelled {
        label: Label("acme".into()),
        secret: "example-only".into(),
    };
    assert_eq!(frame(labelled()), lent(&labelled()));
    assert_eq!(<Labelled as Encrypt>::DEPTH, <&Labelled as Encrypt>::DEPTH);

    // A parameter only a passthrough field names is bounded on `EncryptRef`
    // alone, by value as well as by reference.
    let tagged = || Tagged {
        tag: Label("acme".into()),
        secret: "example-only".into(),
    };
    assert_eq!(frame(tagged()), lent(&tagged()));
    assert_eq!(
        frame(Tagged {
            tag: vec![1u32],
            secret: "example-only".into(),
        }),
        frame(&Tagged {
            tag: vec![1u32],
            secret: "example-only".into(),
        })
    );
}
