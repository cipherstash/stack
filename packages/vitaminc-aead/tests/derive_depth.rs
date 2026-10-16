//! `Encrypt::DEPTH`, and the compile-time depth check in `#[derive(Encrypt)]`.
//!
//! The check is only worth having if it agrees with the walk: a type whose
//! `DEPTH` is at most `MAX_DEPTH` must encrypt when fully populated, and one
//! deeper must be refused. These tests pin that agreement at the boundary,
//! for sequences, maps, derived structs and passthrough fields, so the
//! compile-time count and the encrypting sink's count cannot drift apart.
//! The compile-fail half lives in `tests/ui/derive/sink_too_deep.rs`.

// A type 128 levels deep takes more than the default 128 steps for rustc to
// resolve, as it would in any crate that builds one.
#![recursion_limit = "512"]

use std::collections::{BTreeMap, HashMap};

use vitaminc_aead::frame::MAX_DEPTH;
use vitaminc_aead::plaintext::depth;
use vitaminc_aead::{plan, Encrypt, EncryptError, MapSink, Sink, Unencryptable};
use vitaminc_protected::Protected;

type V2<T> = Vec<Vec<T>>;
type V4<T> = V2<V2<T>>;
type V8<T> = V4<V4<T>>;
type V16<T> = V8<V8<T>>;
type V32<T> = V16<V16<T>>;
type V64<T> = V32<V32<T>>;
type V128<T> = V64<V64<T>>;
/// One and two levels short of `MAX_DEPTH`.
type V127<T> = V64<V32<V16<V8<V4<V2<Vec<T>>>>>>>;
type V126<T> = V64<V32<V16<V8<V4<V2<T>>>>>>;

/// The fully populated value of a type: one element in every sequence, so
/// the value nests as deep as the type allows.
trait Full {
    fn full() -> Self;
}

impl Full for u32 {
    fn full() -> Self {
        7
    }
}

impl<T: Full> Full for Vec<T> {
    fn full() -> Self {
        vec![T::full()]
    }
}

impl<T: Full> Full for HashMap<String, T> {
    fn full() -> Self {
        HashMap::from([("k".to_owned(), T::full())])
    }
}

/// Whether the encrypting sink accepts `value`, or refuses it as too deep.
fn accepted<P: Encrypt>(value: P) -> bool {
    match plan::<_, (), _>(value, "aad") {
        Ok(_) => true,
        Err(EncryptError::Shape(refusal)) if refusal.reason() == Unencryptable::TooDeep => false,
        Err(other) => panic!("refused for another reason: {other:?}"),
    }
}

#[test]
fn a_scalar_has_depth_zero_and_each_container_adds_one() {
    assert_eq!(<u32 as Encrypt>::DEPTH, Some(0));
    assert_eq!(<String as Encrypt>::DEPTH, Some(0));
    assert_eq!(<Vec<u8> as Encrypt>::DEPTH, Some(0), "bytes are a leaf");
    assert_eq!(
        <Option<u32> as Encrypt>::DEPTH,
        Some(0),
        "None is a null leaf"
    );
    assert_eq!(<Vec<u32> as Encrypt>::DEPTH, Some(1));
    assert_eq!(<BTreeMap<String, Vec<u32>> as Encrypt>::DEPTH, Some(2));
    assert_eq!(<&Vec<Option<u32>> as Encrypt>::DEPTH, Some(1));
    assert_eq!(<V128<u32> as Encrypt>::DEPTH, Some(MAX_DEPTH));
}

#[test]
fn the_walk_agrees_with_depth_at_the_limit_for_sequences() {
    assert_eq!(<V128<u32> as Encrypt>::DEPTH, Some(MAX_DEPTH));
    assert!(accepted(V128::<u32>::full()));

    assert_eq!(<Vec<V128<u32>> as Encrypt>::DEPTH, Some(MAX_DEPTH + 1));
    assert!(!accepted(Vec::<V128<u32>>::full()));
}

/// A derived struct is a map: one level for the struct, then its deepest
/// field.
#[derive(Encrypt)]
struct JustFits {
    shallow: u32,
    deep: V127<u32>,
}

#[test]
fn a_derived_struct_is_one_deeper_than_its_deepest_field() {
    assert_eq!(<JustFits as Encrypt>::DEPTH, Some(MAX_DEPTH));
    assert_eq!(<&JustFits as Encrypt>::DEPTH, Some(MAX_DEPTH));
    assert!(accepted(JustFits {
        shallow: 1,
        deep: Full::full(),
    }));
}

/// A passthrough field's frame starts one level below the passthrough node,
/// so it counts one deeper than the same field encrypted.
#[derive(Encrypt)]
struct PassesThrough {
    sealed: u32,
    #[aead(passthrough)]
    clear: V126<u32>,
}

/// The same struct by hand, with a passthrough one level deeper than the
/// derive would accept, to check the walk refuses exactly there.
struct PassesThroughDeeper(Vec<V126<u32>>);

impl Encrypt for PassesThroughDeeper {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(2))?;
        7u32.visit(map.entry("sealed")?)?;
        map.entry("clear")?.passthrough(self.0)?;
        map.end()
    }
}

#[test]
fn the_walk_agrees_with_depth_at_the_limit_for_passthrough() {
    assert_eq!(<PassesThrough as Encrypt>::DEPTH, Some(MAX_DEPTH));
    assert!(accepted(PassesThrough {
        sealed: 1,
        clear: Full::full(),
    }));

    let deeper = depth::container(depth::passthrough(<Vec<V126<u32>> as Encrypt>::DEPTH));
    assert_eq!(deeper, Some(MAX_DEPTH + 1));
    assert!(!accepted(PassesThroughDeeper(Full::full())));
}

/// A newtype is transparent, a fieldless enum is one leaf, and a skipped
/// field is not walked, so none of them adds a level.
#[derive(Encrypt)]
struct Wrapper(Vec<u32>);

#[derive(Encrypt)]
enum Status {
    Active,
}

#[derive(Encrypt)]
struct Skips {
    kept: u32,
    #[aead(skip)]
    #[allow(dead_code)]
    skipped: V128<u32>,
}

#[test]
fn newtypes_enums_and_skipped_fields_add_nothing() {
    assert_eq!(<Wrapper as Encrypt>::DEPTH, Some(1));
    assert_eq!(<Status as Encrypt>::DEPTH, Some(0));
    assert_eq!(<Skips as Encrypt>::DEPTH, Some(1));
    assert!(accepted(Status::Active));
}

/// A generic type's depth follows its parameter.
#[derive(Encrypt)]
struct Holder<T> {
    value: T,
}

#[test]
fn a_generic_type_takes_its_depth_from_its_parameter() {
    assert_eq!(<Holder<u32> as Encrypt>::DEPTH, Some(1));
    assert_eq!(<Holder<Vec<u32>> as Encrypt>::DEPTH, Some(2));
}

/// A type that names itself has no fixed depth; the derive sees that and
/// leaves `DEPTH` as `None` rather than writing a cycle.
#[derive(Encrypt)]
struct Tree {
    label: u32,
    children: Vec<Tree>,
}

#[derive(Encrypt)]
struct List {
    head: u32,
    tail: Option<Vec<Self>>,
}

/// Mutual recursion goes through another type, which the derive cannot see
/// into, so both sides say so.
#[derive(Encrypt)]
#[aead(recursive)]
struct Even {
    next: Vec<Odd>,
}

#[derive(Encrypt)]
#[aead(recursive)]
struct Odd {
    next: Vec<Even>,
}

/// A recursive type inside an ordinary one makes the outer depth unknown
/// too, so the check passes it to the walk.
#[derive(Encrypt)]
struct Forest {
    trees: Vec<Tree>,
}

#[test]
fn a_recursive_type_has_no_fixed_depth_and_the_walk_checks_it() {
    assert_eq!(<Tree as Encrypt>::DEPTH, None);
    assert_eq!(<&Tree as Encrypt>::DEPTH, None);
    assert_eq!(<List as Encrypt>::DEPTH, None);
    assert_eq!(<Even as Encrypt>::DEPTH, None);
    assert_eq!(<Odd as Encrypt>::DEPTH, None);
    assert_eq!(<Forest as Encrypt>::DEPTH, None);

    let shallow = Tree {
        label: 0,
        children: vec![Tree {
            label: 1,
            children: Vec::new(),
        }],
    };
    assert!(accepted(shallow));

    // Each level of the tree is a map and a sequence: two levels per tree.
    let mut deep = Tree {
        label: 0,
        children: Vec::new(),
    };
    for label in 1..=(MAX_DEPTH as u32 / 2 + 1) {
        deep = Tree {
            label,
            children: vec![deep],
        };
    }
    assert!(!accepted(deep));

    let even = Even {
        next: vec![Odd {
            next: vec![Even { next: Vec::new() }],
        }],
    };
    assert!(accepted(even));
}

/// Each source's `DEPTH` is added up by the derive, so each must match the
/// walk it does: too low and a struct compiles whose values are refused,
/// too high and a valid struct does not compile.
#[test]
fn every_source_declares_the_depth_its_walk_has() {
    assert_eq!(<HashMap<String, Vec<u32>> as Encrypt>::DEPTH, Some(2));
    assert_eq!(<&HashMap<String, Vec<u32>> as Encrypt>::DEPTH, Some(2));
    assert_eq!(<&BTreeMap<String, Vec<u32>> as Encrypt>::DEPTH, Some(2));
    assert_eq!(<&[Vec<u32>] as Encrypt>::DEPTH, Some(2));
    assert_eq!(<&Option<Vec<u32>> as Encrypt>::DEPTH, Some(1));
    assert_eq!(<&&Vec<u32> as Encrypt>::DEPTH, Some(1));
    assert_eq!(<Protected<Vec<u32>> as Encrypt>::DEPTH, Some(1));
    assert_eq!(<&Protected<Vec<u32>> as Encrypt>::DEPTH, Some(1));
    assert_eq!(
        <Protected<Vec<u8>> as Encrypt>::DEPTH,
        Some(0),
        "bytes are a leaf"
    );
    assert_eq!(<&[u8] as Encrypt>::DEPTH, Some(0), "bytes are a leaf");
    assert_eq!(<[u8; 16] as Encrypt>::DEPTH, Some(0), "bytes are a leaf");

    assert!(
        accepted(V127::<HashMap<String, u32>>::full()),
        "a map at exactly MAX_DEPTH is accepted"
    );
    assert!(
        !accepted(V128::<HashMap<String, u32>>::full()),
        "a map one level deeper is refused"
    );
    assert!(
        accepted(Protected::new(V128::<u32>::full())),
        "Protected adds no level"
    );
    assert!(
        !accepted(Protected::new(Vec::<V128<u32>>::full())),
        "Protected one level too deep is refused"
    );
}
