//! `#[derive(Plaintext)]` and the sink-based `#[derive(Decrypt)]`, end to
//! end: the calls a derived struct makes, and what a derived target accepts
//! and refuses. Sealing goes through a cipher that keeps the plaintext in
//! the clear and authenticates the AAD, so the tests need no AES.

use std::collections::BTreeMap;

use vitaminc_aead::{
    decrypt, encrypt, Bytes, Context, DecodeError, Decrypt, DecryptError, Int, IntoAad, Logical,
    MapSink, Physical, Plaintext, Raw, SeqSink, Sink, SourceError,
};
use vitaminc_protected::{Controlled, Protected};
use zeroize::ZeroizeOnDrop;

// A sink that records every call, so a derived `Plaintext` can be compared
// with a hand-written one.

#[derive(Debug, Clone, PartialEq)]
enum Event {
    Scalar(Option<Logical>, String),
    Seq(Option<usize>),
    Element,
    EndSeq,
    Map(Option<usize>),
    Entry(String),
    EndMap,
    Passthrough,
}

#[derive(Debug)]
struct RecordError;

impl vitaminc_aead::plaintext::Error for RecordError {
    fn source(_: SourceError) -> Self {
        Self
    }
}

struct Record<'l>(&'l mut Vec<Event>);

impl Sink for Record<'_> {
    type Ok = ();
    type Error = RecordError;
    type Seq = Self;
    type Map = Self;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<(), RecordError> {
        let shown = match value {
            Physical::Null => "null".to_owned(),
            Physical::Bool(b) => b.to_string(),
            Physical::Int(i) => format!("{:?}", i.to_i128()),
            Physical::Float(_) => "float".to_owned(),
            Physical::Text(s) => s.to_owned(),
            Physical::Bytes(b) => format!("{b:?}"),
        };
        self.0.push(Event::Scalar(ty, shown));
        Ok(())
    }

    fn seq(self, len: Option<usize>) -> Result<Self, RecordError> {
        self.0.push(Event::Seq(len));
        Ok(self)
    }

    fn map(self, len: Option<usize>) -> Result<Self, RecordError> {
        self.0.push(Event::Map(len));
        Ok(self)
    }

    fn passthrough<P: Plaintext + Clone>(self, value: P) -> Result<(), RecordError> {
        self.0.push(Event::Passthrough);
        value.visit(Record(self.0))
    }
}

impl SeqSink for Record<'_> {
    type Ok = ();
    type Error = RecordError;
    type Element<'s>
        = Record<'s>
    where
        Self: 's;

    fn element(&mut self) -> Result<Record<'_>, RecordError> {
        self.0.push(Event::Element);
        Ok(Record(self.0))
    }

    fn end(self) -> Result<(), RecordError> {
        self.0.push(Event::EndSeq);
        Ok(())
    }
}

impl MapSink for Record<'_> {
    type Ok = ();
    type Error = RecordError;
    type Entry<'s>
        = Record<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Record<'_>, RecordError> {
        self.0.push(Event::Entry(key.to_owned()));
        Ok(Record(self.0))
    }

    fn end(self) -> Result<(), RecordError> {
        self.0.push(Event::EndMap);
        Ok(())
    }
}

fn record<P: Plaintext>(p: P) -> Vec<Event> {
    let mut log = Vec::new();
    p.visit(Record(&mut log)).expect("records");
    log
}

// A cipher that keeps the plaintext in the clear and authenticates the AAD.

#[derive(Debug, Clone, PartialEq, Eq)]
struct Leaf {
    aad: Vec<u8>,
    plaintext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refused;

struct Mock;

impl vitaminc_aead::seal::Cipher for Mock {
    type Leaf = Leaf;
    type Error = Refused;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Leaf, Refused> {
        Ok(Leaf {
            aad: aad.as_bytes().to_vec(),
            plaintext: plaintext.risky_unwrap(),
        })
    }

    fn open(&self, leaf: Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Refused> {
        if leaf.aad != aad.as_bytes() {
            return Err(Refused);
        }
        Ok(Protected::new(leaf.plaintext))
    }
}

fn round_trip<T: Decrypt>(p: impl Plaintext) -> Result<T, DecryptError<DecodeError, Refused>> {
    decrypt(&Mock, encrypt(p, &Mock, "ctx").expect("encrypts"), "ctx")
}

fn refusal<T>(r: Result<T, DecryptError<DecodeError, Refused>>) -> DecodeError {
    match r {
        Err(DecryptError::Sink(e)) => e,
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("decoded"),
    }
}

// The ADR's section 1 example, derived and by hand.

#[derive(Plaintext, Decrypt, Debug, PartialEq, Clone, zeroize::Zeroize)]
struct User {
    email: String,
    age: u32,
    signed_up: i32,
}

struct HandWritten(User);

impl Plaintext for HandWritten {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(3))?;
        self.0.email.visit(map.entry("email")?)?;
        self.0.age.visit(map.entry("age")?)?;
        self.0.signed_up.visit(map.entry("signed_up")?)?;
        map.end()
    }
}

fn ada() -> User {
    User {
        email: "ada@example.com".into(),
        age: 36,
        signed_up: 19_000,
    }
}

#[test]
fn a_derived_struct_makes_the_same_calls_as_the_hand_written_one() {
    assert_eq!(record(ada()), record(HandWritten(ada())));
    assert_eq!(
        record(ada()),
        [
            Event::Map(Some(3)),
            Event::Entry("email".into()),
            Event::Scalar(None, "ada@example.com".into()),
            Event::Entry("age".into()),
            Event::Scalar(None, "Some(36)".into()),
            Event::Entry("signed_up".into()),
            Event::Scalar(None, "Some(19000)".into()),
            Event::EndMap,
        ]
    );
}

#[test]
fn a_derived_struct_round_trips() {
    assert_eq!(round_trip::<User>(ada()).expect("decodes"), ada());
    // Its ciphertext is the equivalent map's: a map target reads a derived
    // struct, and a map of the same entries reads as the struct.
    struct AsMap;
    impl Plaintext for AsMap {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut map = sink.map(Some(3))?;
            36u32.visit(map.entry("age")?)?;
            "ada@example.com".visit(map.entry("email")?)?;
            19_000i32.visit(map.entry("signed_up")?)?;
            map.end()
        }
    }
    assert_eq!(round_trip::<User>(AsMap).expect("decodes"), ada());
    assert!(matches!(
        refusal(round_trip::<BTreeMap<String, String>>(ada())),
        DecodeError::Expected("string")
    ));
}

#[derive(Plaintext, Decrypt, Debug, PartialEq, Clone)]
struct Account {
    owner: User,
    aliases: Vec<String>,
    nickname: Option<String>,
    scores: Vec<Option<u32>>,
    nested: Vec<Vec<u8>>,
}

#[test]
fn nested_structs_options_and_vecs_round_trip() {
    let account = Account {
        owner: ada(),
        aliases: vec!["ada".into(), "countess".into()],
        nickname: None,
        scores: vec![Some(1), None, Some(3)],
        nested: vec![vec![1, 2], vec![]],
    };
    assert_eq!(
        round_trip::<Account>(account.clone()).expect("decodes"),
        account
    );
    let with_nickname = Account {
        nickname: Some("Ada".into()),
        ..account
    };
    assert_eq!(
        round_trip::<Account>(with_nickname.clone()).expect("decodes"),
        with_nickname
    );
}

#[test]
fn an_unknown_key_and_a_missing_field_are_refused_by_name() {
    struct Extra;
    impl Plaintext for Extra {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut map = sink.map(Some(4))?;
            "ada@example.com".visit(map.entry("email")?)?;
            36u32.visit(map.entry("age")?)?;
            0i32.visit(map.entry("signed_up")?)?;
            "admiral".visit(map.entry("rank")?)?;
            map.end()
        }
    }
    assert!(matches!(
        refusal(round_trip::<User>(Extra)),
        DecodeError::UnknownKey(key) if key == "rank"
    ));

    let mut missing = BTreeMap::new();
    missing.insert("email", "ada@example.com");
    assert!(matches!(
        refusal(round_trip::<User>(missing)),
        DecodeError::MissingField("age")
    ));
}

/// A missing entry is refused even when the field could hold nothing: an
/// absent entry is not authenticated, so it is never read as a default.
#[test]
fn a_missing_option_or_passthrough_field_is_refused() {
    struct NoNickname;
    impl Plaintext for NoNickname {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut map = sink.map(Some(4))?;
            ada().visit(map.entry("owner")?)?;
            vec!["ada"].visit(map.entry("aliases")?)?;
            vec![Some(1u32)].visit(map.entry("scores")?)?;
            vec![vec![1u8]].visit(map.entry("nested")?)?;
            map.end()
        }
    }
    assert!(matches!(
        refusal(round_trip::<Account>(NoNickname)),
        DecodeError::MissingField("nickname")
    ));

    struct NoTenant;
    impl Plaintext for NoTenant {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut map = sink.map(Some(3))?;
            map.entry("tags")?.passthrough(vec![1u32])?;
            "123".visit(map.entry("ssn")?)?;
            "hi".visit(map.entry("n")?)?;
            map.end()
        }
    }
    assert!(matches!(
        refusal(round_trip::<Row>(NoTenant)),
        DecodeError::MissingField("tenant")
    ));
}

#[test]
fn a_field_of_the_wrong_kind_is_refused_by_the_fields_name() {
    let mut wrong = BTreeMap::new();
    wrong.insert("email", "ada@example.com");
    wrong.insert("age", "thirty-six");
    wrong.insert("signed_up", "0");
    assert!(matches!(
        refusal(round_trip::<User>(wrong)),
        DecodeError::Expected("u32")
    ));
}

#[test]
fn a_struct_target_refuses_a_scalar_a_sequence_and_a_passthrough() {
    assert!(matches!(
        refusal(round_trip::<User>(34u32)),
        DecodeError::Expected("User")
    ));
    assert!(matches!(
        refusal(round_trip::<User>(vec![34u32])),
        DecodeError::Expected("User")
    ));
    struct Clear;
    impl Plaintext for Clear {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.passthrough(ada())
        }
    }
    assert!(matches!(
        refusal(round_trip::<User>(Clear)),
        DecodeError::Expected("User")
    ));
}

/// A source that repeats a key, which the walk would have refused: the
/// derived sink refuses it too rather than let last-wins overwrite a
/// decoded field.
#[test]
fn a_repeated_key_is_refused_by_the_sink_itself() {
    struct Repeats;
    impl Plaintext for Repeats {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut map = sink.map(None)?;
            "a@b".visit(map.entry("email")?)?;
            "c@d".visit(map.entry("email")?)?;
            map.end()
        }
    }
    assert!(matches!(
        Repeats.visit(User::sink()),
        Err(DecodeError::DuplicateKey(key)) if key == "email"
    ));
}

// Passthrough, skip and take.

#[derive(Plaintext, Decrypt, Debug, PartialEq, Clone)]
struct Row {
    #[aead(passthrough)]
    tenant: String,
    #[aead(passthrough)]
    tags: Vec<u32>,
    ssn: String,
    #[aead(skip)]
    cached: Option<u64>,
    #[aead(rename = "n")]
    note: String,
}

#[test]
fn passthrough_fields_travel_in_the_clear_and_come_back() {
    let row = Row {
        tenant: "acme".into(),
        tags: vec![1, 2],
        ssn: "123".into(),
        cached: Some(9),
        note: "hi".into(),
    };
    let events = record(row.clone());
    assert_eq!(events[0], Event::Map(Some(4)));
    assert_eq!(events[1], Event::Entry("tenant".into()));
    assert_eq!(events[2], Event::Passthrough);
    assert!(!events.contains(&Event::Entry("cached".into())));
    assert!(events.contains(&Event::Entry("n".into())));

    // Only the sealed fields are leaves; the passthrough ones are frames.
    let sealed = encrypt(row.clone(), &Mock, "ctx").expect("encrypts");
    let leaves = vitaminc_aead::seal::leaves_with_aad(sealed, &"ctx".into_aad());
    assert_eq!(leaves.len(), 2);

    let sealed = encrypt(row.clone(), &Mock, "ctx").expect("encrypts");
    let back: Row = decrypt(&Mock, sealed, "ctx").expect("decodes");
    assert_eq!(
        back,
        Row {
            cached: None,
            ..row
        }
    );
}

#[test]
fn a_passthrough_field_refuses_a_sealed_value_and_a_sealed_field_refuses_a_passthrough() {
    struct Swapped;
    impl Plaintext for Swapped {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut map = sink.map(Some(4))?;
            "acme".visit(map.entry("tenant")?)?;
            map.entry("tags")?.passthrough(vec![1u32])?;
            map.entry("ssn")?.passthrough("123")?;
            "hi".visit(map.entry("n")?)?;
            map.end()
        }
    }
    assert!(matches!(
        refusal(round_trip::<Row>(Swapped)),
        DecodeError::Expected("passthrough")
    ));
    struct SealedPassthrough;
    impl Plaintext for SealedPassthrough {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut map = sink.map(Some(4))?;
            map.entry("tenant")?.passthrough("acme")?;
            map.entry("tags")?.passthrough(vec![1u32])?;
            map.entry("ssn")?.passthrough("123")?;
            "hi".visit(map.entry("n")?)?;
            map.end()
        }
    }
    assert!(matches!(
        refusal(round_trip::<Row>(SealedPassthrough)),
        DecodeError::Expected("string")
    ));
}

/// A skipped field is never looked for, so an entry under its key is
/// refused as unknown: turning a sealed field into a skipped one is a wire
/// change, not a silent drop of what was sealed before.
#[test]
fn an_entry_under_a_skipped_key_is_refused() {
    struct WithCached;
    impl Plaintext for WithCached {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut map = sink.map(Some(5))?;
            map.entry("tenant")?.passthrough("acme")?;
            map.entry("tags")?.passthrough(vec![1u32])?;
            "123".visit(map.entry("ssn")?)?;
            9u64.visit(map.entry("cached")?)?;
            "hi".visit(map.entry("n")?)?;
            map.end()
        }
    }
    assert!(matches!(
        refusal(round_trip::<Row>(WithCached)),
        DecodeError::UnknownKey(key) if key == "cached"
    ));
}

/// A `ZeroizeOnDrop` type has a `Drop` impl, so its fields cannot be moved
/// out; `take` swaps each for its default instead, and the empty value is
/// wiped harmlessly when `self` drops.
#[derive(Plaintext, Decrypt, ZeroizeOnDrop, Debug, PartialEq)]
struct Secret {
    #[aead(take)]
    token: String,
    #[aead(take)]
    salt: Vec<u8>,
}

#[derive(Plaintext, Decrypt, ZeroizeOnDrop, Debug, PartialEq)]
struct Token(#[aead(take)] String);

#[test]
fn take_lets_a_drop_type_derive() {
    let secret = Secret {
        token: "t0k3n".into(),
        salt: vec![1, 2, 3],
    };
    let back: Secret = round_trip(secret).expect("decodes");
    assert_eq!(back.token, "t0k3n");
    assert_eq!(back.salt, [1, 2, 3]);
    let back: Token = round_trip(Token("t0k3n".into())).expect("decodes");
    assert_eq!(back.0, "t0k3n");
}

// Newtypes, tuple structs, empty structs and enums.

#[derive(Plaintext, Decrypt, Debug, PartialEq)]
struct Wrapper(Vec<u16>);

#[derive(Plaintext, Decrypt, Debug, PartialEq)]
struct Pair(String, u32);

#[derive(Plaintext, Decrypt, Debug, PartialEq)]
struct Marker;

#[derive(Plaintext, Decrypt, Debug, PartialEq)]
struct Braced {}

#[derive(Plaintext, Decrypt, Debug, PartialEq, Clone, Copy)]
enum Status {
    Active,
    Suspended = 7,
    Closed,
}

#[test]
fn a_newtype_is_transparent() {
    assert_eq!(record(Wrapper(vec![1, 2])), record(vec![1u16, 2]));
    assert_eq!(
        round_trip::<Wrapper>(vec![1u16, 2]).expect("decodes"),
        Wrapper(vec![1, 2])
    );
    assert_eq!(
        round_trip::<Vec<u16>>(Wrapper(vec![3])).expect("decodes"),
        [3]
    );
}

#[test]
fn a_tuple_struct_is_keyed_by_index() {
    let events = record(Pair("a".into(), 1));
    assert_eq!(events[1], Event::Entry("0".into()));
    assert_eq!(events[3], Event::Entry("1".into()));
    assert_eq!(
        round_trip::<Pair>(Pair("a".into(), 1)).expect("decodes"),
        Pair("a".into(), 1)
    );
}

#[test]
fn an_empty_struct_is_an_empty_map_and_refuses_any_entry() {
    assert_eq!(record(Marker), [Event::Map(Some(0)), Event::EndMap]);
    assert_eq!(round_trip::<Marker>(Marker).expect("decodes"), Marker);
    assert_eq!(round_trip::<Braced>(Braced {}).expect("decodes"), Braced {});
    let mut map = BTreeMap::new();
    map.insert("x", 1u32);
    assert!(matches!(
        refusal(round_trip::<Marker>(map)),
        DecodeError::UnknownKey(key) if key == "x"
    ));
}

#[test]
fn a_fieldless_enum_is_a_fixed_width_leaf_holding_its_discriminant() {
    assert_eq!(
        record(Status::Suspended),
        [Event::Scalar(None, "Some(7)".into())]
    );
    for status in [Status::Active, Status::Suspended, Status::Closed] {
        assert_eq!(round_trip::<Status>(status).expect("decodes"), status);
    }
    // Any width reads back, as for any int target; a value that is no
    // variant's, or a different kind, is refused by the enum's name.
    assert_eq!(round_trip::<Status>(8u16).expect("decodes"), Status::Closed);
    assert_eq!(round_trip::<Status>(0i64).expect("decodes"), Status::Active);
    assert!(matches!(
        refusal(round_trip::<Status>(1u32)),
        DecodeError::Expected("Status")
    ));
    assert!(matches!(
        refusal(round_trip::<Status>(-1i8)),
        DecodeError::Expected("Status")
    ));
    assert!(matches!(
        refusal(round_trip::<Status>("Active")),
        DecodeError::Expected("Status")
    ));
    // An int with a logical type is not a plain int, and a wide value whose
    // low 32 bits are a variant's is not that variant.
    assert!(matches!(
        refusal(round_trip::<Status>(Raw(
            Some(Logical::Date),
            Physical::Int(Int::I32(7))
        ))),
        DecodeError::Expected("Status")
    ));
    assert!(matches!(
        refusal(round_trip::<Status>((1u64 << 32) | 7)),
        DecodeError::Expected("Status")
    ));
    assert_eq!(
        round_trip::<Vec<Status>>(vec![Status::Active, Status::Suspended]).expect("decodes"),
        [Status::Active, Status::Suspended]
    );
}

/// Every variant seals to a leaf of the same length, so the ciphertext's
/// size does not give the variant away.
#[test]
fn every_variant_seals_to_the_same_length() {
    let lengths: Vec<usize> = [Status::Active, Status::Suspended, Status::Closed]
        .into_iter()
        .map(|status| {
            let sealed = encrypt(status, &Mock, "ctx").expect("seals");
            match sealed {
                vitaminc_aead::CipherText::Single(leaf) => leaf.plaintext.len(),
                _ => panic!("not a single leaf"),
            }
        })
        .collect();
    assert!(lengths.iter().all(|&l| l == lengths[0]), "{lengths:?}");
    // The tag and four bytes of discriminant.
    assert_eq!(lengths[0], 5);
}

// Later fields reach their sinks through the right-hand side of the
// `Either` chain, for every kind of child.

#[derive(Plaintext, Decrypt, Debug, PartialEq, Clone)]
struct Mixed {
    first: u32,
    second: BTreeMap<String, u32>,
    third: Option<Vec<u32>>,
    #[aead(passthrough)]
    fourth: Vec<String>,
}

#[derive(Plaintext, Decrypt, Debug, PartialEq, Clone)]
struct Named(BTreeMap<String, Vec<u32>>);

#[test]
fn later_fields_reach_their_sinks_through_the_chain() {
    let mut second = BTreeMap::new();
    second.insert(String::from("a"), 1);
    let mixed = Mixed {
        first: 0,
        second,
        third: Some(vec![2, 3]),
        fourth: vec!["x".into()],
    };
    assert_eq!(round_trip::<Mixed>(mixed.clone()).expect("decodes"), mixed);
}

#[test]
fn a_newtype_over_a_container_is_transparent_and_refuses_a_passthrough() {
    let mut inner = BTreeMap::new();
    inner.insert(String::from("a"), vec![1]);
    assert_eq!(
        round_trip::<Named>(Named(inner.clone())).expect("decodes"),
        Named(inner)
    );
    struct Clear;
    impl Plaintext for Clear {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.passthrough(vec![1u16])
        }
    }
    assert!(matches!(
        refusal(round_trip::<Wrapper>(Clear)),
        DecodeError::Expected("sequence")
    ));
    assert!(matches!(
        refusal(round_trip::<Named>(vec![1u16])),
        DecodeError::Expected("map")
    ));
}

// Generics and the crate attribute.

#[derive(Plaintext, Decrypt, Debug, PartialEq)]
struct Holder<T, const N: usize> {
    value: T,
    bytes: [u8; N],
}

#[test]
fn generic_structs_derive() {
    let holder = Holder {
        value: vec![String::from("x")],
        bytes: [7u8; 4],
    };
    assert_eq!(
        round_trip::<Holder<Vec<String>, 4>>(Holder {
            value: vec![String::from("x")],
            bytes: [7u8; 4],
        })
        .expect("decodes"),
        holder
    );
}

mod umbrella {
    pub mod aead {
        pub use vitaminc_aead::*;
    }
}

#[derive(umbrella::aead::Plaintext, umbrella::aead::Decrypt, Debug, PartialEq)]
#[aead(crate = "crate::umbrella::aead")]
struct Renamed {
    value: u32,
}

#[test]
fn the_crate_attribute_reaches_every_path() {
    assert_eq!(
        round_trip::<Renamed>(Renamed { value: 1 }).expect("decodes"),
        Renamed { value: 1 }
    );
}

/// `Protected<Name>` walks through the by-reference impl, so it must make
/// the same calls as the by-value impl for every shape the derive accepts.
#[test]
fn the_by_reference_walk_makes_the_same_calls_as_the_by_value_walk() {
    let row = Row {
        tenant: "acme".into(),
        tags: vec![1, 2],
        ssn: "123".into(),
        cached: Some(9),
        note: "hi".into(),
    };
    assert_eq!(record(&row), record(row.clone()));
    let wrapper = Wrapper(vec![1, 2]);
    assert_eq!(record(&wrapper), record(wrapper));
    let pair = Pair("a".into(), 1);
    assert_eq!(record(&pair), record(pair));
    assert_eq!(record(&Marker), record(Marker));
    assert_eq!(record(&Braced {}), record(Braced {}));
    // `Status` is `Copy`, so name the reference to walk the by-reference
    // impl rather than the by-value one.
    let status: &Status = &Status::Suspended;
    assert_eq!(record(status), record(Status::Suspended));
}

/// A struct that borrows what it encrypts, such as request data, derives
/// too, and walks the same by reference as by value: a borrowed field is
/// then visited as `&&'a str`, `&Option<&'a str>` and so on.
#[derive(Plaintext, Clone)]
struct NewUser<'a> {
    email: &'a str,
    nickname: Option<&'a str>,
    aliases: Vec<&'a str>,
    avatar: &'a [u8],
    #[aead(passthrough)]
    tenant: &'a str,
    joined: Raw<'a>,
    salt: Bytes<'a>,
}

#[test]
fn a_struct_with_borrowed_fields_walks_the_same_by_reference() {
    let avatar = [1u8, 2, 3];
    let user = NewUser {
        email: "ada@example.com",
        nickname: Some("ada"),
        aliases: vec!["a", "l"],
        avatar: &avatar,
        tenant: "acme",
        joined: Raw(Some(Logical::Date), Physical::Int(Int::I32(19_000))),
        salt: Bytes(&avatar),
    };
    let by_value = record(user.clone());
    assert_eq!(by_value[0], Event::Map(Some(7)));
    assert_eq!(record(&user), by_value);
    let sealed = encrypt(&user, &Mock, "ctx").expect("encrypts");
    let leaves = vitaminc_aead::seal::leaves_with_aad(sealed, &"ctx".into_aad());
    // Every scalar but the passthrough tenant is a leaf.
    assert_eq!(leaves.len(), 7);
}

// Custody: a walk that fails part way wipes the fields it did not reach,
// and a struct inside a `Protected` stays wrapped for the whole walk.

/// A leaf that counts how often it is wiped. Visiting it by value wraps it,
/// as every owned leaf does, so a completed or discarded walk wipes it once;
/// a bare drop does not.
#[derive(Clone)]
struct Counted(std::rc::Rc<std::cell::Cell<usize>>);

impl zeroize::Zeroize for Counted {
    fn zeroize(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

impl Plaintext for Counted {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        Protected::new(self).visit(sink)
    }
}

impl Plaintext for &Counted {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Null)
    }
}

#[derive(Plaintext, zeroize::Zeroize)]
struct Three {
    a: Counted,
    b: Counted,
    c: Counted,
}

/// A sink that refuses the entry under `stop_at` and accepts everything
/// else.
struct StopAt(&'static str);

impl Sink for StopAt {
    type Ok = ();
    type Error = RecordError;
    type Seq = Self;
    type Map = Self;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), RecordError> {
        Ok(())
    }

    fn seq(self, _: Option<usize>) -> Result<Self, RecordError> {
        Ok(self)
    }

    fn map(self, _: Option<usize>) -> Result<Self, RecordError> {
        Ok(self)
    }

    fn passthrough<P: Plaintext + Clone>(self, _: P) -> Result<(), RecordError> {
        Ok(())
    }
}

impl SeqSink for StopAt {
    type Ok = ();
    type Error = RecordError;
    type Element<'s>
        = StopAt
    where
        Self: 's;

    fn element(&mut self) -> Result<StopAt, RecordError> {
        Ok(StopAt(self.0))
    }

    fn end(self) -> Result<(), RecordError> {
        Ok(())
    }
}

impl MapSink for StopAt {
    type Ok = ();
    type Error = RecordError;
    type Entry<'s>
        = StopAt
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<StopAt, RecordError> {
        if key == self.0 {
            return Err(RecordError);
        }
        Ok(StopAt(self.0))
    }

    fn end(self) -> Result<(), RecordError> {
        Ok(())
    }
}

fn three() -> (Three, std::rc::Rc<std::cell::Cell<usize>>) {
    let wipes = std::rc::Rc::new(std::cell::Cell::new(0));
    let three = Three {
        a: Counted(wipes.clone()),
        b: Counted(wipes.clone()),
        c: Counted(wipes.clone()),
    };
    (three, wipes)
}

#[test]
fn a_failed_walk_wipes_the_fields_it_did_not_reach() {
    // `a` is visited (and wiped by its own walk); the sink refuses `b`'s
    // entry; `b` and `c` are discarded through their own walks, not dropped
    // bare. Three wipes, not one.
    let (value, wipes) = three();
    assert!(value.visit(StopAt("b")).is_err());
    assert_eq!(wipes.get(), 3);
    // A completed walk wipes each field once, through its own walk.
    let (value, wipes) = three();
    value.visit(StopAt("none")).expect("walks");
    assert_eq!(wipes.get(), 3);
}

#[test]
fn a_walk_refused_at_the_map_or_at_a_value_wipes_every_field() {
    // The sink refuses the map: all three fields are discarded.
    let (value, wipes) = three();
    assert!(value.visit(u32::sink()).is_err());
    assert_eq!(wipes.get(), 3);
    // `a`'s value is refused: `a` wipes itself; `b` and `c` are discarded.
    let (value, wipes) = three();
    assert!(value.visit(BTreeMap::<String, u32>::sink()).is_err());
    assert_eq!(wipes.get(), 3);
}

#[test]
fn a_struct_inside_protected_stays_wrapped_and_is_wiped_whole() {
    // Walked by reference from inside the wrapper, so nothing leaves it
    // during the walk; the wrapper wipes all three when it drops, whether
    // the walk completed or not.
    let (value, wipes) = three();
    assert!(Protected::new(value).visit(StopAt("b")).is_err());
    assert_eq!(wipes.get(), 3);
    let (value, wipes) = three();
    Protected::new(value).visit(StopAt("none")).expect("walks");
    assert_eq!(wipes.get(), 3);
    // And the walk from inside the wrapper is the same walk.
    let mut by_value = Vec::new();
    ada().visit(Record(&mut by_value)).expect("records");
    let mut wrapped = Vec::new();
    Protected::new(ada())
        .visit(Record(&mut wrapped))
        .expect("records");
    assert_eq!(by_value, wrapped);
    let back: User = round_trip(Protected::new(ada())).expect("decodes");
    assert_eq!(back, ada());
}

// Custody: a `Protected` field stays wrapped on the way in and is read
// straight back into `Protected` on the way out.

#[derive(Plaintext, Decrypt)]
struct Keyed {
    key: Protected<[u8; 4]>,
    label: String,
}

#[test]
fn protected_fields_stay_wrapped() {
    let keyed = || Keyed {
        key: Protected::new([1, 2, 3, 4]),
        label: "k".into(),
    };
    let events = record(keyed());
    assert_eq!(events[2], Event::Scalar(None, "[1, 2, 3, 4]".into()));
    let back: Keyed = round_trip(keyed()).expect("decodes");
    assert_eq!(back.key.risky_ref(), &[1, 2, 3, 4]);
    assert_eq!(back.label, "k");
}

// A const generic of any type, not only `usize`, passes through the derive
// unchanged: the generated sink repeats the struct's generics as written.

#[derive(Plaintext, Decrypt, Debug, PartialEq, Clone)]
struct Window<const N: u32> {
    start: i64,
}

#[test]
fn a_const_generic_of_a_non_usize_type_round_trips() {
    let window = Window::<7> { start: -3 };
    assert_eq!(
        round_trip::<Window<7>>(window.clone()).expect("decodes"),
        window
    );
}
