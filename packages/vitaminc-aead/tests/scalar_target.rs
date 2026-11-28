//! `ScalarTarget`, the decrypt-side marker for a target that one scalar
//! builds: the counterpart of `Scalar`.
//!
//! No target implements the marker itself: a target carries it when its
//! sink is one a scalar satisfies (`TakesScalar`). The marker is only worth
//! having if it agrees with the sinks. So for every kind of target that
//! carries it, these tests walk one scalar into the target's sink and check
//! what it builds. The compile-fail half lives in `tests/ui/scalar_target/`:
//! a sequence, a map, a derived struct, a newtype of a sequence and a
//! protected sequence do not carry the marker, and no one can give it to
//! them by hand.

use vitaminc_aead::plaintext::Raw;
use vitaminc_aead::{
    Decrypt, Encrypt, FixedType, FromScalar, Logical, OwnedFrame, Physical, ScalarTarget,
    ValueKind, Width,
};
use vitaminc_protected::{Controlled, Protected};

/// What a caller that opens exactly one leaf asks for: the target says one
/// scalar builds it, and the scalar `source` does.
fn built_by_one_scalar<T: ScalarTarget>(source: impl Encrypt) -> T {
    source
        .visit(T::sink())
        .expect("one scalar builds a scalar target")
}

/// A null, as a leaf holds one.
fn null() -> Raw<'static> {
    Raw(None, Physical::Null)
}

#[test]
fn every_built_in_scalar_target_is_built_by_one_scalar() {
    assert!(built_by_one_scalar::<bool>(true), "bool");
    assert_eq!(built_by_one_scalar::<i8>(-8i8), -8, "i8");
    assert_eq!(built_by_one_scalar::<i16>(-16i16), -16, "i16");
    assert_eq!(built_by_one_scalar::<i32>(-32i32), -32, "i32");
    assert_eq!(built_by_one_scalar::<i64>(-64i64), -64, "i64");
    assert_eq!(built_by_one_scalar::<i128>(-128i128), -128, "i128");
    assert_eq!(built_by_one_scalar::<u16>(16u16), 16, "u16");
    assert_eq!(built_by_one_scalar::<u32>(32u32), 32, "u32");
    assert_eq!(built_by_one_scalar::<u64>(64u64), 64, "u64");
    assert_eq!(built_by_one_scalar::<u128>(128u128), 128, "u128");
    assert_eq!(built_by_one_scalar::<f32>(1.5f32), 1.5, "f32");
    assert_eq!(built_by_one_scalar::<f64>(2.5f64), 2.5, "f64");
    assert_eq!(built_by_one_scalar::<String>("hi"), "hi", "String");
    assert_eq!(
        built_by_one_scalar::<Vec<u8>>(vec![1u8, 2]),
        [1, 2],
        "Vec<u8> is one byte leaf, not a sequence"
    );
    assert_eq!(
        built_by_one_scalar::<[u8; 3]>([1u8, 2, 3]),
        [1, 2, 3],
        "[u8; N]"
    );
}

#[test]
fn an_option_is_built_by_a_null_or_by_a_scalar() {
    assert_eq!(
        built_by_one_scalar::<Option<i64>>(null()),
        None,
        "a plain null builds None"
    );
    let typed_null = OwnedFrame::typed_null(FixedType::plain(Width::I64).expect("a fixed type"));
    assert_eq!(
        built_by_one_scalar::<Option<i64>>(&typed_null),
        None,
        "a typed null builds None"
    );
    assert_eq!(
        built_by_one_scalar::<Option<i64>>(34i64),
        Some(34),
        "a scalar builds Some"
    );
    assert_eq!(
        built_by_one_scalar::<Option<Option<String>>>("hi"),
        Some(Some(String::from("hi"))),
        "a nested option"
    );
}

#[test]
fn a_protected_scalar_target_is_built_by_one_scalar() {
    let text = built_by_one_scalar::<Protected<String>>("hi");
    assert_eq!(text.risky_ref(), "hi", "Protected<String>");
    let bytes = built_by_one_scalar::<Protected<Vec<u8>>>(vec![9u8, 8]);
    assert_eq!(bytes.risky_ref(), &[9, 8], "Protected<Vec<u8>>");
    let absent = built_by_one_scalar::<Protected<Option<i64>>>(null());
    assert_eq!(
        absent.risky_ref(),
        &None,
        "Protected<Option<i64>> of a null"
    );
    let present = built_by_one_scalar::<Option<Protected<i64>>>(34i64);
    assert_eq!(
        present.map(|value| *value.risky_ref()),
        Some(34),
        "Option<Protected<i64>> of a scalar"
    );
}

#[test]
fn an_owned_frame_is_built_by_any_scalar_and_by_a_null() {
    let text = built_by_one_scalar::<OwnedFrame>("hi");
    assert_eq!(
        text.frame().kind(),
        Some(ValueKind::String),
        "a text scalar"
    );
    let date = built_by_one_scalar::<OwnedFrame>(Raw(
        Some(Logical::Date),
        Physical::Int(vitaminc_aead::Int::I32(19_782)),
    ));
    assert_eq!(date.frame().kind(), Some(ValueKind::Date), "a date scalar");
    let absent = built_by_one_scalar::<OwnedFrame>(null());
    assert!(absent.frame().is_null(), "a null builds the null frame");
    let present = built_by_one_scalar::<Option<OwnedFrame>>(7u16);
    assert_eq!(
        present.map(|frame| frame.frame().kind()),
        Some(Some(ValueKind::UInt16)),
        "Option<OwnedFrame> of a scalar"
    );
}

/// A scalar target written by hand gets the marker from `FromScalar`.
#[test]
fn a_hand_written_scalar_target_carries_the_marker() {
    #[derive(Debug, PartialEq)]
    struct Percent(u8);
    impl FromScalar for Percent {
        const EXPECTED: &'static str = "percentage";
        fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
            let n = u32::from_scalar(ty, value)?;
            u8::try_from(n).ok().filter(|n| *n <= 100).map(Percent)
        }
    }
    assert_eq!(
        built_by_one_scalar::<Percent>(42u32),
        Percent(42),
        "a FromScalar type"
    );
}

/// A derived newtype reads what its inner type reads. Its sink wraps the
/// inner type's sink, so it is a scalar target with no code of its own.
#[test]
fn a_derived_newtype_of_a_scalar_target_is_one_as_it_is() {
    #[derive(Decrypt, Debug, PartialEq)]
    struct Email(String);
    assert_eq!(
        built_by_one_scalar::<Email>("ada@example.com"),
        Email(String::from("ada@example.com")),
        "a derived newtype of a string"
    );

    #[derive(Decrypt, Debug, PartialEq)]
    struct UserId(u64);
    assert_eq!(
        built_by_one_scalar::<UserId>(42u64),
        UserId(42),
        "a derived newtype of an integer"
    );

    // A newtype of a newtype, and a nullable newtype.
    #[derive(Decrypt, Debug, PartialEq)]
    struct Primary(Email);
    assert_eq!(
        built_by_one_scalar::<Primary>("ada@example.com"),
        Primary(Email(String::from("ada@example.com"))),
        "a derived newtype of a derived newtype"
    );
    assert_eq!(
        built_by_one_scalar::<Option<UserId>>(null()),
        None,
        "an Option of a derived newtype reads a null"
    );

    #[derive(Decrypt, Debug, PartialEq)]
    struct MaybeId(Option<u64>);
    assert_eq!(
        built_by_one_scalar::<MaybeId>(null()),
        MaybeId(None),
        "a derived newtype of an Option reads a null"
    );
}

/// A newtype decrypts into `Protected` once its author says how. `Wrap`
/// moves what the newtype's own sink builds into the wrapper, and a scalar
/// satisfies it when it satisfies that sink.
#[test]
fn a_protected_newtype_is_a_scalar_target_through_wrap() {
    use vitaminc_aead::typed::Wrap;
    use vitaminc_aead::DecryptProtected;
    use zeroize::Zeroize;

    #[derive(Decrypt, Zeroize)]
    struct Email(String);
    impl DecryptProtected for Email {
        type ProtectedSink = Wrap<<Email as Decrypt>::Sink>;
        fn protected_sink() -> Self::ProtectedSink {
            Wrap(Email::sink())
        }
    }
    let email = built_by_one_scalar::<Protected<Email>>("ada@example.com");
    assert_eq!(
        email.risky_ref().0,
        "ada@example.com",
        "a protected derived newtype"
    );
}

/// A target with a sink of its own is a scalar target once that sink is
/// marked as one a scalar satisfies.
#[test]
fn a_hand_written_sink_opts_in_by_its_marker() {
    use vitaminc_aead::typed::{Never, TakesScalar};
    use vitaminc_aead::{DecodeError, EncryptRef, Sink};

    #[derive(Debug, PartialEq)]
    struct Flag(bool);
    struct FlagSink;
    impl Sink for FlagSink {
        type Ok = Flag;
        type Error = DecodeError;
        type Seq = Never<Flag>;
        type Map = Never<Flag>;
        fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<Flag, DecodeError> {
            match (ty, value) {
                (None, Physical::Text("yes")) => Ok(Flag(true)),
                (None, Physical::Text("no")) => Ok(Flag(false)),
                _ => Err(DecodeError::Expected("flag")),
            }
        }
        fn typed_null(self, _: FixedType) -> Result<Flag, DecodeError> {
            Err(DecodeError::Expected("flag"))
        }
        fn seq(self, _: Option<usize>) -> Result<Never<Flag>, DecodeError> {
            Err(DecodeError::Expected("flag"))
        }
        fn map(self, _: Option<usize>) -> Result<Never<Flag>, DecodeError> {
            Err(DecodeError::Expected("flag"))
        }
        fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<Flag, DecodeError> {
            Err(DecodeError::Expected("flag"))
        }
    }
    impl Decrypt for Flag {
        type Sink = FlagSink;
        fn sink() -> FlagSink {
            FlagSink
        }
    }
    impl TakesScalar for FlagSink {}
    assert_eq!(
        built_by_one_scalar::<Flag>("no"),
        Flag(false),
        "a target whose own sink is marked"
    );
}

/// A derived fieldless enum reads an int leaf through `FromScalar`, so it
/// carries the marker with no impl of its own.
#[test]
fn a_derived_fieldless_enum_carries_the_marker() {
    #[derive(Encrypt, Decrypt, Debug, PartialEq, Clone, Copy)]
    enum Status {
        Active = 1,
        Closed = 2,
    }
    assert_eq!(
        built_by_one_scalar::<Status>(Status::Closed),
        Status::Closed,
        "a fieldless enum"
    );
    assert_eq!(
        built_by_one_scalar::<Status>(Status::Active),
        Status::Active,
        "the other variant"
    );
}

#[cfg(feature = "jiff")]
#[test]
fn the_date_and_timestamp_targets_are_built_by_one_scalar() {
    let date = jiff::civil::Date::constant(2024, 2, 29);
    assert_eq!(
        built_by_one_scalar::<jiff::civil::Date>(date),
        date,
        "jiff date"
    );
    let wiped = built_by_one_scalar::<vitaminc_aead::Date>(date);
    assert_eq!(wiped.to_jiff(), date, "this crate's Date");
    let instant = jiff::Timestamp::new(1_700_000_000, 0).expect("valid");
    assert_eq!(
        built_by_one_scalar::<jiff::Timestamp>(instant),
        instant,
        "jiff timestamp"
    );
    let stamp = built_by_one_scalar::<vitaminc_aead::Timestamp>(instant);
    assert_eq!(stamp.to_jiff(), instant, "this crate's Timestamp");
}

#[cfg(feature = "rust_decimal")]
#[test]
fn the_decimal_targets_are_built_by_one_scalar() {
    let value = rust_decimal::Decimal::new(1234, 2);
    assert_eq!(
        built_by_one_scalar::<rust_decimal::Decimal>(value),
        value,
        "rust_decimal"
    );
    let wiped = built_by_one_scalar::<vitaminc_aead::Decimal>(value);
    assert_eq!(wiped.to_decimal(), value, "this crate's Decimal");
}

#[cfg(feature = "uuid")]
#[test]
fn the_uuid_targets_are_built_by_one_scalar() {
    let id = uuid::Uuid::from_bytes([7; 16]);
    assert_eq!(built_by_one_scalar::<uuid::Uuid>(id), id, "uuid");
    let wiped = built_by_one_scalar::<vitaminc_aead::Uuid>(id);
    assert_eq!(wiped.to_uuid(), id, "this crate's Uuid");
}

// `trybuild` launches rustc and inspects the filesystem, neither of which can
// run inside Miri's isolated interpreter.
#[cfg(not(miri))]
#[test]
fn containers_are_not_scalar_targets() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/scalar_target/*.rs");
}
