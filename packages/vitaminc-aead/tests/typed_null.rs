//! Typed nulls end to end: a sealed `None` of a fixed-width type is as long
//! as a sealed `Some`, so ciphertext length does not show which values are
//! absent, and it reads back only as an `Option` of the same type. Sealing
//! goes through a cipher that keeps the plaintext in the clear, so a
//! leaf's length is its plaintext's; AES-GCM adds the same nonce and tag
//! to every leaf.

use vitaminc_aead::{
    decrypt, decrypt_to_frame, encrypt, tags, to_frame, CipherText, Context, DecodeError, Decrypt,
    DecryptError, Encrypt, FixedType, Frame, IntoAad, Node, Width,
};
use vitaminc_protected::{Controlled, Protected};

#[derive(Debug)]
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

/// The plaintext of the one leaf `value` seals as.
fn sealed<P: Encrypt>(value: P) -> Vec<u8> {
    match encrypt(value, &Mock, "ctx").expect("encrypts") {
        CipherText::Single(leaf) => leaf.plaintext,
        other => panic!("not one leaf: {other:?}"),
    }
}

/// `None` and `Some(value)` seal to leaves of the same length, the `None`
/// as a typed null, and the `None` reads back as `None`.
fn hides_absence<T>(value: T)
where
    T: Encrypt + Decrypt + PartialEq + core::fmt::Debug,
{
    let none = sealed(None::<T>);
    let some = sealed(Some(value));
    assert_eq!(none.first(), Some(&tags::TYPED_NULL), "{none:?}");
    assert_eq!(none.len(), some.len(), "{none:?} vs {some:?}");
    let read: Option<T> = decrypt(
        &Mock,
        encrypt(None::<T>, &Mock, "ctx").expect("encrypts"),
        "ctx",
    )
    .expect("decrypts");
    assert_eq!(read, None);
}

#[test]
fn every_fixed_width_primitive_hides_absence() {
    hides_absence(-1i8);
    hides_absence(-1i16);
    hides_absence(-1i32);
    hides_absence(-1i64);
    hides_absence(-1i128);
    hides_absence(1u16);
    hides_absence(1u32);
    hides_absence(1u64);
    hides_absence(1u128);
    hides_absence(1.5f32);
    hides_absence(1.5f64);
}

/// A bool's leaf is the tag alone, as short as the plain null, so its
/// `None` stays the plain null and hides nothing it does not already.
#[test]
fn a_bool_none_is_the_plain_null_and_as_long_as_a_bool() {
    assert_eq!(sealed(None::<bool>), [tags::NULL]);
    assert_eq!(sealed(Some(true)).len(), 1);
}

/// Text and bytes are variable width: out of scope, and unchanged.
#[test]
fn a_variable_width_none_is_the_plain_null() {
    assert_eq!(sealed(None::<String>), [tags::NULL]);
    assert_eq!(sealed(None::<Vec<u8>>), [tags::NULL]);
}

#[cfg(feature = "chrono")]
#[test]
fn chrono_types_and_timestamp_hide_absence() {
    use chrono::{DateTime, NaiveDate, Utc};
    hides_absence(NaiveDate::from_ymd_opt(1999, 12, 31).expect("date"));
    hides_absence(DateTime::<Utc>::from_timestamp(1_700_000_000, 5).expect("instant"));
    hides_absence(
        vitaminc_aead::Timestamp::new(DateTime::<Utc>::from_timestamp(7, 0).expect("instant"))
            .expect("not a leap second"),
    );
    // A `Timestamp` and a `DateTime<Utc>` are the one leaf, absent or not.
    assert_eq!(
        sealed(None::<vitaminc_aead::Timestamp>),
        sealed(None::<DateTime<Utc>>)
    );
}

#[cfg(feature = "rust_decimal")]
#[test]
fn a_decimal_hides_absence_whatever_its_scale() {
    use rust_decimal::Decimal;
    for s in ["0", "-1234.5678", "79228162514264337593543950335"] {
        hides_absence(s.parse::<Decimal>().expect("decimal"));
    }
}

#[derive(Encrypt, Decrypt, Debug, PartialEq, Clone, Copy)]
enum Status {
    Active,
    Suspended = 7,
}

#[derive(Encrypt, Decrypt, Debug, PartialEq, Clone, Copy)]
struct Age(u32);

#[test]
fn a_derived_enum_and_newtype_hide_absence() {
    hides_absence(Status::Suspended);
    hides_absence(Age(42));
    let u32 = FixedType::plain(Width::U32);
    assert_eq!(<Age as Encrypt>::FIXED, u32);
    assert_eq!(<&Age as Encrypt>::FIXED, u32);
    assert_eq!(<Status as Encrypt>::FIXED, u32);
    assert!(<Age as Decrypt>::reads_null(u32.expect("fixed")));
    assert!(<Status as Decrypt>::reads_null(u32.expect("fixed")));
    // An absent enum is not one of its variants.
    let read: Result<Status, _> = decrypt(
        &Mock,
        encrypt(None::<Status>, &Mock, "ctx").expect("encrypts"),
        "ctx",
    );
    assert!(matches!(
        read,
        Err(DecryptError::Sink(DecodeError::Expected("Status")))
    ));
}

#[derive(Encrypt, Decrypt, Debug, PartialEq, Clone)]
struct Profile {
    name: String,
    born: Option<i32>,
    score: Option<f64>,
    status: Option<Status>,
}

/// The lengths of a sealed record's leaves, entry by entry.
fn leaf_lengths(node: Node<Leaf>) -> Vec<(String, usize)> {
    match node {
        CipherText::Map(entries) => entries
            .into_iter()
            .map(|(key, value)| match value {
                CipherText::Single(leaf) => (key, leaf.plaintext.len()),
                other => panic!("{key}: not one leaf: {other:?}"),
            })
            .collect(),
        other => panic!("not a map: {other:?}"),
    }
}

#[test]
fn a_struct_with_optional_fields_seals_the_same_lengths_either_way() {
    let present = Profile {
        name: "Ada".into(),
        born: Some(1815),
        score: Some(9.5),
        status: Some(Status::Active),
    };
    let absent = Profile {
        name: "Ada".into(),
        born: None,
        score: None,
        status: None,
    };
    let lengths = |p: &Profile| leaf_lengths(encrypt(p.clone(), &Mock, "ctx").expect("encrypts"));
    assert_eq!(lengths(&present), lengths(&absent));
    for p in [present, absent] {
        let read: Profile = decrypt(
            &Mock,
            encrypt(p.clone(), &Mock, "ctx").expect("encrypts"),
            "ctx",
        )
        .expect("decrypts");
        assert_eq!(read, p);
    }
}

/// A frame a host sends may carry a typed null, which is sealed padded. A
/// frame written here is plaintext for a host, so it carries the plain
/// null every host decoder reads: padding hides nothing unsealed.
#[test]
fn a_frame_reads_a_typed_null_and_writes_the_plain_null() {
    let from_host = [tags::TYPED_NULL, tags::UINT32, 0, 0, 0];
    let parsed = Frame::parse(&from_host).expect("parses");
    assert_eq!(sealed(parsed), from_host);

    assert_eq!(
        to_frame(None::<u32>).expect("frames").risky_ref(),
        &[tags::NULL]
    );
    let node = encrypt(None::<u32>, &Mock, "ctx").expect("encrypts");
    let back = decrypt_to_frame(&Mock, node, "ctx").expect("decrypts");
    assert_eq!(back.risky_ref(), &[tags::NULL]);
}

#[derive(Encrypt, Decrypt, Debug, PartialEq, Clone)]
struct Row {
    #[aead(passthrough)]
    rank: Option<u32>,
    secret: Option<u32>,
}

/// A passthrough field is stored in the clear for other readers, so its
/// absence is the plain null, unchanged; only the sealed field pads.
#[test]
fn a_passthrough_none_stays_the_plain_null() {
    let row = Row {
        rank: None,
        secret: None,
    };
    let CipherText::Map(entries) = encrypt(row.clone(), &Mock, "ctx").expect("encrypts") else {
        panic!("not a map");
    };
    for (key, value) in entries {
        match (key.as_str(), value) {
            ("rank", CipherText::Passthrough(frame)) => assert_eq!(frame.0, [tags::NULL]),
            ("secret", CipherText::Single(leaf)) => {
                assert_eq!(leaf.plaintext, [tags::TYPED_NULL, tags::UINT32, 0, 0, 0])
            }
            (key, other) => panic!("{key}: {other:?}"),
        }
    }
    let read: Row = decrypt(
        &Mock,
        encrypt(row.clone(), &Mock, "ctx").expect("encrypts"),
        "ctx",
    )
    .expect("decrypts");
    assert_eq!(read, row);
}

#[cfg(feature = "uuid")]
#[test]
fn a_uuid_hides_absence() {
    hides_absence(uuid::Uuid::from_bytes([0xAB; 16]));
}

/// A field widened after data was written reads its old `None`s as it
/// reads its old values.
#[test]
fn a_widened_field_reads_its_old_nones() {
    let node = encrypt(None::<u32>, &Mock, "ctx").expect("encrypts");
    let read: Option<u64> = decrypt(&Mock, node, "ctx").expect("decrypts");
    assert_eq!(read, None);
    let node = encrypt(None::<Age>, &Mock, "ctx").expect("encrypts");
    let read: Option<u64> = decrypt(&Mock, node, "ctx").expect("decrypts");
    assert_eq!(read, None);
}

/// A typed null whose padding is not zero is not an absence: a writer with
/// the key cannot pass other plaintext off as one.
#[test]
fn a_typed_null_with_nonzero_padding_is_refused() {
    let forged = Leaf {
        aad: "ctx".into_aad().as_bytes().to_vec(),
        plaintext: vec![tags::TYPED_NULL, tags::UINT32, 0, 0, 1],
    };
    let read: Result<Option<u32>, _> = decrypt(&Mock, CipherText::Single(forged), "ctx");
    assert!(matches!(read, Err(DecryptError::Malformed)), "{read:?}");
}
