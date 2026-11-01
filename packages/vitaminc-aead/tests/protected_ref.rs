//! A protected borrow (`AsProtectedRef`) is a plaintext source, end to end:
//! it seals as the `&Protected<T>` it came from, a fixed-width `None`
//! behind it still pads to the length of a `Some`, and what it seals reads
//! back. Sealing goes through a cipher that keeps the plaintext in the
//! clear, so a leaf's length is its plaintext's.

use vitaminc_aead::{decrypt, encrypt, tags, CipherText, Context, Decrypt, Encrypt};
use vitaminc_protected::{AsProtectedRef, Controlled, Protected, ProtectedRef};

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

/// Seal `value`, then read it back as a `T`.
fn round_trip<P: Encrypt, T: Decrypt>(value: P) -> T {
    decrypt(
        &Mock,
        encrypt(value, &Mock, "ctx").expect("encrypts"),
        "ctx",
    )
    .expect("decrypts")
}

fn accepts_source<S: Encrypt>(_: S) {}

/// The example from the issue that asked for this.
#[test]
fn a_protected_ref_is_a_source() {
    let value = Protected::new(42i32);
    accepts_source(&value);
    accepts_source(value.as_protected_ref());
}

#[test]
fn a_protected_ref_seals_as_the_borrowed_protected_value() {
    let int = Protected::new(42i32);
    assert_eq!(sealed(int.as_protected_ref()), sealed(&int));
    let text = Protected::new(String::from("pw"));
    assert_eq!(sealed(text.as_protected_ref()), sealed(&text));
    let bytes = Protected::new([7u8; 4]);
    assert_eq!(sealed(bytes.as_protected_ref()), sealed(&bytes));

    let read: i32 = round_trip(int.as_protected_ref());
    assert_eq!(read, 42);
    let read: String = round_trip(text.as_protected_ref());
    assert_eq!(read, "pw");
    let read: [u8; 4] = round_trip(bytes.as_protected_ref());
    assert_eq!(read, [7; 4]);

    // The walk borrowed: the owners are untouched and still hold their values.
    assert_eq!(int.risky_ref(), &42);
    assert_eq!(text.risky_ref(), "pw");
}

/// Absent and present seal to the same length, either way round the
/// borrow: a `ProtectedRef` to an `Option`, or an `Option` of a
/// `ProtectedRef`. Each reads back as what it was.
#[test]
fn a_fixed_width_value_behind_a_protected_ref_hides_absence() {
    let some = Protected::new(Some(1815u32));
    let none = Protected::new(None::<u32>);
    let sealed_some = sealed(some.as_protected_ref());
    let sealed_none = sealed(none.as_protected_ref());
    assert_eq!(
        sealed_none.first(),
        Some(&tags::TYPED_NULL),
        "{sealed_none:?}"
    );
    assert_eq!(sealed_none.len(), sealed_some.len());
    assert_eq!(sealed_some, sealed(&some));
    assert_eq!(sealed_none, sealed(&none));
    let read: Option<u32> = round_trip(some.as_protected_ref());
    assert_eq!(read, Some(1815));
    let read: Option<u32> = round_trip(none.as_protected_ref());
    assert_eq!(read, None);

    let value = Protected::new(-7i64);
    let sealed_some = sealed(Some(value.as_protected_ref()));
    let sealed_none = sealed(None::<ProtectedRef<'_, i64>>);
    assert_eq!(
        sealed_none.first(),
        Some(&tags::TYPED_NULL),
        "{sealed_none:?}"
    );
    assert_eq!(sealed_none.len(), sealed_some.len());
    let read: Option<i64> = round_trip(Some(value.as_protected_ref()));
    assert_eq!(read, Some(-7));
    let read: Option<i64> = round_trip(None::<ProtectedRef<'_, i64>>);
    assert_eq!(read, None);
}

#[derive(Encrypt)]
struct Profile<'a> {
    name: ProtectedRef<'a, String>,
    born: Option<ProtectedRef<'a, i32>>,
}

#[derive(Decrypt, Debug, PartialEq)]
struct ProfileRead {
    name: String,
    born: Option<i32>,
}

/// A derived struct of protected borrows seals its optional field at the
/// same length either way, and reads back.
#[test]
fn a_derived_struct_of_protected_refs_round_trips() {
    let name = Protected::new(String::from("Ada"));
    let born = Protected::new(1815i32);
    let lengths = |p: Profile<'_>| -> Vec<(String, usize)> {
        let CipherText::Map(entries) = encrypt(p, &Mock, "ctx").expect("encrypts") else {
            panic!("not a map");
        };
        entries
            .into_iter()
            .map(|(key, value)| match value {
                CipherText::Single(leaf) => (key, leaf.plaintext.len()),
                other => panic!("{key}: not one leaf: {other:?}"),
            })
            .collect()
    };
    let present = || Profile {
        name: name.as_protected_ref(),
        born: Some(born.as_protected_ref()),
    };
    let absent = || Profile {
        name: name.as_protected_ref(),
        born: None,
    };
    assert_eq!(lengths(present()), lengths(absent()));

    let read: ProfileRead = round_trip(present());
    assert_eq!(
        read,
        ProfileRead {
            name: "Ada".into(),
            born: Some(1815)
        }
    );
    let read: ProfileRead = round_trip(absent());
    assert_eq!(
        read,
        ProfileRead {
            name: "Ada".into(),
            born: None
        }
    );
}
