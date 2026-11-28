//! Types of an application that depends on `stack-encrypt` and nothing
//! else.
//!
//! Each type derives `Encrypt` and `Decrypt` from `stack_encrypt`, except
//! [`Price`], whose impls are written by hand with the items in
//! `stack_encrypt::plaintext`. The crate's tests encrypt and decrypt each of
//! them. If a derive or a hand-written impl needed any other crate, this
//! crate would not compile.
//!
//! `keyset.encrypt` asks for `Zeroize`, so that it can wipe the value. An
//! application usually derives `Zeroize` with the zeroize crate. These types
//! implement it by hand, through `stack_encrypt`'s re-export of the trait,
//! so that the crate's only dependency stays `stack-encrypt`.

use stack_encrypt::plaintext::{depth, FixedType, Logical, Physical, Sink};
use stack_encrypt::target::Zeroize;
use stack_encrypt::{Decrypt, Encrypt, EncryptRef, FromScalar, Scalar};

/// A newtype over a `String`. It encrypts as its `String`, so it is a
/// `Scalar`, and `keyset.encrypt` takes it.
#[derive(Debug, PartialEq, Encrypt, Decrypt)]
pub struct Email(pub String);

impl Zeroize for Email {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// A struct with named fields: it encrypts as a map, one entry per field.
#[derive(Debug, PartialEq, Encrypt, Decrypt)]
pub struct Profile {
    pub name: String,
    pub age: u32,
    pub role: Role,
    /// Stored in the clear, beside the encrypted fields.
    #[aead(passthrough)]
    pub tenant: String,
}

/// A fieldless enum: it encrypts as one integer, its discriminant.
#[derive(Debug, PartialEq, Encrypt, Decrypt)]
pub enum Role {
    Admin = 1,
    Member = 2,
}

impl Zeroize for Role {
    fn zeroize(&mut self) {
        *self = Role::Member;
    }
}

/// A generic newtype: a `Scalar` when its inner type is one.
#[derive(Debug, PartialEq, Encrypt, Decrypt)]
pub struct Wrapper<T>(pub T);

impl<T: Zeroize> Zeroize for Wrapper<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// A generic struct: a map whose `value` entry has the type `T`.
#[derive(Debug, PartialEq, Encrypt, Decrypt)]
pub struct Labelled<T> {
    pub label: String,
    pub value: T,
}

/// An amount in cents, with hand-written impls. The derive would store it
/// as a map with one entry, `cents`. These impls store it as its one
/// integer, so `keyset.encrypt` takes it and an `i64` decrypts it.
#[derive(Debug, PartialEq)]
pub struct Price {
    pub cents: i64,
}

impl Zeroize for Price {
    fn zeroize(&mut self) {
        self.cents.zeroize();
    }
}

impl Encrypt for Price {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> = <i64 as Encrypt>::FIXED;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.cents.visit(sink)
    }
}

// `keyset.encrypt` reads the value through a borrow, so the borrow encrypts
// too, and is marked `Scalar`.
impl Encrypt for &Price {
    const DEPTH: Option<usize> = depth::SCALAR;
    const FIXED: Option<FixedType> = <&i64 as Encrypt>::FIXED;
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.cents.visit_ref(sink)
    }
}

impl Scalar for Price {}
impl Scalar for &Price {}

// `FromScalar` gives `Price` its `Decrypt`.
impl FromScalar for Price {
    const EXPECTED: &'static str = "a price in cents";
    const FIXED: Option<FixedType> = <i64 as FromScalar>::FIXED;
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        i64::from_scalar(ty, value).map(|cents| Price { cents })
    }
}
