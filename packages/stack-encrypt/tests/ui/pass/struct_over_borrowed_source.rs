//! A `struct = ..` derive over a source that borrows: the source's lifetime
//! is the record's (a derived record is `'static`, so the source is borrowed
//! for `'static`, as it was before the derive emitted a plan), and the
//! fields it derives from are owned. A borrowed field is refused: see
//! `../struct_field_must_open.rs`.
use std::marker::PhantomData;

use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::DeclaredContext;
use stack_encrypt::{EncryptFrom, Encrypted, StackCipher, StackCipherText};
use stack_encrypt::registry::fake::FakeKeysetRegistry;

struct User<'a> {
    email: String,
    age: u32,
    #[allow(dead_code)] // carried, never encrypted
    note: &'a str,
}

#[derive(EncryptFrom)]
#[stash(struct = User<'a>, context = "users")]
struct EncryptedUser<'a> {
    email: Encrypted<EqualityTerm>,
    age: StackCipherText,
    #[stash(default)]
    source: PhantomData<&'a ()>,
}

async fn round_trip(cipher: &StackCipher<FakeKeysetRegistry>) {
    let keyset = cipher.default_keyset();
    let user = User { email: "bob@example.com".into(), age: 34, note: "static" };
    let record: EncryptedUser<'_> = keyset.encrypt_as(&user, DeclaredContext::default()).await.unwrap();
    let _ = EncryptedUser::plan::<FakeKeysetRegistry>().unwrap();
    let _ = record;
}

fn main() {
    let _ = round_trip;
}
