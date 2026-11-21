//! A `struct = ..` record over a plaintext that borrows. A derived record
//! is `'static`, so the record states that its lifetime is, and the
//! plaintext borrows for `'static`. The borrowed field is passed through in
//! the clear, and the fields the record seals are owned.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{DecryptFrom, EncryptInto, Encrypted, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

#[derive(Zeroize)]
struct User<'a> {
    email: String,
    age: u32,
    // Carried, never encrypted. A borrow has nothing to wipe.
    #[zeroize(skip)]
    note: &'a str,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User<'a>, scope = "users")]
struct EncryptedUser<'a>
where
    'a: 'static,
{
    email: Encrypted<EqualityTerm>,
    age: StackCipherText,
    #[stash(passthrough)]
    note: &'a str,
}

async fn round_trip(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let user = User {
        email: "bob@example.com".into(),
        age: 34,
        note: "static",
    };
    let record: EncryptedUser<'_> = user.encrypt_into(&keyset).await.unwrap();
    let _ = EncryptedUser::EMAIL;
    let _: User<'_> = User::decrypt_from(record, cipher).await.unwrap();
}

fn main() {
    let _ = round_trip;
}
