//! An owned `struct = ..` record accounts for every field of its plaintext:
//! the owned conversion wipes what it seals and moves what it carries, so a
//! field it does neither would be dropped unwiped. It is refused at the
//! `struct = ..` path, naming the field.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::Ciphertext;

#[derive(zeroize::Zeroize)]
struct User {
    email: String,
    password: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    email: Ciphertext,
}

fn main() {}
