//! An owned `struct = ..` record must name every field of its plaintext. The
//! owned conversion wipes the fields it seals, and moves the fields it passes
//! through. A field it does neither would be dropped without being wiped. So
//! that field is a compile error at the `struct = ..` path, and the error
//! names the field.
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
