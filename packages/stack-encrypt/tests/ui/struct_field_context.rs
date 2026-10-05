//! A field of a `struct` derive sits under the record's context, as a plan's
//! field sits under the plan's. A `context = ".."` of its own, which sealed
//! it outside the record's context, is refused, naming `identity`: the
//! attribute that keys the field under another segment of the same context.
use stack_encrypt::{EncryptFrom, StackCipherText};

struct User {
    name: String,
}

#[derive(EncryptFrom)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    #[stash(context = "nickname")]
    name: StackCipherText,
}

fn main() {}
