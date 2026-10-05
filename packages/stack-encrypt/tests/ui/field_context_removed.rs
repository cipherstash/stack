//! A field-level `context = ".."` is refused on every derive form. A plan has
//! exactly one context source, and every output sits under it: all outputs of
//! a `plaintext = T` record share the caller's context, and every field of a
//! `struct = ..` derive sits under the record's (`identity` keys it under
//! another segment). One value written under two contexts, a dual write, is a
//! fields plan that picks the same source twice, not a derive.
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

#[derive(EncryptFrom)]
#[stash(plaintext = String)]
struct Doubled {
    c: StackCipherText,
    #[stash(context = "shadow")]
    shadow: StackCipherText,
}

#[derive(EncryptFrom)]
struct Generic {
    #[stash(context = "legacy_age")]
    c: StackCipherText,
}

fn main() {}
