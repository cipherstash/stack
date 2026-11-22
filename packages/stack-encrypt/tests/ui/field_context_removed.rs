//! A field-level `context = ".."` is refused on every record form. Every
//! output sits under one context source: all outputs of a `plaintext = T`
//! record share the caller's context, and every field of a `struct = ..`
//! record sits under the record's (`identity` keys it under another
//! segment). To write one value under two contexts, encrypt it twice.
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::StackCipherText;

#[derive(zeroize::Zeroize)]
struct User {
    name: String,
}

#[derive(EncryptTarget)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    #[stash(context = "nickname")]
    name: StackCipherText,
}

#[derive(EncryptTarget)]
#[stash(plaintext = String)]
struct Doubled {
    c: StackCipherText,
    #[stash(context = "shadow")]
    shadow: StackCipherText,
}

#[derive(EncryptTarget)]
struct Generic {
    #[stash(context = "legacy_age")]
    c: StackCipherText,
}

fn main() {}
