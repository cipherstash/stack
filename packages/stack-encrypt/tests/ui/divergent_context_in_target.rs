//! Within one target there is no second context to pass: `zip` hands both
//! sides the one context the tree carries, and requires both to need the
//! same type of it. A subtree given a context of its own with `under` may
//! run under `()`, so it needs a `DeclaredContext`; a bare operation needs a
//! real `CallerContext`; the two do not zip. So a target cannot make the
//! caller's context optional for its ciphertext while its term still needs
//! one — the empty-context rule, reaching through `zip`.
//!
//! That is the divergence the type system refuses. The one it cannot refuse
//! is two `under`s in one target, each naming its own context: that compiles,
//! being the same construct as a record naming the contexts of two fields
//! (ADR-0004, decision 1).
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{ciphertext, equality, DeclaredContext, EncryptFrom, Encryption};
use stack_encrypt::{nonempty, StackCipherText};

struct Divergent {
    c: StackCipherText,
    hm: EqualityTerm,
}

impl EncryptFrom<String> for Divergent {
    type Context = DeclaredContext;
    fn encryption<'s, K: stack_encrypt::KeysetRegistry + 'static>() -> Encryption<'s, String, Self, K, Self::Context>
    where
        String: 's,
    {
        ciphertext()
            .under(nonempty!("users/email"))
            .zip(equality())
            .map(|(c, hm)| Self { c, hm })
    }
}

fn main() {}
