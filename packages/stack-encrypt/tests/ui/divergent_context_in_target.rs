//! Within one target there is no second context to pass: `zip` hands both
//! sides the one context the tree carries, and requires both to need the
//! same type of it. A subtree given a context of its own (`under`) needs a
//! `DeclaredContext`; a bare operation needs a `CallerContext`; the two do
//! not zip. So the ciphertext and the term of one target cannot be put under
//! different contexts — the divergence ADR-0004 exists to rule out is a type
//! error, not a convention.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{ciphertext, equality, DeclaredContext, EncryptFrom, Encryption};
use stack_encrypt::{nonempty, StackCipherText};

struct Divergent {
    c: StackCipherText,
    hm: EqualityTerm,
}

impl EncryptFrom<String> for Divergent {
    type Context = DeclaredContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::Context>
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
