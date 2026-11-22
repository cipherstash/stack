//! A ciphertext and several terms over one owned value ask for no `Clone`.
//! Each term reads the value in place, and then the ciphertext takes it. So a
//! value that is moved and wiped can be sealed and indexed in one call.
use stack_encrypt::sem::{EqualityTerm, MatchTerms};
use stack_encrypt::target::{
    ciphertext, equality, indexed, matching, CallerContext, Encrypted, Equality, Match, Owned,
    Pending,
};
use stack_encrypt::{nonempty, Encrypt, EncryptRef, KeysetCipher, StackCipherText};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

// Bounded only by what the operations read, and `Zeroize` for the one that is
// handed the value. `Clone` returning to `zip`, or to either operation, fails
// this file.
fn seal_and_index<'a, S: Encrypt + EncryptRef + AsRef<str> + Zeroize>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) -> Pending<'a, ((StackCipherText, EqualityTerm), MatchTerms), FakeDataKeySource> {
    let all = ciphertext::<_, _, Owned>()
        .accepting::<CallerContext>()
        .zip(equality())
        .zip(matching());
    keyset.run(all, value, CallerContext::from(nonempty!("column")))
}

// The same through `indexed`, as a target with terms composes it.
fn indexed_owned<'a, S: Encrypt + EncryptRef + AsRef<str> + Zeroize>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) -> Pending<'a, Encrypted<(EqualityTerm, MatchTerms)>, FakeDataKeySource> {
    keyset.run(
        indexed::<_, _, Owned, _>((Equality, Match::new())),
        value,
        CallerContext::from(nonempty!("column")),
    )
}

fn main() {
    let _ = (seal_and_index::<String>, indexed_owned::<String>);
}
