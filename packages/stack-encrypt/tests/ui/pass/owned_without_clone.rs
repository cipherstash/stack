//! A single operation in owned mode asks nothing of the plaintext beyond the
//! operation's own capability: no `Clone`, so a value that is moved and
//! wiped can be sealed or indexed.
use stack_encrypt::sem::{EqualityTerm, MatchTerm};
use stack_encrypt::target::{ciphertext, equality, matching, CallerContext, Owned, Pending};
use stack_encrypt::{nonempty, Encrypt, KeysetCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

fn seal<'a, S: Encrypt>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) -> Pending<'a, StackCipherText, FakeDataKeySource> {
    keyset.run(ciphertext::<_, _, Owned>(), value, nonempty!("column").into())
}
fn index<'a, S: vitaminc_prf::PrfValue>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) -> Pending<'a, EqualityTerm, FakeDataKeySource> {
    keyset.run(equality::<_, _, Owned>(), value, CallerContext::from(nonempty!("column")))
}
fn search<'a, S: AsRef<str>>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) -> Pending<'a, MatchTerm, FakeDataKeySource> {
    keyset.run(matching::<_, _, Owned, _>(), value, CallerContext::from(nonempty!("column")))
}
fn main() {
    let _ = (seal::<String>, index::<String>, search::<String>);
}
