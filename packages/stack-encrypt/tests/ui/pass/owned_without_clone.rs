//! A single operation in owned mode asks nothing of the plaintext beyond the
//! operation's own capability: no `Clone`, so a value that is moved and
//! wiped can be sealed or indexed.
use stack_encrypt::sem::{CllwOpeEncrypt, CllwOreEncrypt, EqualityTerm, MatchTerms, OpeTerm, OreTerm};
use stack_encrypt::target::{
    ciphertext, equality, matching, ope, ore, CallerContext, Owned, Pending,
};
use stack_encrypt::{nonempty, Encrypt, KeysetCipher, StackCipherText};
use stack_encrypt::registry::fake::FakeKeysetRegistry;

fn seal<'a, S: Encrypt>(
    keyset: &'a KeysetCipher<'_, FakeKeysetRegistry>,
    value: S,
) -> Pending<'a, StackCipherText, FakeKeysetRegistry> {
    keyset.run(ciphertext::<_, _, Owned>(), value, nonempty!("column").into())
}
fn index<'a, S: vitaminc_prf::PrfValue>(
    keyset: &'a KeysetCipher<'_, FakeKeysetRegistry>,
    value: S,
) -> Pending<'a, EqualityTerm, FakeKeysetRegistry> {
    keyset.run(equality::<_, _, Owned>(), value, CallerContext::from(nonempty!("column")))
}
fn search<'a, S: AsRef<str>>(
    keyset: &'a KeysetCipher<'_, FakeKeysetRegistry>,
    value: S,
) -> Pending<'a, MatchTerms, FakeKeysetRegistry> {
    keyset.run(matching::<_, _, Owned, _>(), value, CallerContext::from(nonempty!("column")))
}
// Bounded only by the scheme's own trait: `CllwOreEncrypt` and
// `CllwOpeEncrypt` do not imply `Clone`, so `Clone` returning to either
// constructor's bounds fails this file.
fn order<'a, S>(
    keyset: &'a KeysetCipher<'_, FakeKeysetRegistry>,
    value: S,
) -> Pending<'a, OreTerm<S>, FakeKeysetRegistry>
where
    S: CllwOreEncrypt + Send + 'static,
    S::Output: Send + 'static,
{
    keyset.run(ore::<_, _, Owned>(), value, CallerContext::from(nonempty!("column")))
}
fn order_preserving<'a, S>(
    keyset: &'a KeysetCipher<'_, FakeKeysetRegistry>,
    value: S,
) -> Pending<'a, OpeTerm<S>, FakeKeysetRegistry>
where
    S: CllwOpeEncrypt + Send + 'static,
    S::Output: Send + 'static,
{
    keyset.run(ope::<_, _, Owned>(), value, CallerContext::from(nonempty!("column")))
}
fn main() {
    let _ = (seal::<String>, index::<String>, search::<String>);
    let _ = (order::<u64>, order_preserving::<u64>);
}
