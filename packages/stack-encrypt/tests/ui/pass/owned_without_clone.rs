//! An operation in owned mode asks nothing of the plaintext beyond the
//! operation's own capability and `Zeroize`: no `Clone`, so a value that is
//! moved and wiped can be sealed or indexed. A ciphertext and an equality
//! term read the value by reference as well as by value, which is
//! `EncryptRef`. The operation wipes the value it is handed, which is
//! `Zeroize`.
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OpeTerm, OreTerm};
use stack_encrypt::target::{
    ciphertext, equality, matching, ope, ore, CallerContext, Owned, Pending,
};
use stack_encrypt::{nonempty, Encrypt, EncryptRef, KeysetCipher, Orderable, StackCipherText};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

fn seal<'a, S: Encrypt + EncryptRef + Zeroize>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) -> Pending<'a, StackCipherText, FakeDataKeySource> {
    keyset.run(ciphertext::<_, _, Owned>(), value, nonempty!("column").into())
}
fn index<'a, S: Encrypt + EncryptRef + Zeroize>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) -> Pending<'a, EqualityTerm, FakeDataKeySource> {
    keyset.run(equality::<_, _, Owned>(), value, CallerContext::from(nonempty!("column")))
}
fn search<'a, S: AsRef<str> + Zeroize>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) -> Pending<'a, MatchTerms, FakeDataKeySource> {
    keyset.run(matching::<_, _, Owned, _>(), value, CallerContext::from(nonempty!("column")))
}
// Bounded by vitaminc-ore's `Orderable`, read in place (`EncryptRef`), and
// wiped (`Zeroize`). `Orderable` does not imply `Clone`, so `Clone`
// returning to either constructor's bounds fails this file.
fn order<'a, S>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) -> Pending<'a, OreTerm<S>, FakeDataKeySource>
where
    S: Orderable + EncryptRef + Zeroize + 'static,
{
    keyset.run(ore::<_, _, Owned>(), value, CallerContext::from(nonempty!("column")))
}
fn order_preserving<'a, S>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) -> Pending<'a, OpeTerm<S>, FakeDataKeySource>
where
    S: Orderable + EncryptRef + Zeroize + 'static,
{
    keyset.run(ope::<_, _, Owned>(), value, CallerContext::from(nonempty!("column")))
}
fn main() {
    let _ = (seal::<String>, index::<String>, search::<String>);
    let _ = (order::<u64>, order_preserving::<u64>);
}
