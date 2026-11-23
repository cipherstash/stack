//! A ciphertext and several terms over one owned value ask for no `Clone`.
//! Each term reads the value in place, and then the ciphertext takes it. So a
//! value that is moved and wiped can be sealed and indexed in one call.
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OreBlockTerm, OreTerm};
use stack_encrypt::value::Date;
use stack_encrypt::target::{
    ciphertext, equality, indexed, matching, CallerContext, Encrypted, Equality, Match, Ore,
    OreBlock, Owned, Pending,
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

// A date, which is not `Clone`, with a ciphertext, an equality term and an
// order term over the one owned value: #1734's own example.
fn date_with_order_terms<'a>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: Date,
) -> Pending<'a, Encrypted<(EqualityTerm, OreTerm<Date>)>, FakeDataKeySource> {
    keyset.run(
        indexed::<_, _, Owned, _>((Equality, Ore)),
        value,
        CallerContext::from(nonempty!("column")),
    )
}

// The same with block ORE, the scheme EQL v4 stores.
fn date_with_block_order<'a>(
    keyset: &'a KeysetCipher<'_, FakeDataKeySource>,
    value: Date,
) -> Pending<'a, Encrypted<(EqualityTerm, OreBlockTerm<Date>)>, FakeDataKeySource> {
    keyset.run(
        indexed::<_, _, Owned, _>((Equality, OreBlock)),
        value,
        CallerContext::from(nonempty!("column")),
    )
}

fn main() {
    let _ = (seal_and_index::<String>, indexed_owned::<String>);
    let _ = (date_with_order_terms, date_with_block_order);
}
