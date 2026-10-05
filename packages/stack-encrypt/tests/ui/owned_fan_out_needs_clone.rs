//! Owned mode hands the plaintext to an operation by value, so a single
//! operation needs no `Clone`. Two operations over one owned value are the
//! one place a copy is unavoidable — the first side gets a clone, the last
//! the value — and the refusal names `zip`, not the operations.
use stack_encrypt::target::{ciphertext, equality, CallerContext, Owned};
use stack_encrypt::{nonempty, Encrypt, KeysetCipher};
use stack_kms::FakeDataKeySource;

fn seal_and_index<S: Encrypt + vitaminc_prf::PrfValue>(
    keyset: &KeysetCipher<'_, FakeDataKeySource>,
    value: S,
) {
    let both = ciphertext::<_, _, Owned>()
        .accepting::<CallerContext>()
        .zip(equality::<_, _, Owned>());
    let _ = keyset.run(both, value, CallerContext::from(nonempty!("column")));
}

fn main() {}
