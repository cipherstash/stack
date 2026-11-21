//! A record of terms alone, and a declaration run over a borrowed
//! plaintext.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{CallerContext, EncryptTarget};
use stack_encrypt::{nonempty, Encrypt, EncryptInto, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

#[derive(EncryptTarget)]
struct Probe {
    hm: EqualityTerm,
}

// No `Decrypt` bound: producing a term requires only that the value
// describes itself, not that it can be read back.
fn query<S: Encrypt + Clone + Zeroize>(cipher: &StackCipher<FakeDataKeySource>, value: S) {
    let keyset = cipher.default_keyset();
    let _ = value.encrypt_into_with_context::<Probe, _>(&keyset, nonempty!("column"));
}

#[derive(EncryptTarget)]
struct Stored {
    c: StackCipherText,
}

// The borrowed form of a declaration reads the plaintext while the request
// is built. The pending request does not hold the borrow, so the plaintext
// can be dropped before the request is awaited.
async fn borrowed(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let pending = {
        let text = String::from("borrowed");
        keyset.run(
            <Stored as EncryptTarget<String>>::encryption(),
            &text,
            CallerContext::from(nonempty!("column")).into(),
        )
    };
    let _ = pending.await.unwrap();
}

fn main() {
    let _ = query::<String>;
    let _ = borrowed;
}
