//! A record that declares `context_type = C` keeps `C` all the way down:
//! nothing in the declaration the derive emits asks for a `CallerContext`
//! it cannot take. Each record is encrypted and opened under a
//! `NonEmpty<u64>`.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{
    equality, DecryptField, DecryptSource, Decryptable, Decryption, EncryptTarget, Encryption,
    IndexSpec, RequiredContext,
};
use stack_encrypt::{DecryptFrom, EncryptInto, NonEmpty, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct Sealed {
    c: StackCipherText,
}

/// A term whose context is a `NonEmpty<u64>`, not a `CallerContext`.
struct Tag(#[allow(dead_code)] EqualityTerm);
impl EncryptTarget<String> for Tag {
    type ContextInput = RequiredContext<NonEmpty<u64>>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::ContextInput> {
        equality().accepting().map(Tag)
    }
    fn indexes() -> Vec<IndexSpec> {
        vec![IndexSpec::Equality]
    }
}
impl Decryptable for Tag {
    const DECRYPTABLE: bool = false;
}
impl<P, Ctx> DecryptField<P, Ctx> for Tag {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}

/// One output, a target whose context is the record's.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct Wrapped {
    sealed: Sealed,
}

/// Several outputs sharing the record's context, one of them decryptable.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct Pair {
    sealed: Sealed,
    tag: Tag,
}

async fn round_trips(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let value = String::from("bob@example.com");
    let wrapped: Wrapped = value
        .clone()
        .encrypt_into_with_context(&keyset, NonEmpty::from(7u64))
        .await
        .unwrap();
    let _: String = String::decrypt_from_with_context(wrapped, cipher, NonEmpty::from(7u64))
        .await
        .unwrap();
    let pair: Pair = value
        .encrypt_into_with_context(&keyset, NonEmpty::from(7u64))
        .await
        .unwrap();
    let _: String = String::decrypt_from_with_context(pair, cipher, NonEmpty::from(7u64))
        .await
        .unwrap();
}

fn main() {
    let _ = round_trips;
}
