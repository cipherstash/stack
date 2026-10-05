//! A record that declares `context_type = C` keeps `C` all the way down:
//! nothing in the plan the derive emits asks for a `CallerContext` it
//! cannot take. Each record is encrypted and opened under a `NonEmpty<u64>`.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptField, Decryptable, Decryption, Encryption, IndexSpec};
use stack_encrypt::{DecryptInto, EncryptFrom, NonEmpty, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct Sealed {
    c: StackCipherText,
}

/// A term whose context is a `NonEmpty<u64>`, not a `CallerContext`.
struct Tag(#[allow(dead_code)] EqualityTerm);
impl EncryptFrom<String> for Tag {
    type Context = NonEmpty<u64>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::Context> {
        <EqualityTerm as EncryptFrom<String>>::encryption()
            .accepting::<NonEmpty<u64>>()
            .map(Tag)
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
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct Wrapped {
    sealed: Sealed,
}

/// Several outputs sharing the record's context, one of them decryptable.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct Pair {
    sealed: Sealed,
    tag: Tag,
}

async fn round_trips(cipher: &StackCipher<FakeDataKeySource>) {
    let keyset = cipher.default_keyset();
    let value = String::from("bob@example.com");
    let wrapped: Wrapped = keyset.encrypt_as(&value, NonEmpty::from(7u64)).await.unwrap();
    let _: String = cipher.decrypt_as(wrapped, NonEmpty::from(7u64)).await.unwrap();
    let pair: Pair = keyset.encrypt_as(&value, NonEmpty::from(7u64)).await.unwrap();
    let _: String = cipher.decrypt_as(pair, NonEmpty::from(7u64)).await.unwrap();
    let _ = Pair::plan::<String>().unwrap();
}

fn main() {
    let _ = round_trips;
}
