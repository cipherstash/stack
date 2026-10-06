//! Canonical execution shared by the cipher-directed and declaration APIs.
use super::{CipherScope, Pending, Request, Responses};
use crate::cipher::{bind_keys, PendingStackCipherText, StackDecipher};
use crate::registry::KeysetRegistry;
use crate::{Descriptor, Error, KeysetCipher, StackCipher, StackCipherText};
use vitaminc_aead::{CipherText, Decrypt, Encrypt, IntoAad, IntoContext};
use vitaminc_protected::NonEmpty;

/// Internal term operation. It is deliberately inaccessible to target authors.
///
/// `S` is what the operation is handed, by value: the PRF and ORE schemes
/// consume their input, so a term that needs the plaintext takes it, and one
/// that only reads it (a match term) is handed a reference as its `S`.
pub(crate) trait Term<S, K: KeysetRegistry, Ctx>: Sized {
    fn encrypt_from<'a>(
        source: S,
        cipher: &'a KeysetCipher<'_, K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a;
}

/// Seal `source` into the native tree. It is consumed, as Vitamin C's
/// `Encrypt` consumes it: a caller holding only a borrow clones before it
/// gets here (see [`ConsumeSource`](super::ConsumeSource)), and one holding
/// the value hands it over without a copy.
pub(crate) fn encrypt_native<'a, 'c, S: Encrypt, K: KeysetRegistry, T: IntoContext<'c>>(
    source: S,
    cipher: &'a KeysetCipher<'_, K>,
    context: NonEmpty<T>,
) -> Pending<'a, StackCipherText, K> {
    let context = context.into_context();
    let descriptor = Descriptor::from_piece(&context);
    if let Err(error) = descriptor.check() {
        return Pending::failed(cipher, error);
    }
    let aad = context.into_aad().into_owned();
    match source.encrypt_with_aad(cipher, aad) {
        Ok(tree) => seal_pending(cipher, tree, descriptor),
        Err(_) => Pending::ready(cipher, Err(Error::Aead)),
    }
}
pub(crate) fn open_native<
    'a,
    'c,
    P: Decrypt<'static> + 'static,
    K: KeysetRegistry,
    T: IntoContext<'c>,
>(
    tree: StackCipherText,
    cipher: &'a StackCipher<K>,
    context: NonEmpty<T>,
) -> Pending<'a, P, K> {
    let context = context.into_context();
    let descriptor = Descriptor::from_piece(&context);
    // Fast path, as in `seal_pending`; `dispatch` is the gate.
    if let Err(e) = descriptor.check() {
        return Pending::ready(cipher, Err(e));
    }
    let requests = retrieve_requests(&tree, &descriptor);
    let aad = context.into_aad().into_owned();
    Pending::request(cipher, requests, move |responses| {
        let decipher = decipher_from_responses(tree, responses)?;
        P::decrypt_with_aad(decipher, aad).map_err(Error::from)
    })
}
pub(crate) fn seal_pending<'a, K: KeysetRegistry>(
    cipher: &'a KeysetCipher<'_, K>,
    tree: PendingStackCipherText,
    descriptor: Descriptor,
) -> Pending<'a, StackCipherText, K> {
    // Fast path: refuse an over-long descriptor before a single request
    // exists, not after one per leaf has been built. `dispatch` is the gate
    // proper, and checks every request's descriptor.
    if let Err(e) = descriptor.check() {
        return Pending::ready(cipher, Err(e));
    }
    let keyset_id = cipher.keyset_id();
    let requests = std::iter::repeat_with(|| Request::generate_under(descriptor.clone()))
        .take(tree.key_count())
        .collect();
    Pending::request(cipher, requests, move |responses| {
        let mut keys = responses.drain_generated();
        tree.seal_with(keyset_id, &mut keys).map_err(Error::from)
    })
}

pub(crate) fn decipher_pending<'a, K: KeysetRegistry>(
    scope: impl CipherScope<'a, K>,
    ciphertext: StackCipherText,
    descriptor: Descriptor,
) -> Pending<'a, StackDecipher, K> {
    // Fast path, as in `seal_pending`; `dispatch` is the gate.
    if let Err(e) = descriptor.check() {
        return Pending::ready(scope, Err(e));
    }
    let requests = retrieve_requests(&ciphertext, &descriptor);
    Pending::request(scope, requests, move |responses| {
        decipher_from_responses(ciphertext, responses)
    })
}

fn decipher_from_responses(
    ciphertext: StackCipherText,
    responses: &mut Responses,
) -> Result<StackDecipher, Error> {
    let mut keys = responses.drain_retrieved();
    // Too few keys for the tree, or keys left over once it is bound, both
    // mean `retrieve_requests` and `bind_keys` disagreed about the tree's
    // shape: a composition bug in this module, not a data error — so
    // `ResponseShape`, never `Aead`, which would read as tampering.
    let keyed = bind_keys(ciphertext, &mut keys).map_err(|_| Error::ResponseShape)?;
    if keys.next().is_some() {
        return Err(Error::ResponseShape);
    }
    Ok(StackDecipher::over(keyed))
}

fn retrieve_requests(ciphertext: &StackCipherText, descriptor: &Descriptor) -> Vec<Request> {
    let mut out = Vec::new();
    collect_retrieve_requests(ciphertext, descriptor, &mut out);
    out
}

fn collect_retrieve_requests(
    ciphertext: &StackCipherText,
    descriptor: &Descriptor,
    out: &mut Vec<Request>,
) {
    match ciphertext {
        CipherText::Single(leaf)
        | CipherText::None(leaf)
        | CipherText::EmptySequence(leaf)
        | CipherText::EmptyMap(leaf) => {
            out.push(Request::retrieve_leaf(leaf, descriptor.clone()));
        }
        CipherText::Sequence(items) => {
            for item in items {
                collect_retrieve_requests(item, descriptor, out);
            }
        }
        CipherText::Map(entries) => {
            for (_, value) in entries {
                collect_retrieve_requests(value, descriptor, out);
            }
        }
        CipherText::Passthrough(_) => {}
    }
}
