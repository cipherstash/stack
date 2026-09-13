//! Canonical execution shared by the cipher-directed and declaration APIs.
use super::{CipherScope, Pending, Request, Responses};
use crate::cipher::{bind_keys, PendingStackCipherText, StackDecipher};
use crate::{Descriptor, Error, KeysetCipher, StackCipher, StackCipherText};
use vitaminc_aead::{CipherText, Decrypt, Encrypt, IntoAad};
use vitaminc_protected::NonEmpty;

/// Internal term operation. It is deliberately inaccessible to target authors.
pub(crate) trait Term<S, K, Ctx>: Sized {
    fn encrypt_from<'a>(
        source: &S,
        cipher: &'a KeysetCipher<'_, K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a;
}

pub(crate) fn encrypt_native<'a, 'c, S: Encrypt + Clone, K, T: IntoAad<'c>>(
    source: &S,
    cipher: &'a KeysetCipher<'_, K>,
    context: NonEmpty<T>,
) -> Pending<'a, StackCipherText, K> {
    let context = context.into_aad_piece();
    let descriptor = Descriptor::from_piece(&context);
    if let Err(error) = descriptor.check() {
        return Pending::failed(cipher, error);
    }
    let aad = context.into_aad().into_owned();
    match source.clone().encrypt_with_aad(cipher, aad) {
        Ok(tree) => seal_pending(cipher, tree, descriptor),
        Err(_) => Pending::ready(cipher, Err(Error::Aead)),
    }
}
pub(crate) fn open_native<'a, 'c, P: Decrypt<'static> + 'static, K, T: IntoAad<'c>>(
    tree: StackCipherText,
    cipher: &'a StackCipher<K>,
    context: NonEmpty<T>,
) -> Pending<'a, P, K> {
    let context = context.into_aad_piece();
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
pub(crate) fn seal_pending<'a, K>(
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
    let requests = std::iter::repeat_with(|| Request::generate_data_key(descriptor.clone()))
        .take(tree.key_count())
        .collect();
    Pending::request(cipher, requests, move |responses| {
        let mut keys = responses.drain_generated();
        tree.seal_with(keyset_id, &mut keys).map_err(Error::from)
    })
}

pub(crate) fn decipher_pending<'a, K>(
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
            out.push(Request::retrieve_data_key(
                *leaf.iv(),
                leaf.tag().to_vec(),
                descriptor.clone(),
                leaf.keyset_id(),
            ));
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
