//! A `Ciphertext` holds one scalar, so it decrypts only into a target that
//! one scalar builds. A sequence, a map, a derived struct, a derived
//! newtype of a sequence and a protected sequence each need a container,
//! and do not compile.
//! `tests/ui/pass/scalar_decrypt_targets.rs` pins the targets that do.
use std::collections::{BTreeMap, HashMap};

use stack_encrypt::{Ciphertext, Decrypt, DecryptFrom, KeysetCipher, Protected};

#[derive(Decrypt, zeroize::Zeroize)]
struct Account {
    id: u64,
}

#[derive(Decrypt, zeroize::Zeroize)]
struct Tags(Vec<String>);

fn unsupported<K: 'static>(keyset: &KeysetCipher<'_, K>, ciphertext: Ciphertext) {
    let _ = keyset.decrypt::<Vec<String>>(ciphertext.clone());
    let _ = keyset.decrypt::<BTreeMap<String, i64>>(ciphertext.clone());
    let _ = keyset.decrypt::<Account>(ciphertext.clone());
    let _ = keyset.decrypt::<Tags>(ciphertext.clone());
    let _ = keyset.decrypt::<Protected<Vec<i64>>>(ciphertext.clone());
    let _ = keyset.decrypt_with_context::<HashMap<String, String>>(ciphertext.clone(), "users/tags");
    let _ = Vec::<i64>::decrypt_from(ciphertext, keyset);
}
fn main() {}
