//! A searchable encrypted record, end to end.
//!
//! The point of target-directed encryption: define a record type that *is*
//! "the ciphertext plus the index terms this field needs", implement
//! `EncryptedFrom` once (the shape a future `#[derive(Encrypted)]` will
//! emit), and every insert is one `encrypt_into(..).await`. A tiny in-memory
//! "table" then answers equality and range queries purely by comparing terms
//! — decrypting only the rows that match.
//!
//! The async shape is the other half of the point: `encrypt_from` does no
//! I/O. It derives the terms locally and combines the field pendings with
//! `zip`/`map` — so a whole *column* of records, encrypted through the
//! `Vec` implementation, settles in **one** batched ZeroKMS call, and the
//! matching rows decrypt in one more.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p stack-encrypt --example encrypted_record
//! ```
//!
//! Uses `FakeDataKeySource`, so no ZeroKMS credentials or network are needed.

use stack_encrypt::sem::{EqualityTerm, OreTerm};
use stack_encrypt::target::{
    DecryptContext, DecryptExt, DecryptedFrom, EncryptContext, EncryptExt, EncryptedFrom, Pending,
};
use stack_encrypt::{StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

/// "An encrypted `u32`, stored as its ciphertext plus an equality term and an
/// ORE term." The same shape as an EQL `integer_ord_ore` payload, minus the
/// EQL wire encoding.
struct EncryptedInt {
    ciphertext: StackCipherText,
    eq: EqualityTerm,
    ord: OreTerm<u32>,
}

// One impl, written the way the derive will write it: build every field's
// pending (no I/O — the terms derive locally, the ciphertext queues its
// data-key requests), merge them with `zip`, shape with `map`. Errors are the
// cipher's; there is nothing to unify.
impl<K> EncryptedFrom<u32, StackCipher<K>> for EncryptedInt {
    fn encrypt_from<'a, 'c, Ctx>(
        source: &'a u32,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Ctx: EncryptContext<'c>,
        Self: 'a,
    {
        // One context fans out to every field: it authenticates the
        // ciphertext (AAD) and domain-separates both terms (PRF context).
        StackCipherText::encrypt_from(source, cipher, context.clone())
            .zip(EqualityTerm::encrypt_from(source, cipher, context.clone()))
            .zip(OreTerm::<u32>::encrypt_from(source, cipher, context))
            .map(|((ciphertext, eq), ord)| Self {
                ciphertext,
                eq,
                ord,
            })
    }
}

// The decrypt mirror the derive will also write: only the ciphertext field
// participates (terms are one-way), so it delegates to the ciphertext's own
// implementation.
impl<K> DecryptedFrom<EncryptedInt, StackCipher<K>> for u32 {
    fn decrypt_from<'a, 'c, Ctx>(
        source: EncryptedInt,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Ctx: DecryptContext<'c>,
        EncryptedInt: 'a,
        Self: 'a,
    {
        source.ciphertext.decrypt_into(cipher, context)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One cipher does everything the record needs: ZeroKMS-backed AEAD (every
    // leaf sealed under its own data key) and SEM term derivation under the
    // keyset's index key, which `init` loads. Data keys and terms are bound to
    // the same keyset by construction — there is no way to mix them up.
    let cipher = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;

    // --- Write side: encrypt a column of ages -------------------------------

    const CONTEXT: &str = "users/age";
    let ages: Vec<u32> = vec![29, 34, 41, 34, 57];

    // One await for the whole column: the Vec implementation merges every
    // record's pending, so five records (ciphertext + two terms each) settle
    // in a single batched generate_keys call.
    let table: Vec<EncryptedInt> = ages.encrypt_into(&cipher, CONTEXT).await?;
    println!(
        "stored {} encrypted records in one ZeroKMS call",
        table.len()
    );

    // --- Query side: terms only, no plaintext, no decryption ----------------

    // Term probes derive under the index key the cipher already holds:
    // building a query never calls ZeroKMS at all.

    // WHERE age = 34: compare equality terms.
    let probe: EqualityTerm = 34u32.encrypt_into(&cipher, CONTEXT).await?;
    let equal: Vec<usize> = (0..table.len()).filter(|&i| table[i].eq == probe).collect();
    println!("WHERE age = 34  => rows {equal:?}");

    // WHERE age > 40: compare ORE terms.
    let bound: OreTerm<u32> = 40u32.encrypt_into(&cipher, CONTEXT).await?;
    let over_40: Vec<usize> = (0..table.len()).filter(|&i| table[i].ord > bound).collect();
    println!("WHERE age > 40  => rows {over_40:?}");

    // ORDER BY age: sort by ORE term.
    let mut by_age: Vec<usize> = (0..table.len()).collect();
    by_age.sort_by(|&a, &b| table[a].ord.cmp(&table[b].ord));
    println!("ORDER BY age    => rows {by_age:?}");

    // --- Read side: decrypt only the rows a query matched -------------------

    // The fake source is deterministic, so a fresh instance re-derives the
    // same data keys (production: any client holding the same ZeroKMS
    // credentials and keyset).
    let decryptor = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await?;

    // Collect the matching rows and decrypt them together: one batched
    // retrieve_keys call, however many rows matched. The context must match
    // the one the records were encrypted under — it is bound into the AAD, so
    // a ciphertext cannot be replayed against a different field.
    let mut table = table;
    let mut matches: Vec<EncryptedInt> = Vec::new();
    // Descending index order keeps earlier indices valid across swap_remove.
    for i in over_40.into_iter().rev() {
        matches.push(table.swap_remove(i));
    }
    let ages: Vec<u32> = matches.decrypt_into(&decryptor, CONTEXT).await?;
    for age in ages {
        println!("decrypted matching row: age {age}");
    }

    Ok(())
}
