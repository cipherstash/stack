//! A searchable encrypted struct, end to end.
//!
//! The point of target-directed encryption: define the encrypted *shape* of
//! a value — "the ciphertext plus the index terms this field needs" — derive
//! `EncryptFrom` / `DecryptInto` for it, and every insert is one
//! `encrypt_into(..).await`. A tiny in-memory "table" then answers equality
//! and range queries purely by comparing terms, decrypting only the rows
//! that match.
//!
//! The async shape is the other half of the point: nothing here does I/O
//! until the `.await`. Terms derive locally; each ciphertext queues its
//! data-key request; the derive combines the field pendings with `zip` /
//! `map` — so a whole `Vec` of structs, encrypted through the `Vec`
//! implementation, settles in **one** batched ZeroKMS call, and the matching
//! rows decrypt in one more.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p stack-encrypt --example encrypted_record
//! ```
//!
//! Talks to real ZeroKMS. On a developer machine, `npx stash auth login` is
//! sufficient: the cipher finds both the access token and the client key in
//! the CLI's profile directory. In CI, set `CS_CLIENT_ACCESS_KEY` /
//! `CS_WORKSPACE_CRN` and `CS_CLIENT_ID` / `CS_CLIENT_KEY` instead (see the
//! `zerokms_auth` example for the lookup order).

use stack_encrypt::sem::{EqualityTerm, OreTerm};
use stack_encrypt::target::{DecryptFrom, EncryptInto};
use stack_encrypt::{nonempty, DecryptInto, EncryptFrom, Error, StackCipher, StackCipherText};

// --- The shapes ----------------------------------------------------------------

/// "An encrypted `u32`, stored as its ciphertext plus an equality term and an
/// ORE term." The same shape as an EQL `integer_ord_ore` payload, minus the
/// EQL wire encoding. Every field is derived from the one `u32`, under one
/// context: the context authenticates the ciphertext (AAD) and
/// domain-separates both terms (PRF context). `DecryptInto` opens the
/// ciphertext field and passes over the terms — the field types say which is
/// which, so no attribute is needed.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    eq: EqualityTerm,
    ord: OreTerm<u32>,
}

/// The plaintext.
#[derive(Debug, Clone, PartialEq)]
struct User {
    age: u32,
    email: String,
}

/// `User`, encrypted field by field: `age` from `user.age` under
/// `("users", "age")`, `email` from `user.email` under `("users", "email")`. The prefix
/// is named once, explicitly — it is part of the stored data's identity, so
/// it is never inferred from a Rust type name — and the field half follows
/// the plaintext field.
#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    age: EncryptedAge,
    email: StackCipherText,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One cipher does everything the shapes need: ZeroKMS-backed AEAD (every
    // leaf sealed under its own data key) and SEM term derivation under the
    // keyset's index key, which `init` loads. Data keys and terms are bound to
    // the same keyset by construction — there is no way to mix them up.
    let cipher = StackCipher::new().await?;
    // Sealing and term derivation bind to a keyset; this is the client's
    // default one.
    let keyset = cipher.default_keyset();

    // --- Write side: encrypt a table of users ---------------------------------

    let users: Vec<User> = [
        (29, "ada"),
        (34, "grace"),
        (41, "edsger"),
        (34, "barbara"),
        (57, "tony"),
    ]
    .into_iter()
    .map(|(age, name)| User {
        age,
        email: format!("{name}@example.com"),
    })
    .collect();

    // Every field carries its own context, so nothing is needed from the
    // caller — and one await seals the whole table: the `Vec` implementation
    // merges every struct's pending, so five users (two ciphertexts and two
    // terms each) settle in a single batched generate_keys call.
    let table: Vec<EncryptedUser> = users.encrypt_into(&keyset).await?;
    println!("stored {} encrypted users in one ZeroKMS call", table.len());

    // --- Query side: terms only, no plaintext, no decryption ------------------

    // Term probes derive under the index key the cipher already holds, under
    // the same context the field was stored under: building a query never
    // calls ZeroKMS at all.

    // WHERE age = 34: compare equality terms.
    let probe: EqualityTerm = 34u32
        .encrypt_into_with_context(&keyset, nonempty!("users").with("age"))
        .await?;
    let equal: Vec<usize> = (0..table.len())
        .filter(|&i| table[i].age.eq == probe)
        .collect();
    println!("WHERE age = 34  => rows {equal:?}");

    // WHERE age > 40: compare ORE terms.
    let bound: OreTerm<u32> = 40u32
        .encrypt_into_with_context(&keyset, nonempty!("users").with("age"))
        .await?;
    let over_40: Vec<usize> = (0..table.len())
        .filter(|&i| table[i].age.ord > bound)
        .collect();
    println!("WHERE age > 40  => rows {over_40:?}");

    // ORDER BY age: sort by ORE term.
    let mut by_age: Vec<usize> = (0..table.len()).collect();
    by_age.sort_by(|&a, &b| table[a].age.ord.cmp(&table[b].age.ord));
    println!("ORDER BY age    => rows {by_age:?}");

    // --- Read side: decrypt only the rows a query matched ---------------------

    // A separate client: any process holding the same ZeroKMS credentials and
    // keyset can decrypt what this one wrote.
    let decryptor = StackCipher::new().await?;

    // Collect the matching rows and decrypt them together: one batched
    // retrieve_keys call, however many rows matched. Each field opens under
    // the context it was sealed under — it is bound into the AAD, so a
    // ciphertext cannot be replayed against a different field.
    let mut table = table;
    let mut matches: Vec<EncryptedUser> = Vec::new();
    // Descending index order keeps earlier indices valid across swap_remove.
    for i in over_40.into_iter().rev() {
        matches.push(table.swap_remove(i));
    }
    let matched: Vec<User> = Vec::<User>::decrypt_from(matches, &decryptor).await?;
    for user in &matched {
        println!("decrypted matching row: {user:?}");
    }

    // --- Binding a value to its record ----------------------------------------

    // A context the caller passes *extends* every field's own: under the
    // record's id, `age` is sealed under `(("users", "age"), id)` and opens only
    // there — a ciphertext can no longer be moved between records of the
    // same table. The price is that its terms are scoped to that record too:
    // a probe built under `("users", "age")` alone never matches them, so extend
    // where a value is read by id, not where it is searched across rows.
    let id = 42u64;
    let alice = User {
        age: 34,
        email: "alice@example.com".into(),
    };
    let record: EncryptedUser = alice.clone().encrypt_into_with_context(&keyset, id).await?;
    let unscoped: Vec<usize> = std::iter::once(&record)
        .enumerate()
        .filter(|(_, r)| r.age.eq == probe)
        .map(|(i, _)| i)
        .collect();
    println!(
        "record-scoped terms match the table probe: {}",
        !unscoped.is_empty()
    );
    let scoped: EqualityTerm = 34u32
        .encrypt_into_with_context(&keyset, nonempty!("users").with("age").with(id))
        .await?;
    println!(
        "  ...and a probe built under the same id: {}",
        record.age.eq == scoped
    );

    let opened = User::decrypt_from_with_context(record, &decryptor, id).await?;
    assert_eq!(opened, alice);
    // The record id is in every field's context, and the context is the
    // ZeroKMS descriptor of every data key: opening under another id fails
    // at ZeroKMS, before any key material moves. (Against a source that
    // does not enforce descriptors — the fake — the AEAD refuses instead.)
    let record: EncryptedUser = alice.encrypt_into_with_context(&keyset, id).await?;
    let wrong_id = User::decrypt_from_with_context(record, &decryptor, 43u64).await;
    println!(
        "opening under another id: {}",
        match wrong_id {
            Err(Error::Provider(e)) => format!("refused by ZeroKMS ({e})"),
            Err(Error::Aead) => "refused (AEAD)".to_owned(),
            _ => "unexpected".to_owned(),
        }
    );

    Ok(())
}
