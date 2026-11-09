//! Encrypt a table of users, query it by equality and by order, and decrypt
//! only the rows that match.
//!
//! Each user is encrypted into an `EncryptedUser`. That type's fields say what
//! is stored for each plaintext field:
//!
//! - The `age` field stores a ciphertext, an equality term, and an order term.
//! - The `email` field stores a ciphertext.
//!
//! One `encrypt_into(..).await` call encrypts the whole table. Queries compare
//! terms only, so they need no decryption and no ZeroKMS call.
//!
//! Nothing calls ZeroKMS until an `.await`. Encrypting the table makes one
//! batched `generate_keys` call. Decrypting the matching rows makes one
//! batched `retrieve_keys` call.
//!
//! Each field's context is the record's name, `users`, then the field's
//! name. The caller adds nothing to it. So two rows of the table can swap a
//! sealed field and both still decrypt. Binding each value to its row needs
//! a row ID declared on the record as a binding. That is not built yet.
//!
//! The plaintext type, `User`, follows the rules for a type that contains
//! secrets. `User` derives `Zeroize` and nothing else:
//!
//! - No `Debug`, so the plaintext cannot be printed.
//! - No `Clone`, so there are no copies to wipe.
//! - No `PartialEq`, because a derived comparison does not run in constant
//!   time.
//!
//! Encrypting a `User` consumes it and wipes it. A decrypted `User` goes
//! straight into a `Protected`. The `Protected` wipes it when it is dropped.
//!
//! Run it with:
//!
//! ```sh
//! cargo run -p stack-encrypt --example encrypted_record
//! ```
//!
//! The example calls the real ZeroKMS service. On a developer machine, run
//! `npx stash auth login` first: the cipher reads the access token and the
//! client key from the profile that command writes. In CI, set
//! `CS_CLIENT_ACCESS_KEY`, `CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, and
//! `CS_CLIENT_KEY` instead. The `zerokms_auth` example shows the order in
//! which the cipher looks for credentials.

use stack_encrypt::sem::{EqualityTerm, OreTerm};
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{
    nonempty, Ciphertext, Controlled, DecryptFrom, EncryptInto, Protected, StackCipher,
};
use zeroize::Zeroize;

// --- The types -----------------------------------------------------------------

/// An encrypted `u32`, stored as a ciphertext, an equality term, and an
/// order term. This is the layout of an EQL `integer_ord_ore` payload, without the
/// EQL encoding.
///
/// All three fields are derived from the one `u32`, under one context. The
/// context is the associated data of the ciphertext, and it keeps each term
/// separate from terms derived for other fields. Decryption opens the
/// ciphertext and ignores the terms.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: Ciphertext,
    eq: EqualityTerm,
    ord: OreTerm<u32>,
}

/// The plaintext. `Zeroize` is the only trait it derives. The module
/// documentation explains why.
#[derive(Zeroize)]
struct User {
    age: u32,
    email: String,
}

/// A `User`, encrypted field by field.
///
/// The `age` field is derived from `user.age` under the context
/// `("users", "age")`, and the `email` field from `user.email` under
/// `("users", "email")`. The first part of each context, `"users"`, is
/// written here once. It is part of what identifies the stored data, so the
/// derive never takes it from the name of a Rust type.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    age: EncryptedAge,
    email: Ciphertext,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The cipher seals each value under its own ZeroKMS data key. `new` also
    // loads the keyset's index key. The index key derives the terms. Data keys
    // and terms always come from the same keyset.
    let cipher = StackCipher::new().await?;
    // The client's default keyset.
    let keyset = cipher.default_keyset();

    // --- Encrypt a table of users -------------------------------------------

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

    // Each field has its own context, so the call needs no context from the
    // caller. The `Vec` conversion combines every user's key requests, so
    // five users make one batched `generate_keys` call. The call consumes
    // `users` and wipes each plaintext.
    let table: Vec<EncryptedUser> = users.encrypt_into(&keyset).await?;
    println!("stored {} encrypted users in one ZeroKMS call", table.len());

    // --- Query the table with terms -----------------------------------------

    // A query term is derived under the index key that the cipher already
    // loaded, and under the context the field was stored under. Building one
    // never calls ZeroKMS.

    // WHERE age = 34: compare equality terms.
    let probe: EqualityTerm = 34u32
        .encrypt_into_with_context(&keyset, nonempty!("users").with("age"))
        .await?;
    let equal: Vec<usize> = (0..table.len())
        .filter(|&i| table[i].age.eq == probe)
        .collect();
    println!("WHERE age = 34  => rows {equal:?}");

    // WHERE age > 40: compare order terms.
    let bound: OreTerm<u32> = 40u32
        .encrypt_into_with_context(&keyset, nonempty!("users").with("age"))
        .await?;
    let over_40: Vec<usize> = (0..table.len())
        .filter(|&i| table[i].age.ord > bound)
        .collect();
    println!("WHERE age > 40  => rows {over_40:?}");

    // ORDER BY age: sort by order term.
    let mut by_age: Vec<usize> = (0..table.len()).collect();
    by_age.sort_by(|&a, &b| table[a].age.ord.cmp(&table[b].age.ord));
    println!("ORDER BY age    => rows {by_age:?}");

    // --- Decrypt only the rows a query matched ------------------------------

    // A second client. Any process with the same ZeroKMS credentials and
    // keyset can decrypt what this one wrote.
    let decryptor = StackCipher::new().await?;

    // Decrypting the matching rows together makes one batched
    // `retrieve_keys` call, however many rows match. Each field opens under
    // the context it was sealed under. That context is the ciphertext's
    // associated data, so a ciphertext copied into another field does not
    // open.
    let mut table = table;
    let mut matches: Vec<EncryptedUser> = Vec::new();
    // Take the rows in descending order, so that `swap_remove` does not move
    // a row that is still to be taken.
    for i in over_40.into_iter().rev() {
        matches.push(table.swap_remove(i));
    }
    // The decrypted users are wrapped as soon as they arrive. The
    // `Protected` wipes them when it is dropped, and `risky_ref` marks the
    // one place the plaintext is read.
    let matched = Protected::new(Vec::<User>::decrypt_from(matches, &decryptor).await?);
    println!("decrypted {} matching rows", matched.risky_ref().len());

    Ok(())
}
