//! A struct with a mix of encrypted and passthrough fields, encrypted as a
//! batch.
//!
//! `User` keeps `id` and `display_name` in the clear (passthrough) while
//! `email` and `age` are sealed — each encrypted leaf under its own ZeroKMS
//! data key. A `Vec<User>` encrypts in **one call and one batched
//! `generate_keys` round-trip**, producing a single ciphertext tree whose
//! shape (sequence of maps, entry keys) is authenticated by the AAD
//! derivation chain.
//!
//! Element *positions* are not. Every element of a sequence is sealed under
//! the same derived AAD, so reordering the elements of a stored sequence
//! still verifies. Order and length are the caller's
//! obligation; if they matter, bind them into the AAD yourself or store the
//! index alongside the row.
//!
//! Passthrough values travel in the clear and are **not authenticated** —
//! use them for non-sensitive routing/display data only.
//!
//! This is the *cipher-directed* layer — vitaminc's `Encrypt` / `Decrypt`
//! derives, sealed through the keyset directly — one level below
//! `#[derive(EncryptFrom)]`, which the
//! `encrypted_record` example uses. Reach for this layer when a value needs
//! what the derive does not express: fields stored in the clear beside
//! sealed ones, or a single ciphertext whose internal shape (this
//! sequence-of-maps) is what the AAD chain authenticates.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p stack-encrypt --example mixed_user
//! ```
//!
//! Talks to real ZeroKMS. On a developer machine, `npx stash auth login` is
//! sufficient: the cipher finds both the access token and the client key in
//! the CLI's profile directory. In CI, set `CS_CLIENT_ACCESS_KEY` /
//! `CS_WORKSPACE_CRN` and `CS_CLIENT_ID` / `CS_CLIENT_KEY` instead (see the
//! `zerokms_auth` example for the lookup order).

use stack_encrypt::{CipherText, Label, StackCipher, StackCipherText};
use vitaminc_aead::{Decrypt, Encrypt};

// --- The record type ---------------------------------------------------------

// The derives walk the struct as a map keyed by field name. Keys travel in
// the clear; each *encrypted* value is sealed against an AAD derived from the
// map's AAD + its key, so entries cannot be renamed or swapped. Passthrough
// entries carry no such binding.
#[derive(Debug, PartialEq, Encrypt, Decrypt)]
struct User {
    #[aead(passthrough)]
    id: u32, // visible in the stored ciphertext
    #[aead(passthrough)]
    display_name: String,
    email: String, // encrypted
    age: u32,      // encrypted
}

// --- Inspect what a server would see -----------------------------------------

fn describe(ciphertext: &StackCipherText, indent: usize) {
    let pad = "  ".repeat(indent);
    match ciphertext {
        CipherText::Sequence(items) => {
            println!("{pad}sequence of {} rows:", items.len());
            for item in items {
                describe(item, indent + 1);
            }
        }
        CipherText::Map(entries) => {
            for (key, value) in entries {
                match value {
                    CipherText::Passthrough(frame) => {
                        // Passthrough values are readable without any key:
                        // the frame of the value, in the clear.
                        let Ok(frame) = frame.parse() else { continue };
                        if let Ok(v) = frame.visit(u32::sink()) {
                            println!("{pad}{key}: {v}  (passthrough, in the clear)");
                        } else if let Ok(v) = frame.visit(String::sink()) {
                            println!("{pad}{key}: {v:?}  (passthrough, in the clear)");
                        }
                    }
                    CipherText::Single(_) => {
                        println!("{pad}{key}: <ciphertext under its own data key>");
                    }
                    _ => println!("{pad}{key}: <nested>"),
                }
            }
        }
        _ => {}
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cipher = StackCipher::new().await?;

    let users = vec![
        User {
            id: 1,
            display_name: "alice".into(),
            email: "alice@example.com".into(),
            age: 34,
        },
        User {
            id: 2,
            display_name: "bob".into(),
            email: "bob@example.com".into(),
            age: 41,
        },
        User {
            id: 3,
            display_name: "carol".into(),
            email: "carol@example.com".into(),
            age: 29,
        },
    ];

    // The context names the data: a `Label` is the first-class spelling of a
    // name, here the users record at schema version 1, rendering `users/v1`
    // in the ZeroKMS log. (EQL's `Identifier`, a table and a column, is the
    // same shape with two segments.)
    let record = Label::new(["users", "v1"])?;

    // One call, one batched generate_keys round-trip for every encrypted leaf
    // in the whole Vec (here: 3 rows x 2 encrypted fields = 6 data keys).
    let ciphertext = cipher
        .default_keyset()
        .encrypt(users, record.clone())
        .await?;

    println!("what the stored ciphertext reveals:");
    describe(&ciphertext, 1);

    // One batched retrieve_keys round-trip, then a crypto-free structural
    // decode back into the typed rows. The AAD must match the encrypt call.
    let users: Vec<User> = cipher.decrypt(ciphertext, record).await?;

    println!("\ndecrypted rows:");
    for user in &users {
        println!("  {user:?}");
    }

    Ok(())
}
