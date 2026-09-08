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
//! the same derived AAD — deliberately, since that is what lets a single row
//! of a batch decrypt on its own as `Element<T>` — so reordering the elements
//! of a stored sequence still verifies. Order and length are the caller's
//! obligation; if they matter, bind them into the AAD yourself or store the
//! index alongside the row.
//!
//! Passthrough values travel in the clear and are **not authenticated** —
//! use them for non-sensitive routing/display data only.
//!
//! This is the *cipher-directed* layer — vitaminc's `Encrypt` / `Decrypt`
//! driven by hand — one level below `#[derive(EncryptFrom)]`, which the
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

use stack_encrypt::{
    Cipher, CipherText, Decipher, Decrypt, Encrypt, IntoAad, StackCipher, StackCipherText,
    Unspecified,
};
use vitaminc_aead::{DecipherVisitor, MapAccess, MapCipher, Passthrough};

// --- The record type ---------------------------------------------------------

#[derive(Debug, PartialEq)]
struct User {
    id: u32,              // passthrough: visible in the stored ciphertext
    display_name: String, // passthrough
    email: String,        // encrypted
    age: u32,             // encrypted
}

impl Encrypt for User {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        // Keys travel in the clear; each *encrypted* value is sealed against
        // an AAD derived from the map's AAD + its key, so entries cannot be
        // renamed or swapped. Passthrough entries carry no such binding.
        cipher
            .encrypt_map(aad)
            .encrypt_entry("id", Passthrough(self.id))?
            .encrypt_entry("display_name", Passthrough(self.display_name))?
            .encrypt_entry("email", self.email)?
            .encrypt_entry("age", self.age)?
            .end()
    }
}

impl<'c> Decrypt<'c> for User {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct UserVisitor;
        impl<'c> DecipherVisitor<'c> for UserVisitor {
            type Value = User;

            fn visit_map<M: MapAccess<'c>>(self, mut map: M) -> Result<User, Unspecified> {
                // Entries arrive in encryption order; each is pulled with its
                // expected type and its key is checked.
                fn entry<'c, M: MapAccess<'c>, T: Decrypt<'c> + 'c>(
                    map: &mut M,
                    key: &str,
                ) -> Result<T, Unspecified> {
                    let (k, value) = map
                        .next_entry::<T>()
                        .map_err(|_| Unspecified)?
                        .ok_or(Unspecified)?;
                    if k == key {
                        Ok(value)
                    } else {
                        Err(Unspecified)
                    }
                }

                let Passthrough(id) = entry::<_, Passthrough<u32>>(&mut map, "id")?;
                let Passthrough(display_name) =
                    entry::<_, Passthrough<String>>(&mut map, "display_name")?;
                let email: String = entry(&mut map, "email")?;
                let age: u32 = entry(&mut map, "age")?;
                Ok(User {
                    id,
                    display_name,
                    email,
                    age,
                })
            }
        }
        decipher.decrypt_map(UserVisitor, aad)
    }
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
                    CipherText::Passthrough(boxed) => {
                        // Passthrough values are readable without any key.
                        if let Some(v) = boxed.downcast_ref::<u32>() {
                            println!("{pad}{key}: {v}  (passthrough, in the clear)");
                        } else if let Some(v) = boxed.downcast_ref::<String>() {
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

    // One call, one batched generate_keys round-trip for every encrypted leaf
    // in the whole Vec (here: 3 rows x 2 encrypted fields = 6 data keys).
    let ciphertext = cipher.encrypt(users, "users/v1").await?;

    println!("what the stored ciphertext reveals:");
    describe(&ciphertext, 1);

    // One batched retrieve_keys round-trip, then a crypto-free structural
    // decode back into the typed rows. The AAD must match the encrypt call.
    let users: Vec<User> = cipher.decrypt(ciphertext, "users/v1").await?;

    println!("\ndecrypted rows:");
    for user in &users {
        println!("  {user:?}");
    }

    Ok(())
}
