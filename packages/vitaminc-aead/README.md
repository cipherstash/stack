# Vitamin C AEAD

[![Crates.io](https://img.shields.io/crates/v/vitaminc-aead.svg)](https://crates.io/crates/vitaminc-aead)
[![Workflow Status](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml/badge.svg)](https://github.com/cipherstash/vitaminc/actions/workflows/test.yml)

Authenticated Encryption with Associated Data (AEAD) primitives for building secure encryption systems.

This crate is part of the [Vitamin C](https://github.com/cipherstash/vitaminc) framework to make cryptography code healthy.

## What is AEAD?

AEAD (Authenticated Encryption with Associated Data) is a form of encryption that provides both confidentiality and authenticity. It ensures that:

- **Confidentiality**: The plaintext is encrypted and cannot be read without the key
- **Authenticity**: The ciphertext cannot be modified without detection
- **Associated Data**: Additional data can be authenticated (but not encrypted) alongside the ciphertext

This crate provides traits and types for implementing AEAD operations in a safe and ergonomic way.

## Key Features

- **Composable encryption shape**: The [`Cipher`] trait is paired with [`SeqCipher`] and [`MapCipher`] sub-traits so a single cipher can drive byte, sequence, and map encryption with a consistent API
- **Visitor-pattern decryption**: The [`Decrypt`] / [`Decipher`] / [`DecipherVisitor`] trio mirrors `serde`'s `Deserialize` / `Deserializer` / `Visitor`, letting types describe how they decrypt themselves independently of any specific cipher
- **Flexible AAD handling**: The [`IntoAad`] trait lets strings, byte slices, integers, tuples, and `()` all be used as additional authenticated data
- **Protected types integration**: Works with `vitaminc-protected` so sensitive plaintext stays wrapped through encrypt and decrypt
- **Side-channel-aware errors**: The [`Unspecified`] error type reveals no information about the cause of a failure

## Usage

### Implementing the Cipher trait

A [`Cipher`] is consumed by the operation it drives — typically you implement it for a *reference* to your cipher state (`&MyCipher`) so the same cipher can be reused across many calls. The trait declares the output (`Ok`) and error types, plus associated types for sequence and map encryption:

```rust,no_run
use vitaminc_aead::{Cipher, IntoAad, MapCipher, SeqCipher, Unspecified};

pub struct MyCipher { /* key material, nonce generator, ... */ }

pub struct MyCipherText(/* ... */);
pub struct MySeqCipher<'c>(&'c MyCipher /* + state */);
pub struct MyMapCipher<'c>(&'c MyCipher /* + state */);

impl<'c> Cipher for &'c MyCipher {
    type Ok = MyCipherText;
    type Error = Unspecified;
    type SeqCipher = MySeqCipher<'c>;
    type MapCipher = MyMapCipher<'c>;

    fn encrypt_bytes_vec<'a, A>(self, data: Vec<u8>, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        todo!("seal `data` with AAD and return a ciphertext")
    }

    fn encrypt_seq(self, size_hint: Option<usize>) -> Self::SeqCipher {
        todo!("return a SeqCipher initialised with `size_hint` capacity")
    }

    fn encrypt_map(self) -> Self::MapCipher {
        todo!("return a MapCipher")
    }
}

impl<'c> SeqCipher for MySeqCipher<'c> {
    type Ok = MyCipherText;
    type Error = Unspecified;

    fn encrypt_next<'a, T, A>(self, _data: T, _aad: A) -> Result<Self, Self::Error>
    where
        T: vitaminc_aead::Encrypt,
        A: IntoAad<'a>,
    { todo!() }

    fn end(self) -> Result<Self::Ok, Self::Error> { todo!() }
}

impl<'c> MapCipher for MyMapCipher<'c> {
    type Ok = MyCipherText;
    type Error = Unspecified;

    fn encrypt_key(self, _key: &'static str) -> Result<Self, Self::Error> { todo!() }

    fn encrypt_value<'a, T, A>(self, _value: T, _aad: A) -> Result<Self, Self::Error>
    where
        T: vitaminc_aead::Encrypt,
        A: IntoAad<'a>,
    { todo!() }

    fn end(self) -> Result<Self::Ok, Self::Error> { todo!() }
}
```

For a complete reference implementation see `vitaminc_encrypt::Aes256Cipher`.

### Encrypting data

Once you have a `Cipher` implementation (typically for `&MyCipher`), use the [`Encrypt`] trait. Many built-in types already implement `Encrypt`:

```rust,ignore
use vitaminc_aead::Encrypt;

// `cipher: MyCipher` where `Cipher` is implemented for `&MyCipher`.

// Encrypt a string
let encrypted_string = "secret message".encrypt(&cipher)?;

// Encrypt with additional authenticated data
let encrypted_with_aad = "secret".encrypt_with_aad(&cipher, "context data")?;

// Encrypt a byte array
let encrypted_bytes = [1u8, 2, 3, 4, 5].encrypt(&cipher)?;
```

Note that `Encrypt::encrypt` consumes the cipher value. Implementing `Cipher` for `&MyCipher` (rather than `MyCipher`) means you can pass `&cipher` for each call and reuse the underlying state.

### Decrypting data

Decryption uses a visitor pattern modelled on `serde::Deserialize`:

- A type that knows how to decrypt itself implements [`Decrypt`].
- A cipher provides a [`Decipher`] (typically wrapping a ciphertext + cipher state) that drives the decryption.
- Concrete cipher implementations expose ergonomic decrypt entry points — for example, `Aes256Cipher` provides `cipher.decrypt::<T>(ciphertext)` and `cipher.decrypt_with_aad::<T, _>(ciphertext, aad)`.

```rust,ignore
// Using a concrete cipher (see `vitaminc_encrypt::Aes256Cipher`):
let plaintext: String = cipher.decrypt(ciphertext)?;
let plaintext: String = cipher.decrypt_with_aad(ciphertext, "context data")?;
```

`String`, `Vec<u8>`, `[u8; N]`, `u32`, `Vec<T: Decrypt>`, `HashMap<String, T: Decrypt>`, and `Protected<T: Decrypt>` all implement `Decrypt` out of the box.

> **Note on maps:** `HashMap` decryption yields `HashMap<String, T>`, but map *encryption* requires statically known keys — only `HashMap<&'static str, T>` implements `Encrypt`. Map keys are passed to [`MapCipher::encrypt_key`], which takes a `&'static str`. A `HashMap<String, T>` with runtime-derived keys can therefore be decrypted but not encrypted directly.

### Additional Authenticated Data (AAD)

Many types can be used as AAD through the [`IntoAad`] trait:

```rust,ignore
use vitaminc_aead::Encrypt;

// String AAD
"my-secret".encrypt_with_aad(&cipher, "user_id:123")?;

// Byte slice AAD
"my-secret".encrypt_with_aad(&cipher, &b"metadata"[..])?;

// Integer AAD
"my-secret".encrypt_with_aad(&cipher, 42u64)?;

// Tuple AAD (PAE-encoded to prevent canonicalisation attacks)
"my-secret".encrypt_with_aad(&cipher, ("user_id", "session_token"))?;

// No AAD
"my-secret".encrypt_with_aad(&cipher, ())?;
```

### Working with Protected Types

The crate integrates with `vitaminc-protected` so sensitive plaintext stays wrapped:

```rust,ignore
use vitaminc_aead::Encrypt;
use vitaminc_protected::Protected;

let sensitive_data = Protected::new([1u8, 2, 3, 4, 5]);
let encrypted = sensitive_data.encrypt(&cipher)?;
```

The corresponding `Decrypt` impl for `Protected<T>` re-wraps the decrypted plaintext, so the value stays inside `Protected` end-to-end.

### Custom Types

Implementing [`Encrypt`] and [`Decrypt`] for your own types lets you choose which fields are encrypted and how the ciphertext is structured.

```rust
use vitaminc_aead::{
    Cipher, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess, MapCipher,
    Unspecified,
};

struct User {
    id: u64,
    email: String,
    password_hash: String,  // Will be encrypted
}

impl Encrypt for User {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        // Encrypt the user as a map of named fields, encrypting only the
        // password hash. id and email are not stored here for brevity —
        // a real implementation would also encrypt or pass them through.
        cipher
            .encrypt_map()
            .encrypt_entry("password_hash", self.password_hash, aad)?
            .end()
    }
}

impl<'c> Decrypt<'c> for User {
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
        // A visitor describes what to do with each shape the cipher might
        // produce. Here we only accept maps.
        struct UserVisitor;
        impl<'c> DecipherVisitor<'c> for UserVisitor {
            type Value = User;

            fn visit_map<A: MapAccess<'c>>(self, mut map: A) -> Result<Self::Value, Unspecified> {
                let mut password_hash = None;
                while let Some((key, value)) =
                    map.next_entry::<String>().map_err(|_| Unspecified)?
                {
                    if key == "password_hash" {
                        password_hash = Some(value);
                    }
                }
                Ok(User {
                    id: 0,
                    email: String::new(),
                    password_hash: password_hash.ok_or(Unspecified)?,
                })
            }
        }
        decipher.decrypt_map(UserVisitor)
    }
}
```

The visitor pattern keeps the cipher and the type independent: the cipher decides how the ciphertext is laid out and how AAD is enforced, while the type decides how its fields are reassembled.

### Nonce Generation

The crate provides nonce generation utilities for AEAD operations:

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use vitaminc_aead::{NonceGenerator, RandomNonceGenerator};

// Create a random nonce generator for 12-byte nonces
let generator = RandomNonceGenerator::<12>::init()?;
let nonce = generator.generate()?;
# Ok(())
# }
```

## Security Considerations

- Always use unique nonces for each encryption operation with the same key
- Never reuse nonces with the same key, as this can compromise security
- The [`Unspecified`] error type is used to prevent side-channel attacks by not revealing information about failures
- When decrypting, always verify authentication before processing the plaintext

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT
