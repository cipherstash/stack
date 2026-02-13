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

- **Type-safe encryption**: The [`Encrypt`] and [`Decrypt`] traits provide a type-safe interface for encryption operations
- **Flexible AAD handling**: The [`IntoAad`] trait allows multiple types to be used as additional authenticated data
- **Protected types integration**: Works seamlessly with `vitaminc-protected` types to handle sensitive data
- **Side-channel resistance**: Uses an [`Unspecified`] error type that reveals no information about failures

## Usage

### Implementing the Cipher Trait

To use this crate, you need to implement the [`Cipher`] trait for your AEAD algorithm:

```rust
use vitaminc_aead::{Cipher, Unspecified, IntoAad, LocalCipherText};

struct MyCipher {
    // Your cipher implementation
}

impl Cipher for MyCipher {
    fn encrypt_slice<'a, A>(
        &self,
        plaintext: &'a [u8],
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>
    {
        // Your encryption implementation
        todo!()
    }

    fn encrypt_vec<'a, A>(
        &self,
        plaintext: Vec<u8>,
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>
    {
        // Your encryption implementation
        todo!()
    }

    fn decrypt_vec<'a, A>(
        &self,
        ciphertext: LocalCipherText,
        aad: A,
    ) -> Result<Vec<u8>, Unspecified>
    where
        A: IntoAad<'a>
    {
        // Your decryption implementation
        todo!()
    }
}
```

### Encrypting Data

Once you have a [`Cipher`] implementation, you can use the [`Encrypt`] trait to encrypt various types:

```rust
use vitaminc_aead::{Encrypt, Cipher};

fn encrypt_data<C: Cipher>(cipher: &C) -> Result<(), Box<dyn std::error::Error>> {
    // Encrypt a string
    let encrypted_string = "secret message".encrypt(cipher)?;

    // Encrypt with additional authenticated data
    let encrypted_with_aad = "secret".encrypt_with_aad(cipher, "context data")?;

    // Encrypt a byte array
    let data = [1, 2, 3, 4, 5];
    let encrypted_bytes = data.encrypt(cipher)?;

    Ok(())
}
```

### Decrypting Data

Use the [`Decrypt`] trait to decrypt ciphertext back to the original type:

```rust
use vitaminc_aead::{Decrypt, Cipher, LocalCipherText};

fn decrypt_data<C: Cipher>(
    cipher: &C,
    ciphertext: LocalCipherText
) -> Result<String, Box<dyn std::error::Error>> {
    // Decrypt back to a String
    let plaintext = String::decrypt(ciphertext, cipher)?;
    Ok(plaintext)
}
```

### Additional Authenticated Data (AAD)

Many types can be used as AAD through the [`IntoAad`] trait:

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use vitaminc_aead::{Encrypt, Cipher};
use vitaminc_encrypt::{Key, Aes256Cipher};
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

let key = Key::random(&mut SafeRand::from_entropy())?;
let cipher = Aes256Cipher::new(&key)?;

// Use a string as AAD
"my-secret".encrypt_with_aad(&cipher, "user_id:123")?;

// Use a byte slice as AAD
"my-secret".encrypt_with_aad(&cipher, &b"metadata"[..])?;

// Use a u64 as AAD
"my-secret".encrypt_with_aad(&cipher, 42u64)?;

// Use a tuple to combine multiple AAD values
"my-secret".encrypt_with_aad(&cipher, ("user_id", "session_token"))?;

// Use no AAD
"my-secret".encrypt_with_aad(&cipher, ())?;
# Ok(())
# }
```

### Working with Protected Types

The crate integrates with `vitaminc-protected` to handle sensitive data safely:

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use vitaminc_aead::{Encrypt, Cipher};
use vitaminc_encrypt::{Key, Aes256Cipher};
use vitaminc_protected::Protected;
use vitaminc_random::{Generatable, SafeRand, SeedableRng};

let key = Key::random(&mut SafeRand::from_entropy())?;
let cipher = Aes256Cipher::new(&key)?;

let sensitive_data = Protected::new([1, 2, 3, 4, 5]);

let encrypted = sensitive_data.encrypt(&cipher)?;
# Ok(())
# }
```

### Custom Types

You can implement [`Encrypt`] and [`Decrypt`] for your own types to enable selective encryption:

```rust
use vitaminc_aead::{Encrypt, Decrypt, Cipher, IntoAad, Unspecified, LocalCipherText};

struct User {
    id: u64,
    email: String,
    password_hash: String,
}

struct EncryptedUser {
    id: u64,
    email: String,
    password_hash: LocalCipherText,  // Only encrypt the password hash
}

impl<'a> Encrypt<'a> for User {
    type Encrypted = EncryptedUser;

    fn encrypt_with_aad<C, A>(
        self,
        cipher: &C,
        aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        Ok(EncryptedUser {
            id: self.id,
            email: self.email,
            password_hash: self.password_hash.encrypt_with_aad(cipher, aad)?,
        })
    }
}

impl Decrypt for User {
    type Encrypted = EncryptedUser;

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        Ok(User {
            id: encrypted.id,
            email: encrypted.email,
            password_hash: String::decrypt_with_aad(encrypted.password_hash, cipher, aad)?,
        })
    }
}
```

### Nonce Generation

The crate provides nonce generation utilities for AEAD operations:

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use vitaminc_aead::{NonceGenerator, RandomNonceGenerator};

// Create a random nonce generator for 12-byte nonces
let generator = RandomNonceGenerator::<12>::init();
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
