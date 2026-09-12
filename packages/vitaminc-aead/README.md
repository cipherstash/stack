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
use std::any::Any;
use vitaminc_aead::{Cipher, IntoAad, MapCipher, SeqCipher, Unspecified};
use vitaminc_protected::Protected;

pub struct MyCipher { /* key material, nonce generator, ... */ }

pub struct MyCipherText(/* ... */);
pub struct MySeqCipher<'c>(&'c MyCipher /* + state */);
pub struct MyMapCipher<'c>(&'c MyCipher /* + state */);

impl<'c> Cipher for &'c MyCipher {
    type Ok = MyCipherText;
    type Error = Unspecified;
    // The passthrough payload type: Box<dyn Any + Send> for Rust-native use
    // (callers box in, downcast out), or an owned host-value type for FFI.
    type Passthrough = Box<dyn Any + Send + 'static>;
    type SeqCipher = MySeqCipher<'c>;
    type MapCipher = MyMapCipher<'c>;

    fn encrypt_bytes_vec<'a, A>(
        self,
        data: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        unimplemented!("seal `data` with AAD and return a ciphertext")
    }

    // The AAD is captured here, once, and covers every element and the
    // empty marker — the sub-cipher methods take none of their own.
    fn encrypt_seq<'a, A>(self, size_hint: Option<usize>, aad: A) -> Self::SeqCipher
    where
        A: IntoAad<'a>,
    {
        unimplemented!("return a SeqCipher holding `aad`, sized by `size_hint`")
    }

    fn encrypt_map<'a, A>(self, aad: A) -> Self::MapCipher
    where
        A: IntoAad<'a>,
    {
        unimplemented!("return a MapCipher holding `aad`")
    }

    fn encrypt_none<'a, A>(self, _aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        unimplemented!("produce an authenticated 'absent' marker bound to `aad`")
    }

    fn passthrough(self, _value: Self::Passthrough) -> Result<Self::Ok, Self::Error> {
        unimplemented!("store `value` unencrypted inside the cipher's output container")
    }

    fn passthrough_boxed(
        self,
        _value: Box<dyn Any + Send + 'static>,
    ) -> Result<Self::Ok, Self::Error> {
        // Type-erased passthrough for self-describing encoders (e.g. FfiValue).
        // When the payload type IS `Box<dyn Any + Send>`, forward to `passthrough`.
        unimplemented!("store the boxed value unencrypted (or downcast to an owned type)")
    }
}

impl<'c> SeqCipher for MySeqCipher<'c> {
    type Ok = MyCipherText;
    type Error = Unspecified;
    type Passthrough = Box<dyn Any + Send + 'static>;

    fn encrypt_next<T>(self, _data: T) -> Result<Self, Self::Error>
    where
        T: vitaminc_aead::Encrypt,
    { unimplemented!() }

    fn passthrough_next(self, _value: Self::Passthrough) -> Result<Self, Self::Error> {
        unimplemented!()
    }

    fn end(self) -> Result<Self::Ok, Self::Error> { unimplemented!() }
}

impl<'c> MapCipher for MyMapCipher<'c> {
    type Ok = MyCipherText;
    type Error = Unspecified;
    type Passthrough = Box<dyn Any + Send + 'static>;

    fn encrypt_key<K>(self, _key: K) -> Result<Self, Self::Error>
    where
        K: Into<std::borrow::Cow<'static, str>>,
    { unimplemented!() }

    // Must seal the value against `Aad::for_map_entry(aad, key)` of the AAD
    // this MapCipher was constructed with — see the `MapCipher` docs on key
    // authentication.
    fn encrypt_value<T>(self, _value: T) -> Result<Self, Self::Error>
    where
        T: vitaminc_aead::Encrypt,
    { unimplemented!() }

    fn passthrough_entry<K>(self, _key: K, _value: Self::Passthrough) -> Result<Self, Self::Error>
    where
        K: Into<std::borrow::Cow<'static, str>>,
    { unimplemented!() }

    // The type-erased counterpart, for callers that cannot name
    // `Self::Passthrough` — a derived `Encrypt` impl, or a self-describing
    // tree value. Absorb the box, or reject a payload type you don't own.
    fn passthrough_entry_boxed<K>(
        self,
        _key: K,
        _value: Box<dyn std::any::Any + Send + 'static>,
    ) -> Result<Self, Self::Error>
    where
        K: Into<std::borrow::Cow<'static, str>>,
    { unimplemented!() }

    fn end(self) -> Result<Self::Ok, Self::Error> { unimplemented!() }
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

// Encrypt a byte vector — a byte leaf, the same wire shape as the array
let encrypted_vec = vec![1u8, 2, 3, 4, 5].encrypt(&cipher)?;
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

> **Note on maps:** both `HashMap<&'static str, T>` and `HashMap<String, T>` implement `Encrypt` (keys are anything `Into<Cow<'static, str>>`), and decryption yields `HashMap<String, T>`. Map keys travel in the clear but are bound into each value's AAD via [`Aad::for_map_entry`], so swapping or renaming keys inside a stored ciphertext causes decryption to fail.

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

Every one of those types also describes itself as a tree of *parts*, before
framing, through `IntoAad::into_aad_piece` — for a consumer that has to name what the
bytes were built from (a key service logging the field a key was issued for,
an audit trail, a structured binding built from the same parts as the AAD)
rather than parse PAE back out of them:

```rust
use vitaminc_aead::{AadPiece, IntoAad};

let piece = ("users/email", 7u64).into_aad_piece();
assert_eq!(piece.to_string(), "(\"users/email\", 7u64)");
assert_eq!(piece.leaves().count(), 2);
// Same bytes, one extra view.
assert_eq!(
    piece.into_aad().as_bytes(),
    ("users/email", 7u64).into_aad().as_bytes()
);
```

`into_aad_piece` has a default on `IntoAad` that returns the whole encoding as one opaque `Bytes`
leaf, so a context type of your own keeps compiling with only `into_aad`, and overrides
`into_aad_piece` when it wants its parts named. A `ContextTag` hands its cipher a context whose
`into_aad_piece()` is `List([extra_aad, tag])`, so a backend can read the parts directly, while
`into_aad()` still writes the bytes in one allocation. `Display` renders different trees
differently (in Rust literal syntax), so two contexts that authenticate different bytes never share
a log line.

A parts tree is the same context as the value it came from, on both sides a context is used.
`AadPiece` implements `IntoPrfContext` as well as `IntoAad`, and for every built-in context type
`x.into_aad_piece().into_aad() == x.into_aad()` and
`x.into_aad_piece().into_prf_context() == x.into_prf_context()` (checked by quickcheck). So a
context that arrives as data, for example across an FFI boundary, needs no mirror type: a list of
one is `Some(x)`, the empty list is `None`, a list of two is `(a, b)`,
`nonempty!(a).with(b).with(c)` is the nested `((a, b), c)`, and `AadPiece::Unit` is `()`.
`AadPiece` also implements `MaybeEmpty` by the same rule the static types use, so a tree can be
wrapped in `NonEmpty`.

### Working with Protected Types

The crate integrates with `vitaminc-protected` so sensitive plaintext stays wrapped:

```rust,ignore
use vitaminc_aead::Encrypt;
use vitaminc_protected::Protected;

let sensitive_data = Protected::new([1u8, 2, 3, 4, 5]);
let encrypted = sensitive_data.encrypt(&cipher)?;
```

The corresponding `Decrypt` impl for `Protected<T>` re-wraps the decrypted plaintext, so the value stays inside `Protected` end-to-end.

For the byte leaves — `[u8; N]`, `Vec<u8>`, and `String` — "end-to-end" is literal. `Protected<T>`'s impls go through [`Encrypt::encrypt_protected`] and [`Decrypt::decrypt_protected`], and the byte leaves override those to hand the still-wrapped value straight to the cipher's `Protected`-taking entry points (`Cipher::encrypt_bytes_array`, `Cipher::encrypt_bytes_vec`, `DecipherVisitor::visit_bytes_vec`). `String` converts between its string and byte-buffer representations *inside* the wrapper (via `Controlled::map`), so a `Protected<String>` password, like a `Protected<[u8; 32]>` key, is never unwrapped on its way in or out. Composite types take the defaults, which unwrap to `T` and rely on each leaf re-wrapping its own payload before it reaches the cipher.

Because a derived newtype is transparent, `#[derive(Encrypt)] struct Key(Protected<[u8; 32]>);` gets exactly that path — no hand-written impl is needed to keep key material wrapped.

### Deriving `Encrypt` and `Decrypt`

Most structs do not need a hand-written impl:

```rust
use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
struct User {
    name: String,
    age: u32,
}
```

A derived struct is encrypted as a **map keyed by field name**, which is the shape that gets each field its own AAD binding: `MapCipher` seals every value against `Aad::for_map_entry` of its key, so a stored field cannot be renamed, or moved onto another key, without decryption failing. A sequence would give no such guarantee — element AAD carries no positional component, so two same-typed fields would be freely interchangeable.

What follows from that shape:

- **Field names are part of the ciphertext contract.** Renaming a field breaks compatibility with data already encrypted; `#[aead(rename = "...")]` keeps the old wire key.
- A derived struct's ciphertext is interchangeable with the equivalent `HashMap<String, _>` ciphertext.
- A tuple struct of two or more fields is keyed by decimal index (`"0"`, `"1"`, …), so its fields are bound the same way.
- A **newtype** struct (exactly one unnamed field) is *transparent* — it encrypts and decrypts exactly as its inner type, adding nothing to the ciphertext. Wrapping an existing type is therefore not a wire-breaking change.
- A unit struct, or a struct with no fields, encrypts to the authenticated empty-map marker.

Decoding is strict. Entry order in a stored ciphertext is not authenticated, so the derived `Decrypt` reads keys first and matches them to fields; a missing field, an unknown key, or a duplicate key is rejected rather than defaulted or skipped, because an entry whose value is never decrypted is an entry whose AAD binding is never verified.

Enums are **not** supported: a ciphertext carries no authenticated variant discriminator, so any encoding the macro could pick would either leak the variant in the clear or leave it forgeable. Model the choice explicitly instead — for example as a struct of `Option` fields.

A field that should be stored **in the clear** — a plain database column other queries can read without the key — takes `#[aead(passthrough)]`. Such a field is neither encrypted nor authenticated; the derive's documentation spells out exactly what that gives up.

Use `#[aead(crate = "...")]` on the container when `vitaminc_aead` is reached through a re-export, e.g. `#[aead(crate = "::vitaminc::aead")]`.

### Custom Types

Where the derive's shape is not what you want, implement [`Encrypt`] and [`Decrypt`] by hand. The cases that call for it:

- **Leaving fields out of the ciphertext entirely** (as opposed to storing them in the clear, which is `#[aead(passthrough)]`).
- **A non-map layout** — a sequence, or a single leaf built from several fields.
- **Transforming the AAD** on the way through, as [`ContextTag`] and [`Element`] do.
- **Enums**, which the derive rejects.

For example, a `User` whose `id` and `email` live in ordinary columns and whose `password_hash` is encrypted is a derive with two passthrough fields:

```rust
use vitaminc_aead::{Decrypt, Encrypt};

#[derive(Encrypt, Decrypt)]
struct User {
    #[aead(passthrough)]
    id: u64,
    #[aead(passthrough)]
    email: String,
    password_hash: String, // encrypted
}
```

But if `id` and `email` are not to be stored in this ciphertext at all, that is a hand-written impl:

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
        // Encrypt the user as a map of named fields, storing only the
        // password hash — id and email are deliberately left out of this
        // ciphertext. The AAD is supplied once, to `encrypt_map`.
        cipher
            .encrypt_map(aad)
            .encrypt_entry("password_hash", self.password_hash)?
            .end()
    }
}

impl<'c> Decrypt<'c> for User {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        // A visitor describes what to do with each shape the cipher might
        // produce. Here we only accept maps. The `aad` mirrors the encrypt
        // side and is threaded to the decipher so each value is authenticated
        // against it.
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
        decipher.decrypt_map(UserVisitor, aad)
    }
}
```

The visitor pattern keeps the cipher and the type independent: the cipher decides how the ciphertext is laid out and how AAD is enforced, while the type decides how its fields are reassembled.

### Passing fields through in the clear

Not every column of a table needs encrypting. A record usually has a few fields that other queries select, filter, or update without holding the key — a display name, a schema version, a plain `id` column — beside the ones that must be sealed. Wrap such a field in [`Passthrough`] and it is stored as a cleartext entry of the same ciphertext container, so the record still round-trips as one unit while that field stays an ordinary column.

**Passthrough provides no security guarantees whatsoever.** The value is not encrypted and not authenticated — it, and for map entries its key, can be read, edited, added, or removed in storage and every encrypted field beside it still decrypts. Treat what comes back as untrusted input: non-sensitive, non-security-deciding data only, never a field the program then trusts for authorization, tenancy, access control, or for choosing which encrypted record to trust. The full contract is documented once, under [`#[aead(passthrough)]`](Encrypt#aeadpassthrough); `Passthrough<T>` is the hand-written equivalent of that attribute.

Because a custom type's impl is generic over every cipher, it cannot name a particular cipher's passthrough payload type; `Passthrough<T>` drives the type-erased channel for it, through the same `encrypt_entry` / `next_value` calls as any encrypted field:

```rust
use vitaminc_aead::{
    Cipher, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess, MapCipher,
    Passthrough, Unspecified,
};

struct User {
    id: u32,       // stored in the clear
    email: String, // encrypted
}

impl Encrypt for User {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher
            .encrypt_map(aad)
            .encrypt_entry("id", Passthrough(self.id))?
            .encrypt_entry("email", self.email)?
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

            fn visit_map<A: MapAccess<'c>>(self, mut map: A) -> Result<Self::Value, Unspecified> {
                // Entry order in a stored ciphertext is not authenticated, so
                // read key-first and let the key choose the type — never the
                // position. A duplicate, unknown, or missing key is an error:
                // a skipped value is one whose binding was never verified.
                let (mut id, mut email) = (None, None);
                while let Some(key) = map.next_key().map_err(|_| Unspecified)? {
                    match key.as_str() {
                        "id" if id.is_none() => {
                            let Passthrough(value) =
                                map.next_value::<Passthrough<u32>>().map_err(|_| Unspecified)?;
                            id = Some(value);
                        }
                        "email" if email.is_none() => {
                            email = Some(map.next_value::<String>().map_err(|_| Unspecified)?);
                        }
                        _ => return Err(Unspecified),
                    }
                }
                Ok(User {
                    id: id.ok_or(Unspecified)?,
                    email: email.ok_or(Unspecified)?,
                })
            }
        }
        decipher.decrypt_map(UserVisitor, aad)
    }
}
```

Anything secret-bearing belongs in `Protected` and gets encrypted; anything that must be tamper-evident but readable belongs in the AAD, not in a passthrough.

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
