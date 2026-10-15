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

This crate provides the data model and the traversals for encrypting structured values with any AEAD cipher, in a safe and ergonomic way.

## Key Features

- **One data model**: a value is described once, as a [`Plaintext`] that walks itself into a [`Sink`]. Encryption, decryption, the transport frame, index terms and host bindings are all sinks or sources of the same model, so there is no intermediate value type to convert through.
- **A cipher is `seal` and `open`**: the [`Cipher`] trait seals and opens one leaf; every rule about the *shape* of a value (how map entries are bound to their keys, how sequence elements are bound to their sequence but not to their index or count, how empty containers are authenticated, the refusal of a container with nothing sealed) lives once in the encrypting sink and the opening walk. [`AsyncCipher`] is the same for a cipher that has to be awaited, with batching hooks for a remote key service.
- **Typed decryption names a sink**: a [`Decrypt`] target is any type that names the sink that builds it, so a ciphertext is decoded straight into a struct, a `Vec`, an `Option`, a `Protected<T>`, or a host value. Decoding is strict.
- **Self-describing leaves**: every scalar seals as a tagged leaf (`[tag] ++ payload`), with an optional logical type (a date, a timestamp, a decimal, a UUID) over its physical kind, so a value encrypted from Rust, Go or JavaScript opens from any of them.
- **Flexible AAD handling**: the [`IntoAad`] trait lets strings, byte slices, integers, tuples, and `()` all be used as additional authenticated data, and [`ContextTag`] moves the obligation to supply it into the type system.
- **Protected types integration**: works with `vitaminc-protected` so sensitive plaintext stays wrapped through encrypt and decrypt.
- **Side-channel-aware errors**: a cipher's [`Unspecified`] error reveals nothing about the cause of a failure.

## Usage

The examples below use a cipher that keeps the plaintext in the clear and authenticates the AAD, so they run without a key. A real one is `vitaminc_encrypt::Aes256Cipher`.

```rust
# use vitaminc_aead::{Cipher, Context, Unspecified};
# use vitaminc_protected::Protected;
# struct Clear;
# impl Cipher for Clear {
#     type Leaf = (Vec<u8>, Vec<u8>);
#     type Error = Unspecified;
#     fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Self::Leaf, Unspecified> {
#         Ok((aad.as_bytes().to_vec(), vitaminc_protected::Controlled::risky_unwrap(plaintext)))
#     }
#     fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
#         if leaf.0 != aad.as_bytes() { return Err(Unspecified); }
#         Ok(Protected::new(leaf.1))
#     }
# }
# let cipher = Clear;
use vitaminc_aead::{decrypt, encrypt};

// Encrypt a value under some associated data...
let ciphertext = encrypt(vec!["one".to_string(), "two".to_string()], &cipher, "user:42")?;

// ...and decrypt it back into the type you expect.
let plaintext: Vec<String> = decrypt(&cipher, ciphertext, "user:42")?;
assert_eq!(plaintext, ["one", "two"]);

// The wrong AAD fails at the cipher, and a ciphertext of the wrong shape
// fails at the type: a string where a sequence was stored is refused.
assert!(decrypt::<Vec<String>, _, _>(&cipher, encrypt("x", &cipher, "right")?, "wrong").is_err());
assert!(decrypt::<String, _, _>(&cipher, encrypt(vec![1u32], &cipher, ())?, ()).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Implementing a cipher

A cipher seals and opens one leaf. The `aad` it receives is the context the walk derived for the leaf's position (the caller's AAD for a top-level scalar, `Context::for_sequence_element` of it for a sequence element, `Context::for_map_entry` for a map value, and so on); the cipher binds whatever it needs on top, such as the wire version of its leaf format.

```rust
use vitaminc_aead::{Cipher, Context, Unspecified};
use vitaminc_protected::{Controlled, Protected};

struct MyCipher;

impl Cipher for MyCipher {
    /// The sealed leaf: here the AAD it was sealed under and the plaintext,
    /// which a real cipher replaces with `nonce ‖ ciphertext ‖ tag`.
    type Leaf = (Vec<u8>, Vec<u8>);
    /// Opaque: a wrong key, a wrong AAD and a tampered leaf look the same.
    type Error = Unspecified;

    fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Self::Leaf, Unspecified> {
        Ok((aad.as_bytes().to_vec(), plaintext.risky_unwrap()))
    }

    fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
        if leaf.0 != aad.as_bytes() {
            return Err(Unspecified);
        }
        Ok(Protected::new(leaf.1))
    }
}
```

A cipher that has to be awaited implements [`AsyncCipher`] instead, and drives [`encrypt_async`] and [`decrypt_async`]. The walk of the value finishes before the first await, so the future holds only the planned leaves and is `Send` even when the source is not. `seal_many` and `open_many` take every leaf of one document at once, for a provider with a batch API.

### Encrypting data

[`encrypt`] takes any [`Plaintext`] source. Built in: strings, bytes (`Vec<u8>`, `&[u8]`, `[u8; N]`), the integers `i8`, `i16`, `i32`, `i64`, `i128`, `u16`, `u32`, `u64` and `u128`, `f32` and `f64`, `bool`, `Option<T>`, `Vec<T>`, `HashMap<String, T>` and `BTreeMap<String, T>`, `Protected<T>` (walked by reference inside the wrapper), and, behind features, `chrono`, `rust_decimal` and `uuid` scalars. The result is a [`CipherText`] tree mirroring the value's shape: one sealed leaf per scalar, with the containers around them.

```rust
# use vitaminc_aead::{Cipher, Context, Unspecified};
# use vitaminc_protected::Protected;
# struct Clear;
# impl Cipher for Clear {
#     type Leaf = (Vec<u8>, Vec<u8>);
#     type Error = Unspecified;
#     fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Self::Leaf, Unspecified> {
#         Ok((aad.as_bytes().to_vec(), vitaminc_protected::Controlled::risky_unwrap(plaintext)))
#     }
#     fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
#         if leaf.0 != aad.as_bytes() { return Err(Unspecified); }
#         Ok(Protected::new(leaf.1))
#     }
# }
# let cipher = Clear;
use std::collections::BTreeMap;
use vitaminc_aead::{encrypt, CipherText};

// A scalar seals as one leaf.
assert!(matches!(encrypt("secret", &cipher, ())?, CipherText::Single(_)));

// A sequence seals each element under the element derivation of the AAD.
assert!(matches!(encrypt(vec![1u32, 2], &cipher, ())?, CipherText::Sequence(items) if items.len() == 2));

// A map seals each value under its key, so keys cannot be swapped or renamed.
let mut map = BTreeMap::new();
map.insert("name".to_string(), "Ada".to_string());
assert!(matches!(encrypt(map, &cipher, ())?, CipherText::Map(entries) if entries[0].0 == "name"));

// An empty container is an authenticated marker; `None` is a null leaf.
assert!(matches!(encrypt(Vec::<u32>::new(), &cipher, ())?, CipherText::EmptySequence(_)));
assert!(matches!(encrypt(None::<u32>, &cipher, ())?, CipherText::Single(_)));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Decrypting data

[`decrypt`] opens a ciphertext into any [`Decrypt`] target, named at the call site. A target names the sink that builds it, so the walk hands each opened leaf straight to the type: there is no intermediate tree, and a leaf that was wiped stays wiped. `String`, `Vec<u8>`, `[u8; N]`, the same integer and float widths as above, `bool`, `Option<T>`, `Vec<T>`, `HashMap<String, T>`, `BTreeMap<String, T>` and `Protected<T>` are targets out of the box, and the derive below adds your own types. There is no `u8` source or target on its own, because `Vec<u8>` is a bytes leaf and a `Vec<T>` of `u8` scalars would overlap with it; seal a single byte as a `u16` or a `[u8; 1]`.

For a value whose shape is not known at compile time, [`decrypt_into`] takes any [`Sink`]: a [`FrameWriter`] to get the transport frame a host binding reads, or a sink of your own.

```rust
# use vitaminc_aead::{Cipher, Context, Unspecified};
# use vitaminc_protected::Protected;
# struct Clear;
# impl Cipher for Clear {
#     type Leaf = (Vec<u8>, Vec<u8>);
#     type Error = Unspecified;
#     fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Self::Leaf, Unspecified> {
#         Ok((aad.as_bytes().to_vec(), vitaminc_protected::Controlled::risky_unwrap(plaintext)))
#     }
#     fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
#         if leaf.0 != aad.as_bytes() { return Err(Unspecified); }
#         Ok(Protected::new(leaf.1))
#     }
# }
# let cipher = Clear;
use vitaminc_aead::{decrypt, decrypt_into, encrypt, DecryptError, Frame, FrameWriter};

let ciphertext = encrypt(vec![Some(1u32), None], &cipher, "ctx")?;
let back: Vec<Option<u32>> = decrypt(&cipher, ciphertext, "ctx")?;
assert_eq!(back, [Some(1), None]);

// The same ciphertext, written as a frame instead of a Rust type.
let ciphertext = encrypt(vec![Some(1u32), None], &cipher, "ctx")?;
let mut frame = Vec::new();
decrypt_into(&cipher, ciphertext, "ctx", FrameWriter::new(&mut frame))?;
assert!(Frame::parse(&frame).is_ok());

// A target refuses a shape it cannot build, before anything is trusted.
let ciphertext = encrypt("text", &cipher, "ctx")?;
assert!(matches!(decrypt::<u32, _, _>(&cipher, ciphertext, "ctx"), Err(DecryptError::Sink(_))));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Additional Authenticated Data (AAD)

Many types can be used as AAD through the [`IntoAad`] trait:

```rust
# use vitaminc_aead::{Cipher, Context, Unspecified};
# use vitaminc_protected::Protected;
# struct Clear;
# impl Cipher for Clear {
#     type Leaf = (Vec<u8>, Vec<u8>);
#     type Error = Unspecified;
#     fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Self::Leaf, Unspecified> {
#         Ok((aad.as_bytes().to_vec(), vitaminc_protected::Controlled::risky_unwrap(plaintext)))
#     }
#     fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
#         if leaf.0 != aad.as_bytes() { return Err(Unspecified); }
#         Ok(Protected::new(leaf.1))
#     }
# }
# let cipher = Clear;
use vitaminc_aead::encrypt;

// String AAD
encrypt("my-secret", &cipher, "user_id:123")?;

// Byte slice AAD
encrypt("my-secret", &cipher, &b"metadata"[..])?;

// Integer AAD
encrypt("my-secret", &cipher, 42u64)?;

// Tuple AAD (PAE-encoded to prevent canonicalisation attacks)
encrypt("my-secret", &cipher, ("user_id", "session_token"))?;

// No AAD
encrypt("my-secret", &cipher, ())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Every one of those types is a context, and a context has one encoding. The AEAD's associated
data and a PRF's derivation context for the same value are the same bytes, because both are views
of the [`vitaminc-context`](https://docs.rs/vitaminc-context) crate: a context type implements
`IntoContext`, which names its parts as a `ContextPiece` tree, and `IntoAad` is a blanket over it.
There is no `into_aad` to write by hand, so a type of your own cannot be given one encoding for
the AEAD and another for the PRF.

```rust
use vitaminc_aead::{ContextPiece, IntoAad, IntoContext};

struct TenantId(u64);

impl<'a> IntoContext<'a> for TenantId {
    fn into_context(self) -> ContextPiece<'a> {
        ("tenant", self.0).into_context()
    }
}

let piece = TenantId(7).into_context();
assert_eq!(piece.to_string(), "(\"tenant\", 7u64)");
assert_eq!(piece.leaves().count(), 2);
assert_eq!(
    TenantId(7).into_aad().as_bytes(),
    ("tenant", 7u64).into_aad().as_bytes()
);
```

The parts view is for a consumer that has to name what the bytes were built from (a key service
logging the field a key was issued for, an audit trail) rather than parse framing back out of them.
`Display` renders different trees differently (in Rust literal syntax), so two contexts that
authenticate different bytes never share a log line.

A parts tree is the same context as the value it came from. A context that arrives as data, for
example across an FFI boundary, needs no mirror type: a `ContextPiece` list of one is `Some(x)`,
the empty list is `None`, a list of two is `(a, b)`, `nonempty!(a).with(b).with(c)` is the nested
`((a, b), c)`, and `ContextPiece::Unit` is `()`. Every leaf is typed, so `7u32` and `7i32` are
different contexts and so are `"ab"` and `b"ab"`. `ContextPiece` also implements `MaybeEmpty` by the
same rule the static types use, so a tree can be wrapped in `NonEmpty`.

[`ContextTag`] pairs a value with a tag that is folded into the AAD whenever it is encrypted, so a
value that must always be sealed against its context (a user id, a column name) cannot be
encrypted without it; `ContextTag::context(tag).decrypt(..)` mirrors it on the way out.

[`LeafTypeAad`] binds the column type a schema expects, its physical kind and logical type, into
the AAD at both ends, so a ciphertext written under one column type fails to open under another.
The binding is a declaration, not a check of the value, and it only works when both ends supply it.

### Working with Protected Types

The crate integrates with `vitaminc-protected` so sensitive plaintext stays wrapped. A `Protected<T>`
is a [`Plaintext`] whenever `&T` is: it is walked *by reference inside the wrapper*, so the secret
never leaves it on the way in. On the way out, `Protected<T>` is a [`Decrypt`] target that builds in
place: scalars are read straight into the wrapper, and a `Vec` or an `Option` builds inside it from
the first element, so a failure part way wipes what was already decoded.

```rust
# use vitaminc_aead::{Cipher, Context, Unspecified};
# use vitaminc_protected::Protected;
# struct Clear;
# impl Cipher for Clear {
#     type Leaf = (Vec<u8>, Vec<u8>);
#     type Error = Unspecified;
#     fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Self::Leaf, Unspecified> {
#         Ok((aad.as_bytes().to_vec(), vitaminc_protected::Controlled::risky_unwrap(plaintext)))
#     }
#     fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
#         if leaf.0 != aad.as_bytes() { return Err(Unspecified); }
#         Ok(Protected::new(leaf.1))
#     }
# }
# let cipher = Clear;
use vitaminc_aead::{decrypt, encrypt};
use vitaminc_protected::Controlled;

let sensitive = Protected::new("password123".to_string());
let ciphertext = encrypt(sensitive, &cipher, ())?;
let back: Protected<String> = decrypt(&cipher, ciphertext, ())?;
assert_eq!(back.risky_unwrap(), "password123");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Because a derived newtype is transparent, `#[derive(Plaintext)] struct Key(Protected<[u8; 32]>);`
gets exactly that path — no hand-written impl is needed to keep key material wrapped.

### Deriving `Plaintext` and `Decrypt`

A struct walks as a map keyed by field name, each value sealed under its key, and decodes strictly: an unknown key, a duplicate key or a missing field is refused. A fieldless enum is one int leaf holding the variant's discriminant.

```rust
# use vitaminc_aead::{Cipher, Context, Unspecified};
# use vitaminc_protected::Protected;
# struct Clear;
# impl Cipher for Clear {
#     type Leaf = (Vec<u8>, Vec<u8>);
#     type Error = Unspecified;
#     fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Self::Leaf, Unspecified> {
#         Ok((aad.as_bytes().to_vec(), vitaminc_protected::Controlled::risky_unwrap(plaintext)))
#     }
#     fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
#         if leaf.0 != aad.as_bytes() { return Err(Unspecified); }
#         Ok(Protected::new(leaf.1))
#     }
# }
# let cipher = Clear;
use vitaminc_aead::{decrypt, encrypt, CipherText, Decrypt, Plaintext};

#[derive(Debug, PartialEq, Plaintext, Decrypt)]
enum Role {
    Admin = 1,
    Member = 2,
}

#[derive(Debug, PartialEq, Plaintext, Decrypt)]
struct User {
    #[aead(passthrough)]
    id: u64,                 // stored in the clear, readable without the key
    #[aead(rename = "mail")]
    email: String,           // sealed under the wire key "mail"
    role: Role,
    #[aead(skip)]
    cached: Option<String>,  // not in the ciphertext at all; `Default` on decrypt
}

let user = User { id: 42, email: "ada@example.com".into(), role: Role::Admin, cached: Some("x".into()) };
let ciphertext = encrypt(user, &cipher, "users")?;
let CipherText::Map(entries) = &ciphertext else { panic!("a struct seals as a map") };
assert!(entries.iter().any(|(key, node)| key == "id" && matches!(node, CipherText::Passthrough(_))));

let back: User = decrypt(&cipher, ciphertext, "users")?;
assert_eq!(back, User { id: 42, email: "ada@example.com".into(), role: Role::Admin, cached: None });
# Ok::<(), Box<dyn std::error::Error>>(())
```

The attributes are documented on the derives: `rename`, `passthrough`, `skip`, `take` (for a type that implements `Drop`, such as one deriving `ZeroizeOnDrop`) and `crate`. A field's type must be at least as visible as the struct, since the generated sink names it.

### Custom types

A hand-written source implements [`Plaintext`] by walking itself into the sink, and a hand-written target implements [`Decrypt`] by naming a sink that builds it. Most types need neither; derive both. A source that is a thin view of something else, such as a frame or a host value, is where the trait is written by hand:

```rust
use vitaminc_aead::{MapSink, Plaintext, SeqSink, Sink};

/// A record whose fields are not all one type, so no `BTreeMap` fits.
struct Reading { sensor: String, values: Vec<f64>, ok: bool }

impl Plaintext for Reading {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(3))?;
        self.sensor.visit(map.entry("sensor")?)?;
        self.values.visit(map.entry("values")?)?;
        self.ok.visit(map.entry("ok")?)?;
        map.end()
    }
}

let frame = vitaminc_aead::to_frame(Reading { sensor: "a".into(), values: vec![1.5], ok: true })?;
assert!(vitaminc_aead::Frame::parse(vitaminc_protected::Controlled::risky_ref(&frame)).is_ok());
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Passing fields through in the clear

Not every column of a table needs encrypting. A record usually has a few fields that other queries select, filter, or update without holding the key — a display name, a schema version, a plain `id` column — beside the ones that must be sealed. Mark such a field `#[aead(passthrough)]` (or call [`Sink::passthrough`] from a hand-written source) and it is stored as a cleartext entry of the same ciphertext container, so the record still round-trips as one unit while that field stays an ordinary column. The payload is a [`PassthroughFrame`]: the subtree as a transport frame, in every binding and in static Rust.

**Passthrough provides no security guarantees whatsoever.** The value is not encrypted and not authenticated — it, and for map entries its key, can be read, edited, added, or removed in storage and every encrypted field beside it still decrypts. Treat what comes back as untrusted input: non-sensitive, non-security-deciding data only, never a field the program then trusts for authorization, tenancy, access control, or for choosing which encrypted record to trust. A container whose children are all passthrough has nothing to authenticate it and is refused.

Anything secret-bearing belongs in `Protected` and gets encrypted; anything that must be tamper-evident but readable belongs in the AAD, not in a passthrough.

### The frame

Host bindings do not convert their values into a Rust value tree. [`Frame`] is a validated, borrowed transport frame that implements [`Plaintext`] by walking its own bytes in place, [`FrameWriter`] is a [`Sink`] that writes one, and [`to_frame`] walks any source into a frame. The Go binding encrypts from the frame it receives and decrypts into one; the Node binding snapshots a JavaScript value as a frame to encrypt it off the JavaScript thread.

### Index terms

[`Tee`] runs two sinks over one walk. `vitaminc-normalize` uses it to produce equality terms beside encryption, so a document is walked once and every term exists before any cipher is called.

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
- When decrypting, always verify authentication before processing the plaintext: the walk opens every leaf before a typed target sees any of them
- Map keys and passthrough subtrees travel in the clear; keys are bound into the AAD of their values, passthrough is not bound at all
- A sequence's order and length are not authenticated: each element is bound to its sequence, not to its index, so elements can be reordered or dropped without a cipher failure. A caller who needs them should put them in a map or in the AAD

## CipherStash

Vitamin C is brought to you by the team at [CipherStash](https://cipherstash.com).

License: MIT
