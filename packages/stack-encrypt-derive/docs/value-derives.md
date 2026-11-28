# Encrypting a type of your own

`#[derive(Encrypt)]` describes a value of your type to Stack Encrypt.
`#[derive(Decrypt)]` builds the value back. Import both from
`stack_encrypt`. Your crate needs no other dependency for them:

```rust
use stack_encrypt::{Decrypt, Encrypt, StackCipher};

#[derive(Encrypt, Decrypt)]
struct User {
    name: String,
    age: u32,
}
# tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
// With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
// the environment, or from the profile that `npx stash auth login` writes.
let cipher = StackCipher::builder()
#     .kms(stack_encrypt::kms::FakeDataKeySource::new())
    .init()
    .await?;
let keyset = cipher.default_keyset();
let user = User { name: "Ada".into(), age: 37 };
let stored = keyset.encrypt_tree(user, ("users", "profile")).await?;
let user: User = keyset.decrypt_tree(stored, ("users", "profile")).await?;
assert_eq!(user.name, "Ada");
assert_eq!(user.age, 37);
# Ok::<(), Box<dyn std::error::Error>>(())
# }).unwrap();
```

`#[derive(Encrypt)]` walks a struct into a sink as a map, with one entry
per field. `#[derive(Decrypt)]` generates the map sink that builds the
struct back. The sink hands each entry to the sink of the field's own type.

## The shape of the ciphertext

A struct is encrypted as a **map**, keyed by field name. A map binds each
entry's key into the associated data that its value is sealed against.
So nobody can rename or swap the fields of a stored ciphertext without
decryption failing. A sequence would not do this. The associated data of a
sequence element has no position in it, so two fields of the same type
could be swapped.

The map shape has these consequences:

- Field **names are part of the ciphertext**. Renaming a field breaks the
  data already stored under the old name. Use `#[aead(rename = "...")]` to
  keep the old name.
- A derived struct's ciphertext is the same as the ciphertext of the
  equivalent `HashMap<String, _>`, and of a map that another language's SDK
  wrote.
- A tuple struct of two or more fields uses each field's index as its key:
  `"0"`, `"1"`, and so on. Each field is bound to its key, as in a struct
  with named fields.
- A **newtype** is a struct with exactly one unnamed field, such as
  `struct Email(String)`. A newtype is *transparent*: it encrypts and
  decrypts exactly as its inner type. It adds nothing to the ciphertext.
  serde treats a newtype in the same way. So does `Protected<T>`.
  A newtype is also a `Scalar`, one leaf, when its inner type is one. So
  `Email(String)` is a `Scalar`, and `keyset.encrypt` takes it.
  `Tags(Vec<String>)` is not a `Scalar`.
- A unit struct, or a struct with no fields, encrypts to the authenticated
  marker of an empty map.

The entries of a stored map are not authenticated in any order. So the
derived `Decrypt` reads each key first, and matches it to a field.
Decryption is strict: it refuses an unknown key, a key that appears twice,
and a missing field.

## Enums

A **fieldless** enum is one `u32` leaf that contains the variant's
discriminant. The discriminant is an explicit `= n`, or one more than the
previous variant's, as Rust assigns them. The leaf is sealed and
authenticated like any other. Every variant's leaf has the same length, so
the length of the ciphertext does not show the variant.

Decryption refuses an integer that is not the discriminant of a variant.
Give each variant an explicit `= n` before you store anything. Otherwise,
reordering the variants changes their discriminants. Variants take no
`#[aead(...)]` attributes. A fieldless enum is a `Scalar`, by value and by
reference, because it is one leaf.

An enum with fields cannot be derived. There is no agreed layout for the
fields of a variant. Model the choice as a struct instead, with a
fieldless enum for the variant and an `Option` field for each variant's
data.

## Writing the impls by hand

A type can implement `Encrypt` and `Decrypt` by hand, with no other
dependency than `stack_encrypt`. The items a hand-written impl names are in
`stack_encrypt::plaintext`: the sink traits, the `depth` constants, and
the types of a scalar. A type that encrypts as one value also implements
`stack_encrypt::Scalar` for its borrow. The docs of
`stack_encrypt::OpaqueEncode` show a complete example.
