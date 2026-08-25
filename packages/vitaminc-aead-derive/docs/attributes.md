# Attributes

All options live under `#[aead(...)]`. Anything else — a misspelling included —
is a compile error rather than a silently dropped setting, because a dropped
option is one the author believes is in effect.

| Attribute | Applies to | Effect |
|---|---|---|
| `crate = "path"` | container | Name the path to `vitaminc_aead` in the generated code |
| `rename = "name"` | field | Store the field under `name` instead of its own name |
| `passthrough` | field | Store the field **in the clear**, unencrypted and unauthenticated |

## `#[aead(crate = "...")]`

Points the generated code at a re-export of `vitaminc_aead`, for callers who
depend on it through an umbrella crate rather than directly:

```ignore
#[derive(Encrypt, Decrypt)]
#[aead(crate = "::vitaminc::aead")]
struct User {
    name: String,
}
```

Every path the expansion emits is redirected, so the deriving crate needs no
direct dependency on `vitaminc_aead` at all.

## `#[aead(rename = "...")]`

Changes the map key a field is stored under:

```ignore
#[derive(Encrypt, Decrypt)]
struct User {
    #[aead(rename = "n")]
    name: String,
}
// ciphertext: Map { "n": … }
```

Field names are part of the ciphertext contract — each key is bound into the
AAD its value is sealed against — so renaming a field in Rust breaks
compatibility with data already stored under the old name. `rename` is how you
keep the old wire key while changing the Rust one.

Two fields cannot share a key; the collision is a compile error rather than a
value silently overwriting another. `rename` on a newtype is a compile error
too: a newtype is transparent, so its value is not stored under a key at all
and there is nothing to rename.

## `#[aead(passthrough)]`

Stores a field as a cleartext map entry, so it can be an ordinary database
column that other queries select, filter, and update without holding the key:

```ignore
#[derive(Encrypt, Decrypt)]
struct Row {
    #[aead(passthrough)]
    tenant: String,   // a plain column
    ssn: String,      // encrypted
}
```

### ⚠️ The field gives up all protection

That independence is bought by giving up everything, and the trade is total:

- The value is **not encrypted** — anyone who can read the stored ciphertext
  can read it.
- The value is **not authenticated**. No tag covers it, and unlike an encrypted
  entry's key, nothing binds its key either. It can be edited, retargeted at
  another key, added, or removed, and every encrypted field beside it still
  decrypts. Treat what comes back as untrusted input — it is exactly as
  trustworthy as the column it was read from.
- Deleting the entry is caught only by the ordinary missing-field rule, and is
  not distinguished from a value that was never written.

So: non-sensitive, non-security-deciding data only. Never a field the program
then trusts to make an authorization choice.

A cleartext field that must be tamper-evident needs to be bound into the AAD
instead of passed through — and note that binding couples the two, so any
independent write to that column would break decryption of every encrypted
field beside it. That coupling is precisely what `passthrough` exists to avoid.

### Requirements

A passthrough field's type must be `Any + Send + 'static`: the value travels
through the cipher type-erased and is downcast on the way out. That rules out
borrowed types such as `&'a str`.

Two shapes are rejected at compile time:

- **Every field passthrough.** Nothing would be encrypted, so the ciphertext
  would carry no tag at all — neither the associated data nor the entry keys
  would be authenticated. `MapCipher::end` refuses to seal such a container, so
  the derive refuses to emit one.
- **`passthrough` on a newtype.** A newtype is transparent and opens no map, so
  there is no entry to store in the clear; honouring the attribute would mean
  the whole value travelled unencrypted.
