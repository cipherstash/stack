# Attributes

All options live under `#[aead(...)]`. Anything else — a misspelling included —
is a compile error rather than a silently dropped setting, because a dropped
option is one the author believes is in effect.

| Attribute | Applies to | Effect |
|---|---|---|
| `crate = "path"` | container | Name the path to `vitaminc_aead` in the generated code |
| `rename = "name"` | field | Store the field under `name` instead of its own name |
| `passthrough` | field | Store the field **in the clear**, unencrypted and unauthenticated |
| `skip` | field | Leave the field out of the ciphertext; rebuild it with `Default` on decrypt |
| `take` | field | Take the value with `mem::take` instead of moving it, for a type that implements `Drop` |

Enum variants take no attributes.

## `#[aead(crate = "...")]`

Points the generated code at a re-export of `vitaminc_aead`, for callers who
depend on it through an umbrella crate rather than directly:

```ignore
#[derive(Plaintext, Decrypt)]
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
#[derive(Plaintext, Decrypt)]
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
#[derive(Plaintext, Decrypt)]
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

A passthrough field's type implements `Plaintext + Clone` on the way in
(the subtree is walked into a frame, and a sink that is really several sinks
gives each a copy) and `Decrypt` on the way out.

Two shapes are rejected at compile time:

- **Nothing sealed.** If every field is `passthrough` or `skip`, nothing would
  be encrypted, so the ciphertext would carry no tag at all — neither the
  associated data nor the entry keys would be authenticated. The encrypting
  sink refuses to seal such a container, so the derive refuses to emit one.
- **`passthrough` on a newtype.** A newtype is transparent and opens no map, so
  there is no entry to store in the clear; honouring the attribute would mean
  the whole value travelled unencrypted.

## `#[aead(skip)]`

Leaves a field out of the ciphertext altogether, for data that lives
somewhere else, such as an ordinary column alongside the ciphertext, or a
value derived from the others:

```ignore
#[derive(Plaintext, Decrypt)]
struct User {
    #[aead(skip)]
    id: u64,          // not in the ciphertext at all
    password: String, // encrypted
}
```

On encrypt the field contributes nothing: no entry, no key binding, and it
is not counted in the map's length. On decrypt it is rebuilt with
`Default::default()`, so its type must implement `Default`. The strict decode
rules treat a skipped field as never present: an entry that does turn up
under its key is refused as an unknown key.

Adding `skip` to a new field is not a wire-breaking change, since the field
is simply absent from the map. Changing a field that was sealed to `skip` is.

`skip` cannot be combined with `passthrough` or `take`, and is a compile error
on a newtype, whose only field is the whole value.

## `#[aead(take)]`

A struct that implements `Drop`, such as one that derives `ZeroizeOnDrop`,
cannot be destructured, so its fields cannot be moved out to be walked. `take`
swaps the field for its default with `core::mem::take` instead, and the empty
value left behind is dropped, and wiped, with `self`:

```ignore
#[derive(Plaintext, Decrypt, ZeroizeOnDrop)]
struct SecretToken(#[aead(take)] String);
```

The field's type must implement `Default`. Every stored field of a `Drop`
type that is not `Copy` needs it, passthrough fields included. A
`Protected<T>` field has no `Default` and needs no `take`: it wipes itself,
so a struct whose secrets are all `Protected` does not need `ZeroizeOnDrop`
in the first place. `take` only affects how the value leaves `self`; the
ciphertext is the same with or without it.

## Field types and visibility

The sink-based `Decrypt` derive generates a sink type beside the struct, with
the struct's visibility, whose public associated types name each field's
type. A field's type therefore has to be at least as visible as the struct,
or the derive fails with E0446 ("private type in public interface"). A type
that should stay unreachable from outside can be declared `pub` inside a
private module; it is then visible enough for the derive and still not
nameable by other crates.
