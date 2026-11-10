# Attributes

All attributes are written inside `#[stash(...)]`. There are two pairs of
derives, and they read the same attributes.

**Use `EncryptTarget` and `DecryptSource`.** With these, encryption takes
the plaintext by value. The call `user.encrypt_into(&keyset)` moves `user`
into the encryption, so the caller has no copy left. The encryption then
wipes the plaintext: it overwrites the memory that held each encrypted
field. Only this pair accepts `passthrough`.

`EncryptFrom` and `DecryptInto` are the older pair. They encrypt a borrowed
plaintext, `&user`. The caller keeps the original, and must wipe it. Plans
and the dynamic engine still use them. The older pair will be removed once
plans and the dynamic engine use the new pair (#1488).

Derive one pair or the other on a record. `EncryptTarget` and
`DecryptSource` already implement `EncryptFrom` and `DecryptInto` for the
record, so an owned record also works where the older pair is expected.
If you derive both pairs, those traits are implemented twice. That does not
compile.

## On the struct

| Attribute | Effect |
|---|---|
| `plaintext = Type` | Every field is derived from one whole value of `Type`. You can repeat it: the derive writes one impl for each type you list. Leave it out for one impl that is generic over the plaintext. |
| `struct = Type` | The record encrypts the struct `Type` field by field. Each field is derived from the plaintext field of the same name, under the context `("<scope>", "<field>")`. See [Structs, field by field](#structs-field-by-field). Needs `scope`. Not with `plaintext`. |
| `scope = "..."` | With `struct` only. The record's name, which is the first scope of every field's context. The field's name is the next scope. Required. It must not be empty, and the derive never takes it from the type's name. |
| `context_type = Type` | The context type that the caller passes, for a record whose fields all take the caller's context. The default is `CallerContext`. Use `AeadContext` for a record made only of ciphertexts. See [Which context a record takes](#which-context-a-record-takes). Not with `context_field` or `struct`. |
| `crate = "path"` | The path to `stack_encrypt` in the generated code. The default is `::stack_encrypt`. Set it when you use the derives through a re-export. |

A `plaintext` type must be an owned type, not a reference. The generated
impl has no lifetime to give a reference.

Without `plaintext`, each derive writes one impl that is generic over the
plaintext. The impl accepts any plaintext that every field accepts. For
example, `EncryptedAge` below accepts any `P` that both `StackCipherText`
and `EqualityTerm` accept. With `plaintext`, the record accepts only the
types you list. A record that stores an integer should not accept a
`String`, for example.

`plaintext = User` treats a struct `User` as one value. It derives every
field from the whole `User`. To encrypt a struct field by field, use
`struct = User`.

## On a field

| Attribute | Effect |
|---|---|
| `context_field` | This field stores the record's context, and decryption reads it back. At most one per record. Not with any other field attribute. |
| `identity = "..."` | With `struct` only. The field is derived under `("<scope>", "<identity>")`, in place of the plaintext field's name. One plain segment. The plan builder's `.identity(segment)` does the same. |
| `from = field` or `from = 0` | With `struct` only. Derive this field from `plaintext.field`, or `plaintext.0` for a tuple struct, when the names differ. Each plaintext field has one output, so two fields `from` the same plaintext field are refused. A ciphertext with search terms is one `Encrypted<Terms>` field. |
| `default` or `default = expr` | The field is not derived. It is filled with `Default::default()` or `expr`. It is not encrypted and not authenticated. |
| `decrypt` | Decryption opens this field. Use it only when the field types do not decide it. See [Which field decryption opens](#which-field-decryption-opens). |
| `passthrough` | Owned derives, with `struct` only. The plaintext field is moved into the record as it is, and moved back on decryption. It is **not encrypted and not authenticated**. See [Passthrough fields](#passthrough-fields). Not with `identity`, `default` or `decrypt`. |

A field cannot have a `context = ".."` of its own, on any derive. Every
field of a `plaintext` record shares the caller's context. Every field of a
`struct` record sits under the record's scope, and `identity` changes only
its second part. To write one value under two contexts, use a plan that
picks the same source twice.

**Upgrading from 0.2.0.** Version 0.2.0 accepted a field `context = ".."`
and `#[stash(nested)]`. Each change below derives the field under a
different context from the one 0.2.0 used:

- removing the field's `context = ".."` from a `plaintext` record;
- writing `identity = ".."` in its place on a `struct` record;
- removing `nested`.

Data that 0.2.0 wrote does not decrypt under the new context. Its search
terms do not match new query terms either. Re-encrypt that data.

## The context of each kind of record

| Record | Encryption needs | Decryption needs |
|---|---|---|
| With a `context_field` of type `T` | A `NonEmpty<T>`, which the record stores in that field | Nothing, or the `NonEmpty<T>` the caller expects. See [Check where a record with a `context_field` came from](#check-where-a-record-with-a-context_field-came-from) |
| `struct = ..` | No context from the caller. Each field has its own | The same |
| `plaintext = ..` | A `CallerContext`, built from a `NonEmpty<T>` or an integer | The same |

The type `T` of a `context_field` must implement these traits: Vitamin C's
context traits, `Clone`, `MaybeEmpty`, and `PartialEq`. The stored context is not
encrypted.

No context is ever taken from a Rust type's name.

## Owned records

An owned record is a struct that you derive `EncryptTarget` and
`DecryptSource` on. It takes the attributes above.

- `user.encrypt_into(&keyset)` takes the plaintext by value, encrypts each
  field, and wipes each field it encrypts.
- `Protected::<User>::decrypt_from(record, &cipher)` decrypts the record
  into a `Protected`. The `Protected` wipes the plaintext when it is
  dropped.

The plaintext type must implement `Zeroize`.

### The context a call takes

Each kind of record decides whether the caller must pass a context, may
pass one, or must not pass one. Its `ContextInput` type says which:

| Record | Encrypt input | Decrypt input | Example call |
|---|---|---|---|
| `struct = User, scope = "users"` | `DeclaredScopes`, which takes no context from the caller | The same as for encryption | `user.encrypt_into(&keyset)` |
| `plaintext = T` | `RequiredContext<CallerContext>`, or `RequiredContext<AeadContext>` with `context_type = AeadContext` | The same as for encryption | `value.encrypt_into_with_context(&keyset, nonempty!("users/email"))` |
| With a `context_field` of type `C` | `RequiredContext<NonEmpty<C>>` | Nothing, or the `NonEmpty<C>` the caller expects | `T::decrypt_from_with_context(record, &cipher, nonempty!(..))`, which checks the stored context before it decrypts |

#### Check where a record with a `context_field` came from

A `context_field` record stores its own context beside its ciphertext. An
EQL value does this. Its `i` field names the table and column that the value
was written to, such as `users.email`. Decryption reads the context from that
field.

The ciphertext is tied to the context it stores. If someone changes only
the stored context, decryption fails. But the context does not say where
the record should be. If someone copies the whole record, ciphertext and
stored context together, from `users.email` into the `admins.email` column,
it still decrypts there.

So when you know where a record should have come from, say so:

```rust,ignore
// The record stores its column in `#[stash(context_field)] identifier:
// &'static str`. This value was read from the `admins.email` column.
let email = Protected::<String>::decrypt_from_with_context(
    stored,
    &cipher,
    nonempty!("admins.email"),
)
.await?;
```

This refuses a record that stores any other context, with
`Error::ContextMismatch`, before any key is requested.

`decrypt_from(stored, &cipher)`, with no context, does not make this check.
It decrypts under whatever context the record stores. Use it only when you
do not know the expected context, or have checked it another way.

### Fields of a `struct` record

Each field of a `struct` record has its own context, `("users", "<field>")`.
The record's name, `users`, is the first scope. The field's name is the
next.

A caller cannot add to it: `encrypt_into_with_context` does not compile for
a `struct` record. A part that the caller supplies, such as a tenant scope
or a row binding, must be declared on the record. The attributes that
declare one are not built yet.

When the record is a field of another record, the outer field's context
extends each of its fields' contexts. So the field's target must accept a
context from the record. These targets accept one:

- `Ciphertext`, whose input is `OptionalContext`.
- A term, or an `Encrypted<Terms>`, whose input is
  `RequiredContext<CallerContext>`.
- `StackCipherText`, whose input is `RequiredContext<AeadContext>`.
- A `plaintext` record.
- Another `struct` record. The outer field's context then extends the
  inner record's own contexts.

Two kinds of target are a compile error at the field. One kind builds its
whole context itself (`NoCallerContext`). The other requires a context of
another type, such as `RequiredContext<u64>`.

The record must name every field of its plaintext, as a sealed field or a
passthrough field. The owned conversion moves the fields out of the
plaintext struct, and a field it did not name would be dropped without
being wiped. So a field that is left out is a compile error at the
`struct = ..` path ("pattern does not mention field").

### Passthrough fields

Most database rows encrypt only some of their columns. A row's `id` and
`created_at` usually stay as they are, so that the database can index,
join, and sort on them. Mark those fields `#[stash(passthrough)]`:

```rust,ignore
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: SearchableEmail,
    #[stash(passthrough)]
    created_at: i64,
}
```

Encryption moves each passthrough field from the plaintext into the record
as it is, and decryption moves it back. It is never copied.

A passthrough field is stored in the clear, like any unencrypted column. It
is not authenticated either. Someone who can write to the database can
change it, and the encrypted fields beside it still decrypt. So:

- Do not decide who may read a row from a passthrough field alone.
- If a value must be readable and also detect changes, it belongs in the
  record's context. A `struct` record cannot take a caller's context yet.

The field's type must implement `Clone`. The owned conversion never clones
it, but the older `EncryptFrom` form of the record does, and plans run that
form.

### Wiping

- The conversion wipes each sealed field before the pending request is
  returned.
- If a field's declaration panics, the sealed fields that are still waiting
  for their own declarations are wiped.
- If the record's declaration panics while it is being built, the whole
  plaintext is wiped.
- On decryption, if a later field is refused, the fields already opened are
  wiped before the error is returned.

#### Decrypt into a `Protected`

The plaintext type itself cannot wipe on drop. The derive moves the fields
out of the plaintext struct. Rust does not allow that for a type that
implements `Drop`, so the type cannot derive `ZeroizeOnDrop`.

So decrypt straight into a `Protected`. It wipes the plaintext when it is
dropped:

```rust,ignore
let user = Protected::<User>::decrypt_from(record, &cipher).await?;
let rows = Vec::<Protected<User>>::decrypt_from(records, &cipher).await?;
```

The derive implements `DecryptSource<Protected<User>>` for every plaintext
type the record names. Keep the value in its `Protected`, and take the
plaintext out only at the one place that needs it. `User::decrypt_from` still works, but it returns a bare
`User` that the caller must wipe.

#### Traits on the plaintext type

| Instead of | Derive | Why |
|---|---|---|
| `Debug` | `OpaqueDebug`, from `vitaminc::protected` | It prints the field names, with each value hidden |
| `PartialEq` | `TimingSafeEq`, from `vitaminc::protected` | It compares in constant time |
| `Clone` | Nothing | Each clone is another copy to wipe |

### Fields of a `plaintext` record

Every field of a `plaintext` record is given the one context the record
requires. So a term field in a record with `context_type = AeadContext` is a
compile error at the term, because a term needs a `CallerContext`. A call
that leaves out a required context is a compile error at the call
(`AllowsNoContext`), even if the context type implements `Default`.

### The structural traits

Each owned derive also implements the structural traits:

- `EncryptTarget` also implements `EncryptFrom` and `Decryptable`.
  `EncryptFrom` converts the record's structural context into the owned
  input. The structural context is a `DeclaredContext`, a `CallerContext`,
  or a `NonEmpty<C>`.
- `DecryptSource` also implements `DecryptInto` and `DecryptField`.

So an owned record can be a field of a `#[derive(EncryptFrom)]` record, or a
typed field of a plan (`encrypt_into::<Record, _>`), with no second derive.
A hand-written owned target that will be a record field must implement
`Decryptable` and `DecryptField`, as well as `DecryptSource`.

### Example

```rust
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{Ciphertext, Controlled, DecryptFrom, EncryptInto, Protected, StackCipher};

// The plaintext derives `Zeroize`. It derives no `Debug`, `Clone` or
// `PartialEq`.
#[derive(zeroize::Zeroize)]
struct User { id: u64, name: String, email: String }

/// An email address you can search for: its ciphertext and an equality
/// term, under the one context that the record field supplies.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct SearchableEmail { ciphertext: Ciphertext, equality: EqualityTerm }

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct SearchableUser {
    // Not encrypted and not authenticated.
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,        // sealed under ("users", "name")
    email: SearchableEmail,  // derived under ("users", "email")
}

# tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
// With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
// the environment, or from the profile that `npx stash auth login` writes.
let cipher = StackCipher::builder()
#     .kms(stack_encrypt::kms::FakeDataKeySource::new())
    .init()
    .await?;
let keyset = cipher.default_keyset();
let users = vec![
    User { id: 42, name: "Alice".into(), email: "alice@example.com".into() },
    User { id: 43, name: "Bob".into(), email: "bob@example.com".into() },
];
// One batched key request seals the four sealed fields of both rows.
let rows: Vec<SearchableUser> = users.encrypt_into(&keyset).await?;

// A query term is the same derivation, under the same context.
let wanted: EqualityTerm = String::from("alice@example.com")
    .encrypt_into_with_context(&keyset, stack_encrypt::nonempty!("users").with("email"))
    .await?;
let matched: Vec<SearchableUser> = rows.into_iter().filter(|r| r.email.equality == wanted).collect();

// Each decrypted user is wiped when its `Protected` is dropped.
let opened = Vec::<Protected<User>>::decrypt_from(matched, &cipher).await?;
assert_eq!(opened.len(), 1);
# assert_eq!(opened[0].risky_ref().id, 42);
# Ok::<(), stack_encrypt::Error>(())
# }).unwrap();
```

## Which context a record takes

A `CallerContext` contains two encodings of the context. A ciphertext is
sealed under the AEAD encoding. A search term is derived under the PRF
encoding. So a `CallerContext` can only be built from a type that has both,
`IntoAad` and `IntoPrfContext`.

A record made only of ciphertexts needs the AEAD encoding alone. Declare it
with `#[stash(context_type = AeadContext)]`. The record then accepts any
context that `StackCipherText` accepts, including a type that implements
only `IntoAad`:

```rust,no_run
use stack_encrypt::{EncryptInto, NonEmpty, StackCipherText};
use stack_encrypt::target::{AeadContext, DecryptSource, EncryptTarget};

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = AeadContext)]
struct SealedName {
    c: StackCipherText,
}

# async fn example<K: stack_encrypt::kms::DataKeySource + stack_encrypt::kms::IndexKeySource + Sync + 'static>(keyset: stack_encrypt::KeysetCipher<'_, K>, name: String, tenant: &str) -> Result<(), Box<dyn std::error::Error>> {
let record: SealedName = name.encrypt_into_with_context(&keyset, NonEmpty::new(tenant)?).await?;
# Ok(())
# }
```

The derive cannot choose this for you, because it sees only the names of
the field types. The type you name must convert into the context of every
field. An `AeadContext` does not convert into a `CallerContext`, so a search
term beside it is a compile error at the record. That is intended.

A record with a `context_field`, or a `struct` record, decides its own
context. It refuses `context_type`.

A hand-written target implements the same methods that the derives write:
`EncryptTarget::encryption` and `DecryptSource::decryption`. Neither method
is given the plaintext together with a cipher.

Every attribute except `plaintext` may be given once. Repeating one is a
compile error. You can repeat `plaintext`. You can list each type only
once.

## Structs, field by field

A `struct = ..` record needs no attribute on its fields. With
`#[stash(struct = User, scope = "users")]`:

- the field `age` is derived from `user.age`, under the context
  `("users", "age")`;
- the field `email` is derived from `user.email`, under
  `("users", "email")`.

Each context has two parts: the record's `scope`, then the name of the
plaintext field. ZeroKMS logs it as the descriptor `users/age`. The same
context at a call site is `nonempty!("users").with("age")`.

Both parts must be plain descriptor segments, so that the ZeroKMS log names
the column. A plain segment has none of these:

- a `/`, `(` or `)`;
- a control or invisible character;
- a start of `b64:`, a digit, or `-`.

So the derive refuses a scope such as `"public/users"`. Write `"users"`.

A tuple field's name is its index, and an index starts with a digit. So a tuple
field must name its segment with `identity = ".."`.

Both parts name the stored data, not the encrypted struct. With
`#[stash(from = email_address)] email: ..`, the field is derived under
`("users", "email_address")`. Nothing is made plural or guessed.

`#[stash(identity = "nickname")] name: ..` replaces the second part only.
The field is derived under `("users", "nickname")`.

Each plaintext field has exactly one output, with its own segment. A
ciphertext with search terms beside it is one field of type
`Encrypted<Terms>`, such as `email: Encrypted<(EqualityTerm, MatchTerms)>`.
It is not a ciphertext field and term fields `from` the same plaintext
field.

A field whose type is another `struct` record is an ordinary field. It is
given its own context, and that context extends the contexts of the inner
record's fields.

A `struct = ..` record takes no context from the caller. A `plaintext = ..`
record and a record with a `context_field` do take one. See [The context a
call takes](#the-context-a-call-takes). A plan that contains a `struct = ..`
record can still extend each field's context. Under a plan extension `7u64`, the `age` field
is derived under `(("users", "age"), 7u64)`.

### Why the scope is required

The context is part of the stored data's identity. It is the associated
data of every ciphertext in the column, and the domain of every search
term. So the derive never takes the scope from the Rust type's name:

- Two types with the same name in different modules would share every
  context. Equal plaintexts would give equal search terms in both tables.
  A ciphertext could be moved from one table to the other.
- Renaming the type would change the context of everything stored.

### Renaming a plaintext field

The second part of each context is the plaintext field's name. So renaming
a plaintext field changes that field's context, and stored data no longer
decrypts. Nothing warns you when it compiles. ZeroKMS refuses the key
request under the changed descriptor, with `Error::Kms`. A key source that
ignores descriptors, such as the fake one in tests, fails at the AEAD with
`Error::Aead` instead.

Before you rename a field, pin its old name with
`#[stash(identity = "old_name")]`. The field keeps the context
`("<scope>", "old_name")`.

`from` and `identity` work only with `struct`. A `struct` record has no
field derived from the whole plaintext. A `plaintext` record has no field
derived from a part of it. So you cannot give both `struct` and
`plaintext`.

## Which field decryption opens

Usually the field types decide it. Each field type says whether it is a
ciphertext or a one-way search term (`Decryptable`). The derive requires
exactly one ciphertext:

- among all the fields of a `plaintext` record;
- among the fields derived from each plaintext field, in a `struct` record.

Too few or too many is a compile error at the record's definition. For a
generic record, the error is at its first use.

A derived record is itself `Decryptable` if any of its fields is, so a
record can be a field of another record. A type of your own implements
`Decryptable` and `DecryptField` by hand.

Mark a field `decrypt` when the types do not decide it:

- the record has two ciphertexts, of which decryption opens one;
- a field's type is not `Decryptable`.

Once any field is marked, only the marked fields count. One marked field is
opened as the whole plaintext. Several marked fields, each with
`from = ..`, rebuild the plaintext field by field. The record's own
`Decryptable` impl is then `true`, so a marked record can still be a field
of another record.

Decryption consumes the record, and moves each opened field out of it. So
the record type must not implement `Drop`. That rules out `ZeroizeOnDrop`.
Wrap the fields that need wiping instead.

A search term opens nothing, so decryption ignores the context given to a
term field. The ciphertext field is what is checked, under the context it
was sealed under.
