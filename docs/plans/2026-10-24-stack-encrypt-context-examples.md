# Context scenarios for the Stack Encrypt API

Date: 7 November 2026.

This document lists eight ways a record can get its context, each as a
code example with its use case. Together they are the acceptance matrix
for the work item [Context from fields and from the
caller](2026-10-24-stack-encrypt-api-plan.md#context-from-fields-and-from-the-caller)
in the API plan. The plan's section [Query context and stored
context](2026-10-24-stack-encrypt-api-plan.md#query-context-and-stored-context)
gives the rules, and its terms table defines every term used here.

In short: every part of a context is a scope or a binding. The query
context is all the scopes. The stored context is the scopes followed by
the bindings. Search terms derive under the query context, and the data
key and the AAD derive under the stored context.

The code below is proposed. None of it compiles on `next` today. The
rules are decided; the attribute spellings, such as `scope(tenant: u64)`,
are illustrative.

## How to read the examples

- `scope(tenant: u64)` declares a scope the caller supplies on every call.
  `bind(row: Uuid)` declares a binding the caller supplies.
- `scope(field = "tenant")` declares a scope stored in the row, in the
  passthrough field `tenant`. `bind(field = "id")` declares a stored
  binding in the same way.
- A caller passes its parts as `Scope::new(..)`, `Bind::new(..)`, or
  `Scope::new(..).bind(..)`. A query accepts a `Scope` only.
- `SearchableEmail` is the target type from the plan's [record
  example](2026-10-24-stack-encrypt-api-plan.md#encrypt-a-record): a
  ciphertext and an equality term.
- A stored part is read from the plaintext on encrypt. On decrypt, the
  reader takes it from the row. If the reader passes it as well, Stack
  Encrypt checks it against the row before it fetches any key.

## 1. A static context only

The record's own name and each field's name make up the whole context.
Nothing comes from the caller or the row. This is the default for a
record that has no tenant and no row binding, such as a settings table.

```rust
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Settings, context = "settings")]
struct EncryptedSettings {
    theme: Ciphertext,
}

let encrypted: EncryptedSettings = settings.encrypt_into(&keyset).await?;
let settings = Settings::decrypt_from(encrypted, &keyset).await?;
```

## 2. A scope the caller supplies and does not store

The caller knows the tenant from the request, and passes it on every
write, query, and read. Nothing about the tenant is stored with the row.
A query for one tenant matches only that tenant's rows.

```rust
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users", scope(tenant: u64))]
struct EncryptedUser {
    email: SearchableEmail,
}

let encrypted: EncryptedUser = user
    .encrypt_into_with_context(&keyset, Scope::new(tenant))
    .await?;
let user = User::decrypt_from_with_context(encrypted, &keyset, Scope::new(tenant)).await?;

let by_email = EncryptedUser::EMAIL
    .eq("alice@example.com")
    .scope(tenant)
    .encrypt(&keyset)
    .await?;
```

## 3. A scope taken from the plaintext and stored in the row

The tenant is a field of the plaintext, and the record stores it in the
clear. The declaration marks that field as the stored copy, so encrypt
reads it from the plaintext. A reader takes the tenant from the row, so a
batch job can decrypt rows from many tenants without knowing each one
first. A reader that serves one
tenant passes it as well, to check that the row belongs to that tenant.

```rust
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users", scope(field = "tenant"))]
struct EncryptedUser {
    #[stash(passthrough)]
    tenant: u64,
    email: SearchableEmail,
}

let encrypted: EncryptedUser = user.encrypt_into(&keyset).await?;   // tenant comes from `user.tenant`

let user = User::decrypt_from(encrypted, &keyset).await?;           // tenant comes from the row
let user = User::decrypt_from_with_context(encrypted, &keyset, Scope::new(session.tenant)).await?;
```

The second decrypt is refused with `ContextMismatch` if the row's tenant
is not `session.tenant`, before any key is fetched.

## 4. A binding stored in the row

The row's own ID is part of the context, so each ciphertext opens only
in its row. A ciphertext copied into another row fails to open. The ID is
stored in the clear, as any primary key is. A query is not affected,
because a binding is not in the query context.

```rust
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users", bind(field = "id"))]
struct EncryptedUser {
    #[stash(passthrough)]
    id: Uuid,
    email: SearchableEmail,
}

let encrypted: EncryptedUser = user.encrypt_into(&keyset).await?;
let user = User::decrypt_from(encrypted, &keyset).await?;

// A query covers the whole column. It does not take the row ID.
let by_email = EncryptedUser::EMAIL.eq("alice@example.com").encrypt(&keyset).await?;
```

## 5. A stored scope and a stored binding

The tenant and the row ID are both stored in the row. A query for one
tenant matches that tenant's rows, and each ciphertext opens only in its
own row. This ties each decrypted value to the row it came from. The facts of a
row's writing, such as the address it came from, are caveats added by
[tag refinement](2026-11-07-stack-encrypt-tag-refinement.md), not parts
of the context.

```rust
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users", scope(field = "tenant"), bind(field = "id"))]
struct EncryptedUser {
    #[stash(passthrough)]
    tenant: u64,
    #[stash(passthrough)]
    id: Uuid,
    email: SearchableEmail,
}

let encrypted: EncryptedUser = user.encrypt_into(&keyset).await?;
let user = User::decrypt_from(encrypted, &keyset).await?;

// Check both stored parts on decrypt.
let user = User::decrypt_from_with_context(
    encrypted,
    &keyset,
    Scope::new(session.tenant).bind(requested_id),
)
.await?;

let by_email = EncryptedUser::EMAIL
    .eq("alice@example.com")
    .scope(session.tenant)
    .encrypt(&keyset)
    .await?;
```

## 6. A stored part and a caller-supplied part together

The tenant is stored in the row. The row ID comes from the caller on
every call, and is never stored. The row ID is known from elsewhere, such
as the request path. A reader passes the row ID, and may pass the tenant
as well to check it.

```rust
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users", scope(field = "tenant"), bind(row: Uuid))]
struct EncryptedUser {
    #[stash(passthrough)]
    tenant: u64,
    email: SearchableEmail,
}

let encrypted: EncryptedUser = user
    .encrypt_into_with_context(&keyset, Bind::new(row_id))
    .await?;

// The tenant comes from the row. The row ID must be passed.
let user = User::decrypt_from_with_context(encrypted, &keyset, Bind::new(row_id)).await?;

// Passing the tenant as well checks it against the row.
let user = User::decrypt_from_with_context(
    encrypted,
    &keyset,
    Scope::new(session.tenant).bind(row_id),
)
.await?;
```

## 7. A scope the caller supplies on every call and never stores

The scope is a value that exists only where the data may be used, such as
a host or application ID. The record is fully stored, but part of its
context is not. So the data opens only on a host that has the value. A
row copied to another host fails to open, and a query from another host
matches nothing.

```rust
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Secret, context = "secrets", scope(host: String))]
struct EncryptedSecret {
    value: Ciphertext,
}

let host = host_id()?;
let encrypted: EncryptedSecret = secret
    .encrypt_into_with_context(&keyset, Scope::new(&host))
    .await?;
let secret = Secret::decrypt_from_with_context(encrypted, &keyset, Scope::new(&host)).await?;
```

## 8. An EQL type, with its column as the context

An EQL type such as `TextEq` is one column's value, stored in a
PostgreSQL column of type `public.eql_v4_text_eq`. Its context is the
table and column, as an `Identifier`. The type stores the identifier in
its `i` field, so a reader takes it from the stored value. A reader that
knows which column it is reading passes the identifier as well. If the
stored identifier differs, the value is refused before any key is
fetched.

Inside a record, the derive supplies the identifier from the record's
name and the field's context name, so none of this is written by hand.

```rust
use eql_bindings::{v4::text::{TextEq, TextEqQuery}, Identifier};

let column = Identifier::for_column("users", "email")?;

// Encrypt one value for the column. The identifier is the context, and
// `TextEq` stores it in `i`.
let stored: TextEq = "alice@example.com"
    .encrypt_into_with_context(&keyset, Scope::new(&column))
    .await?;

// Decrypt, taking the column from the stored value.
let email = String::decrypt_from(stored, &keyset).await?;

// Decrypt, checking that the stored column is the one expected. A value
// from `users.name` is refused with `ContextMismatch` before any key
// is fetched.
let email = String::decrypt_from_with_context(stored, &keyset, Scope::new(&column)).await?;

// A query for the column uses the same context, so its term matches.
let query: TextEqQuery = "alice@example.com"
    .encrypt_into_with_context(&keyset, Scope::new(&column))
    .await?;
```
