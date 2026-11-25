---
status: accepted
date: 2026-11-23
extends: ADR-0004
amends: ADR-0004, ADR-0006, ADR-0010
---

# A context is a field path and named parts: policies, labels and partitions

## Summary

This ADR decides what the parts of a context are, what each kind protects,
and how a part is added to a value after it is encrypted. It replaces the
scopes and bindings of ADR-0004's amendment of 2026-11-10.

- A context is a **field path** and a list of **named parts**. Every part
  has one wire name, the same in every SDK.
- A part type is a **policy**, a **label**, a **partition**, or more than
  one of these. Only a policy restricts who can read a value.
- `Policy` is a sealed trait. Only the key provider's own types implement
  it. `Label` and `Partition` are open.
- At encryption, the field path, the partitions and the labels go into key
  derivation, in a fixed order. A policy goes to the key provider with the
  key request.
- A **refinement** adds a label or a policy to a value that is already
  stored. It changes the key tag and encrypts nothing again.
- Every entry point takes named parts. The untyped `Scope` and `Bind` are
  removed, and `Describe` is removed.
- Only a value whose whole context is a field path keeps its stored bytes.

## The problem

ADR-0004's amendment of 2026-11-10 sorts each part of a context by one
question: is the part in the query context? A scope is. A binding is not.
That rule is right, and it stays. Four problems remain.

1. **The rule does not say who can read a value.** A binding whose value is
   stored in the row restricts no reader: anyone who reads the row has the
   value. A tenant ID that a caller supplies is not a secret. The words
   "scope" and "binding" read as isolation and access control, and neither
   is.
2. **A part has no name.** Only the values and their order are in a
   derivation. So `7` as a tenant and `7` as a region are one context. A
   key provider cannot tell the parts of a request apart, and a part cannot
   be recorded beside a stored value.
3. **Anything can be a context.** Every entry point accepts any
   `IntoContext`, and `Describe` is open. Nothing stops a developer from
   treating a value as access control when it is not.
4. **A fact cannot be added to a stored value.** A row ID that exists only
   after the insert, or a time limit decided later, means encrypting the
   value again.

## Decision

### 1. Three kinds of part

| Kind | What it means | Restricts readers |
|---|---|---|
| **Policy** | The wrong reader cannot get the value accepted, so the key provider returns no key. The key provider supplies or checks the value itself: a claim from the reader's token, or a time tested against its own clock. | Yes |
| **Label** | A value that is safe to show. It is sent to the key provider in the clear with every key retrieval, and logged there. It is usually stored with the data, in the payload or in a plaintext column. A caller may supply it on every call instead. | No |
| **Partition** | A value that splits data into groups. It is in the context of the ciphertext and of its search terms. A ciphertext from one partition does not decrypt under another, and equality terms from two partitions never match. | No |

A type can be more than one kind. A policy whose value is stored, such as a
time limit, is also a label. A tenant ID is a label and a partition.

A partition restricts no reader. It keeps one group's ciphertexts and
search terms apart from another's, and that is all. Order and match terms
from two partitions still compare, and give a wrong answer.

A label can never act as a policy. A reader can pass a label to check that
a value is the one written for a row or a column, and a mismatch is refused
before any key is requested. That check stops a service from being tricked
into decrypting a value written for another record. It restricts no reader.

### 2. The traits, and what is sealed

```rust
/// One part of a context: a wire name and a typed value.
pub trait ContextPart: IntoContext { const NAME: &'static str; }

/// The wrong reader cannot get the value accepted.
/// Sealed: only a key provider's types implement it.
pub trait Policy: ContextPart + sealed::Sealed {}
/// The value is safe to show. Open.
pub trait Label: ContextPart {}
/// Splits the ciphertext and its search terms into groups. Open.
pub trait Partition: ContextPart {}
/// The key provider checks the value itself, so the value may be stored.
pub trait Checked<P: DataKeySource>: Policy + Label {}
```

`Policy` is sealed, so an application cannot define one. In this version
every policy is checked by the key provider, so every `Policy` is also
`Checked`. The two traits stay separate, so a later version can add a
policy whose value the caller supplies.

`Label` and `Partition` are open. An application, or another crate such as
`eql-bindings`, defines its own for what the built-in parts do not cover,
such as a region. A wrong label or partition restricts nobody, so the
damage is bounded. A wrong policy is a false security claim, and that is
what the seal prevents.

A secret kept in a label or a partition that an application defines works
as it does today. Stack Encrypt makes no claim about it.

All four traits, and the policy types of the ZeroKMS provider, live in
Stack Encrypt. `stack-kms` knows nothing about contexts, and Stack Encrypt
depends on it, not the reverse. A key vendor crate cannot add a policy.

### 3. The built-in parts

| Type | Kinds | Wire name | Where the value comes from |
|---|---|---|---|
| `NotBefore(time)` | Policy, label | `not_before` | Stored with the data. The key provider tests it against its clock. |
| `NotAfter(time)` | Policy, label | `not_after` | Stored with the data. The key provider tests it against its clock. |
| `ForSub` | Policy. A label when stored. | `for_sub` | The `sub` claim of a token. |
| `ForTenant` | Policy, partition | `for_tenant` | A tenant claim in the reader's token. |
| `TenantId<T>` | Label, partition | `tenant_id` | The caller, from the session or from a tenant column. |
| `RecordId<T>` | Label | `record_id` | The row, or a refinement that adds it later. |
| `Note<T>` | Label | `note` | The caller. A general-purpose label. |

`TenantId` and `RecordId` are generic over the value's type, so a UUID
tenant or a bigint row ID needs no new type.

A built-in wire name is reserved. A custom label or partition that takes
one is refused: at compile time in a derive, and at load in a dynamic
plan. The key provider acts on the names it knows.

`ForSub` takes the writer's own `sub` from the token, unless the writer
names another user. A writer who names another user cannot read the value
back. That is write-only encryption, and it needs no permission: the
writer only gives up their own access.

`TenantId` is not access control. A tenant ID is not a secret, and the
client holds the index key, so it can make search terms for any tenant.
`ForTenant` is the strong form: the key provider checks the claim and
separates the index key by it.

### 4. The field path

A field path is the declared names a value is stored under: a record's
scope and a field's name, or a table and a column. It is a label and a
partition. It is never a policy.

- The struct `stack_encrypt::Label` is renamed `FieldPath`, and the name
  `Label` goes to the trait. `FieldPath` is a path built from plain
  segments. This is the type #1663 asks for. `IntoLabel`, and parsing a
  path from text, are removed as that issue says.
- EQL's `Identifier`, the table and column stored in `i`, implements
  `Label` and `Partition` in `eql-bindings`. It keeps `ContextFromField`,
  which is how a record hands an EQL field its declared pair.
- `Describe` is removed. Nothing takes it as a bound, and a part already
  carries what it provided. `Descriptor::from_piece` stays the only
  renderer, so the safety rule of ADR-0006 holds.
- `context_from` (ADR-0004, amended 2026-11-09) is unchanged. It reads a
  field path from the plaintext.

### 5. Where a part goes at encryption

The stored context of a value is, in this order:

1. the field path;
2. the partitions, sorted by wire name;
3. the labels, sorted by wire name.

A part that is both a partition and a label, such as `TenantId`, goes with
the partitions.

The data key and the AAD derive under the stored context. The query
context is the field path and the partitions, so it is a prefix of the
stored context. Search terms derive under it.

Each part enters a derivation as its wire name and its value. So
`tenant_id = 7` and `region = 7` are different contexts, and a part that
is renamed is a different context.

Each wire name is used at most once in a value's context at encryption. A
second part with the same name is refused.

The order is fixed, and it is not the order of the declaration. Reordering
the fields of a Go struct must not change a context, and a Rust and a Go
declaration of one table must not have to list their parts alike.

A policy that is present at encryption goes to the key provider with the
key request. It is not in the stored context, unless it is also a label: a
stored policy, such as `NotAfter`, enters the derivation as a label and
goes to the key provider as a policy. How a key provider enforces a policy
is the provider's concern.

A value has one of two forms:

- A value with no parts keeps the form the release candidates write, byte
  for byte.
- A value with any part uses a new form. Its parts go to the key provider
  as named key request items (#1566), so the 512-byte limit on a
  descriptor applies to the field path alone.

### 6. Refinements

A refinement adds a part to a value that is already stored. It changes the
key tag, not the input to the tag, so nothing is encrypted again. The new
tag replaces the stored one. A part that is present at encryption is not a
refinement.

- **A label refinement is local.** The new tag is an HMAC of the name and
  the value, keyed by the current tag. It needs no call to the key
  provider, so a database trigger can add `RecordId` once the primary key
  exists.
- **A policy refinement is a call to the key provider.** It is not a
  decryption: no data key leaves the provider. The step is keyed by a
  value that only the provider holds. Examples are adding `NotAfter` to a
  value that had none, and locking a value to one user with `ForSub` after
  it is assigned.
- **A refinement is never a partition.** Search terms are made at
  encryption, and a refinement does not change them.
- **The steps are stored in order**, each as a name and a value, because
  the provider replays the chain. A `ForSub` step may store its name
  alone, and the provider takes the value from the reader's token. A
  refinement may repeat a wire name, because the chain keeps its own
  order.

A label refinement is only as strong as write access to the row. Someone
who holds an older tag can drop a later label, or copy the value to
another row and add that row's `RecordId`. A label that must resist this
is set at encryption, where it is in the derivation. This limit fits what
a label refinement is for: a refiner that cannot read the value, such as
a database that refines what an application writes.

### 7. Entry points take named parts

- **A record lists its parts by type**:
  `context(TenantId<u64>, RecordId<Uuid>, ForSub)`. The untyped
  `Scope::new(..)` and `Bind::new(..)`, and the `scope(..)` and `bind(..)`
  forms of a declaration, are removed.
- **A query takes partitions only.** The query method `.scope(..)` becomes
  `.partition(..)`, and it accepts a `Partition` and nothing else.
- **`refine` takes a label or a policy.** A partition does not compile.
- **The simple path is unchanged for a value with no context.**
  `encrypt_with_context` and `decrypt_with_context` accept named parts.
  They also accept a bare value, such as a string, which is a `Note`. A
  bare value is accepted on this path only. It can only become a label, so
  it cannot be mistaken for a policy or a partition.
- **`contexts()` prints the kinds of each part**, so a test can state them.
- **A `Checked<P>` part does not compile** with a keyset whose provider is
  not `P`. A value passed at encryption for a policy that the provider
  takes only from the token, such as `ForTenant`, does not compile either.

```rust
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Note, scope = "notes", context(TenantId<u64>, RecordId<Uuid>, ForSub))]
struct EncryptedNote {
    #[stash(passthrough)]
    id: RecordId<Uuid>,     // the label's stored copy
    title: TextEq,
}

let stored: EncryptedNote = note
    .encrypt_into_with_context(&keyset, TenantId(42))
    .await?;
let term = EncryptedNote::TITLE.eq("Renewal").partition(TenantId(42)).encrypt(&keyset).await?;
let note = Note::decrypt_from_with_context(stored, &keyset, TenantId(42)).await?;
```

### 8. Nested records

A record is read as a relation. A record nested in another, with a scope
of its own, is a second relation.

- The leaves of the inner record do not take the outer record's names into
  their context. A leaf's field path is the inner record's scope and the
  field's name, which is what an EQL leaf already stores in `i`. So two
  values with the same `i` have the same field path.
- The leaves of the inner record do take the outer record's parts, such as
  its tenant and its record ID. `RecordId` is what tells two fields of one
  inner type apart.
- A wire name declared at two levels is refused.
- A nested record with no scope of its own is a composite attribute. Its
  leaves are named by a dotted path under the outer record.

### 9. Go

Go declares the same parts with struct tags, and supplies their values
through the cipher.

```go
type Note struct {
    _      struct{}  `stash:"context=notes,policy=for_sub"`
    ID     uuid.UUID `stash:"id,label=record_id"`
    Tenant int64     `stash:"tenant,partition=tenant_id"`
    Title  string    `stash:"title,encrypt_into=TextEq"`
}

c := cipher.With(encrypt.TenantID(42))
```

- **Tags.** `label=`, `partition=` and `policy=` each take a wire name. On
  a field, the value is read from that field and stored in the clear. On
  the `_` field, the caller supplies the value through the cipher, or the
  key provider takes it from the token. `stashgen` refuses a word that
  does not match a built-in name, and a reserved name used for something
  else.
- **Interfaces.** `Label` and `Partition` are open interfaces. `Policy` is
  sealed by an unexported method, so only the `encrypt` package implements
  it. The built-in parts are constructor functions, such as
  `encrypt.TenantID(v)` and `encrypt.NotAfter(t)`.
- **One method on the cipher.** `Cipher.With(parts ...)` replaces
  `Cipher.Scope` and `Cipher.Bind`. A part's type decides whether it
  enters a query. A query through a cipher that carries a label is
  refused, as a query with a binding is today.
- **The plan.** The `Extension` list and the `bind` key become one `parts`
  list. Each entry has its wire name, its value and a partition flag.
- **`context_field` is removed.** A tenant read from a row is a `TenantID`
  declared on that field.
- **`encrypt/policy` becomes `encrypt/rules`** before Go 0.1.0. That
  package holds the generate-time rules for types that cannot carry tags.
  The old import path stays as a deprecated alias until 0.1.0, so "policy"
  means one thing in every SDK.

### 10. What every SDK takes from this record

- The three words: policy, label and partition.
- The wire names of the built-in parts, and the rule that a custom part
  cannot take one.
- `.partition(..)` as the word for narrowing a query.
- A bare value on the simple path is a `Note`.
- A part read from a field of a record, in place of a context field.

Each SDK settles its own form in its plan document. Go is specified here
because it is the only SDK released.

### 11. What Stack Encrypt requires of a key provider

- It accepts a value's parts as named key request items.
- It enforces every policy it is sent, and refuses a key when one fails.
- For `ForTenant`, it separates the index key by the tenant claim.
- For a policy refinement, it returns a step that only it can produce, and
  it refuses a chain that has been rolled back to an earlier state.

Who may refine a value, and what the provider's own keys are scoped to,
are the provider's decisions.

A key vendor backend has no service to check a policy. Partitions and
labels work there, because key derivation enforces them. A `Checked` type
does not compile, and a policy refinement does not exist.

## Considered options

- **Keep scopes and bindings, and document them better.** Rejected. The
  words say isolation and access control, and a stored binding is neither.
  A part would still have no name.
- **Seal all three traits.** Rejected. `Identifier` lives in another crate
  and has to be a label and a partition. A sealed `TenantId<T>` can hold
  any value anyway, so the seal bought little outside `Policy`.
- **Keep an open route for an untyped context.** Rejected. Any open route
  lets a caller build a context the model does not name. The one exception
  is a bare value on the simple path, which can only be a label.
- **Make every part a step in the tag chain, including a part present at
  encryption.** Rejected. A label that is known at encryption belongs in
  key derivation. The chain is for what is added afterwards.
- **Keep the order of the declaration.** Rejected. See decision 5.
- **A keyset for each tenant.** Not used. Keysets stay as they are, and
  tenancy is a partition. Removing keysets is a separate decision.

## Consequences

- **Stored bytes.** Only a value whose whole context is a field path keeps
  its bytes. That covers every EQL value written with an identifier alone.
  A value written through an untyped scope or binding, through Go's
  `context_field`, or as a leaf of a nested record with its own scope, is
  not kept readable or matching. Search terms carry no version, so the old
  terms and the new terms cannot both match a query.
- **Renaming a part is a migration.** The wire name is in the derivation.
- **The words change everywhere.** The glossary entries for "scope" and
  "binding" in `CONTEXT.md` are replaced when the code changes. The
  language integration guide's context contract follows.
- **Issues this record answers or changes.** #1663 takes `FieldPath` as
  its type. #1566 sends named parts. #1567 becomes refinements. #1683 is
  rewritten or closed: `ForSub`, `ForTenant` and `Checked<P>` replace
  `bind(claim = ..)`, a custom claim and `ResolvesClaims`. #1572 is
  rewritten or closed, because its use case is a keyset for each tenant.
- **Not decided here.** The name of a policy whose value the caller
  supplies, for a later version. A label that holds data which is not
  safe to show. Whether keysets are removed.
