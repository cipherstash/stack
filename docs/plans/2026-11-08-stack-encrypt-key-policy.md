# Binds, claims, and labels: key policy in Stack Encrypt

Date: 8 November 2026. Written from a design discussion with Dan on that
day. The ZeroKMS behaviour described here was read from the Vitur server
code in `cipherstash-suite` at commit `f63c85d5f`.

A stored value can be tied to facts about it in three ways. A **bind**
ties the data key to a fact the client knows, such as a tenant or a row
ID. A **claim** ties the data key to a fact the key provider resolves,
such as the `sub` of the caller's token.

A **label** records a fact on
the key tag, verified by the key provider, without restricting who can
read. Binds and claims are access control. Labels are not.

This document
gives the design of all three, the rules that keep them apart, and what
ZeroKMS must do.

The [API plan](2026-10-24-stack-encrypt-api-plan.md) lists the work. Its
[Query context and stored
context](2026-10-24-stack-encrypt-api-plan.md#query-context-and-stored-context)
section gives the context model that binds and claims extend. None of
the code below is on `next` today.

## Contents

- [Terms](#terms)
- [How ZeroKMS works today](#how-zerokms-works-today)
- [Three mechanisms, and when to use each](#three-mechanisms-and-when-to-use-each)
  - [Guards for the developer](#guards-for-the-developer)
- [Binds move from the descriptor to key context items](#binds-move-from-the-descriptor-to-key-context-items)
  - [A new envelope version](#a-new-envelope-version)
- [Claims](#claims)
  - [Declaring a claim](#declaring-a-claim)
  - [Which token](#which-token)
  - [Other provider facts](#other-provider-facts)
- [Labels](#labels)
  - [How it works](#how-it-works)
  - [Rules for labels](#rules-for-labels)
  - [ZeroKMS can write a label](#zerokms-can-write-a-label)
  - [Labelling in Rust and SQL](#labelling-in-rust-and-sql)
  - [Go, and labelling many values](#go-and-labelling-many-values)
  - [The labels list in the payload](#the-labels-list-in-the-payload)
  - [Example: access intelligence for a notes table](#example-access-intelligence-for-a-notes-table)
- [What ZeroKMS must do](#what-zerokms-must-do)
- [Open questions](#open-questions)

## Terms

| Term | Meaning |
| --- | --- |
| Bind | A part of the stored context whose value the client knows. The data key and the AAD derive under it. A reader must present the same value |
| Claim | A bind whose value the key provider resolves from the caller's verified token, such as `sub`. The client names it and never sees the value |
| Label | A named, typed fact added to a stored value's key tag after encryption. ZeroKMS verifies it when it returns the key, and logs it. It restricts nothing |
| Descriptor | The string a key request names its key under. ZeroKMS derives the data key from it. Today Stack Encrypt renders the whole stored context into it |
| Key context | The list of items a key request sends to the provider beside the descriptor: each scope, binding, and claim as one item. The provider folds the items into the key tag. The ZeroKMS protocol's field for this list is still named `context`, and its older name was lock context; ZeroKMS version 2 drops that name |
| Key tag | The HMAC ZeroKMS returns with a data key. A reader must present it to get the key again. Stack Encrypt binds it into every leaf's AAD |
| PAE | Pre-authentication encoding: a length-prefixed encoding of several values, so that two values cannot run into each other |

## How ZeroKMS works today

These facts were verified in the Vitur server, in
`packages/vitur-server-core/src`:

- **The data key is derived from the IV, the descriptor, and the
  keyset's authority key.** Nothing else goes in. The descriptor is
  padded to a 512-byte block. That block is the source of the
  descriptor size limit (`client.rs`, `generate_key_material`).
- **The key tag is an HMAC over the IV, the descriptor, and each lock
  context item in order.** An identity claim goes in as its name and
  the value ZeroKMS resolved from the caller's token (`tag_key.rs`,
  `create_tag`).
- **On retrieve, ZeroKMS resolves the items again from the reader's
  token, recomputes the tag, and compares it in constant time.** A
  mismatch is refused before any key material is derived. A match
  returns the key, derived from the descriptor alone
  (`key_retrieval.rs`, `verify_and_retrieve_key`).
- **A second tag version carries a decryption policy** with OR
  semantics over claims. It is the earlier policy-engine design. This
  plan retires it.

So a key context item is enforced by a check. The descriptor is
enforced by derivation. If ZeroKMS skipped the check, a key context item
would not stop decryption, because the key does not depend on it. A
descriptor part cannot be skipped, because the key is derived from it.

## Three mechanisms, and when to use each

| | Bind | Claim | Label |
| --- | --- | --- | --- |
| Who supplies the value | The client, from the caller or the row | ZeroKMS, from the caller's token | The client, a trigger, or ZeroKMS |
| Who sets the rule | The client, at write time | The client, at write time | ZeroKMS policy, at any time |
| Can the rule change later | No. Lose the value, lose the data | No. Lose the claim, lose the data | Yes. A policy can be added, changed, or removed |
| Can the rule be overridden | No | No | Yes, by changing the policy |
| Affects search terms | A scope does. A binding does not | No | No |
| Good for | Tenant isolation, a value that must stay in its row | Per-user secrets that no one else may read | Access intelligence, and any rule an operator may need to change |

A bind and a claim are the same mechanism with a different source of the
value. Both are strict by construction. A label is a record, and ZeroKMS
may later apply a policy to it. The two routes reach the same outcome
with different threat models and trade-offs. So the API must keep a
developer from choosing the strict one by accident.

### Guards for the developer

1. **A claim is declared on the type, never added on one call.**
   `bind(claim = sub)` in a declaration is visible in code review and in
   `contexts()`. A per-call claim would let one code path make a row
   unreadable to everyone else without anyone noticing. Binds of values
   the caller knows may still be added per call, because the caller
   already has the value.
2. **Every bind's documentation says the same sentence.** A value bound
   to this part cannot be read without it, by anyone, ever, including a
   migration. For a claim it adds: deleting the user deletes access to
   the data.
3. **A label is the default suggestion for identity facts.** Where the
   documentation shows `sub`, it shows it as a label first, written by
   ZeroKMS at generate time. The claim is the stricter option, with its
   cost spelled out.

## Binds move from the descriptor to key context items

Today Stack Encrypt renders the whole stored context into the descriptor
string, frozen, and sends an empty key context. Decided on 8 November
2026: new values send the context's parts as key context items instead.
Each scope and binding becomes a name-and-value item. The descriptor
shrinks to the context name, such as the table and column.

This removes the 512-byte limit on a context, and it gives ZeroKMS the
parts as structure instead of one string it logs and cannot parse.

### A new envelope version

A key generated under a descriptor must be retrieved under the same
descriptor. So this is a stored-format change, under the plan's
[stored-format
rule](2026-10-24-stack-encrypt-api-plan.md#the-stored-format-stays-compatible-with-go-rc3).
The `SealedValue` envelope begins with a format version byte, `0x01`
today, and binds it into the leaf AAD. The new form is version `0x02`.

On decrypt, the engine reads the byte and sends the request in the form
the value was written with. Version 1 renders the descriptor as rc.3
did. Version 2 sends the context name and the items. Go rc.3 data stays
readable without re-encryption. The rc.3 rendering code stays until the
last version 1 value is gone.

Two things the move changes, for ZeroKMS to know:

- Under version 2, a context part is enforced by the tag check, not by
  key derivation. Under version 1 it was both. [What ZeroKMS must
  do](#what-zerokms-must-do) asks version 2 of ZeroKMS to close that gap.
- The ZeroKMS protocol says the items "should never include sensitive
  information". A tenant ID or row ID reaches ZeroKMS as an item instead
  of inside the descriptor, so nothing new is sent. The plan states the
  rule rather than assuming it.

## Claims

A claim is a bind whose value the key provider resolves. The client
names the claim. ZeroKMS reads its value from the token it verified, and
folds the name and the value into the key tag. On read, ZeroKMS resolves
the claim again from the reader's token. A reader with a different value
gets a tag mismatch and no key.

A claim is on the stored-context side of the plan's rule, with the
bindings. The client never sees the value, so no search term can derive
from it. A claim is never a scope.

### Declaring a claim

The claim type belongs to the provider, and a capability trait gates it
at compile time:

```rust
// In the ZeroKMS provider. `Name` is validated, as a keyset name is.
pub enum Claim { Sub, Custom(Name) }

// A provider that can resolve claims. A fake provider, or a future
// provider without verified tokens, does not implement it.
pub trait ResolvesClaims: DataKeySource { type Claim; }
```

```rust
// Declared on the type. The caller cannot leave it out.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Note, context = "notes", bind(claim = sub))]
struct EncryptedNote {
    body: Ciphertext,
}

// Encrypt and decrypt take the keyset as every call does. The engine
// adds the claim item to the key request. Only the same `sub` can read.
let encrypted: EncryptedNote = note.encrypt_into(&keyset).await?;
let note = Note::decrypt_from(encrypted, &keyset).await?;

// A client-known bind may be added on one call. A claim may not.
let encrypted: EncryptedNote = note
    .encrypt_into_with_context(&keyset, Bind::new(row_id))
    .await?;
```

The context chain already uses typestate to refuse a scope after a bind.
The same mechanism marks a declaration that contains a claim, and the
entry points accept it only for a keyset whose provider implements
`ResolvesClaims`. A dynamic declaration with a claim part is refused at
load on a provider that cannot resolve claims, before any key I/O.

`contexts()` and `assert_context!` show a claim as a part whose value
reads "resolved by the provider". Go declares a claim in the struct tag,
and `stashgen` puts the part in the declaration it sends. The dynamic
declaration gains a part kind `claim`. A declaration without one is the
rc.3 form.

### Which token

The claim resolves from the bearer token on the ZeroKMS request. For a
per-user claim, that token must have been exchanged from the user's own
JWT.

The Go SDK passes the call's context into the token call, and the
`@cipherstash/auth` binding has `getTokenForJwt`. The `@cipherstash/stack`
native entry does not: it calls the JavaScript token callback from a
background task, outside the caller's request. Issue #1565 tracks that
defect. A claim on that path is not safe until it is fixed.

### Other provider facts

The kind generalises to any fact the provider knows and the client
cannot forge. Examples: the client ID that authenticated, the
provider's clock at generation, and the caller's address as the provider
saw it. Each would be a
variant of `Claim`. Start with `Sub` and `Custom`, and add a variant
when it has a use.

## Labels

A label adds a named, typed fact to the key tag of a stored value, after
encryption. The value is then tied to its row and to the facts of its
writing. Its context, its AAD, and its queries do not change. ZeroKMS
verifies the labels when it returns the key, and logs them. That log is
where access intelligence comes from now, and where policy over labels
comes later.

Labelling was called tag refinement, and a label a caveat, until 8
November 2026. Dan chose "label" because a caveat is a restriction in
the Macaroons sense, and a label restricts nothing.

### How it works

The write path:

1. ZeroKMS returns a data key and a tag. Stack Encrypt binds the tag in
   the leaf AAD and stores the tag with the ciphertext.
2. The stored tag can be labelled in three places:
   - in Rust, after encryption;
   - in the database, by a trigger, once the primary key is known;
   - by ZeroKMS, at generate time.
3. Labelling is HMAC chaining, in the style of Macaroons:
   `tag' = HMAC(tag, PAE(name, value))`. The label is appended to the
   payload's label list. Then `tag'` replaces the stored tag, inside the
   ciphertext envelope where it lives.

The read path:

1. The client sends the stored tag and the label list to ZeroKMS.
2. ZeroKMS derives the original tag again, applies the chain of labels,
   and compares the result with the tag it was sent.
3. ZeroKMS logs the labels. Later it applies policy to them.
4. ZeroKMS returns the original tag with the key material.
5. The client rebuilds the leaf AAD with the original tag, and decrypts.

The reader passes nothing. The tag and the labels are in the row.

### Rules for labels

- **EQL defines the standard names, and an application adds its own.**
  EQL publishes a standard set of label names for access intelligence,
  such as `row_id`, `created_at`, and `written_from`. ZeroKMS policy
  will match on names, so the standard set gives every customer one
  vocabulary. An application adds custom names beside them. Stack
  Encrypt checks only that a name is non-empty text.
- **Values are typed.** A timestamp and the text of a timestamp are
  different MAC inputs. Each value carries its type in the encoding, as
  a context part does.
- **Any layer may label, in any order.** A client can label before the
  insert. A trigger can label after it. A client can label again later.
  The chain records the order, so a client-side label added after the
  trigger follows the row ID.
- **A name may repeat.** Two `updated_at` labels, added at different
  times, are a history.
- **Values are in the clear.** They are stored beside the tag. Anyone
  who can read the row can read them. ZeroKMS verifies them through the
  chain. The AEAD does not.
- **A label is not a part of the context.** It is not in the query
  context, so it changes no search term. It is not in the AAD, so the
  AEAD does not check it.

### ZeroKMS can write a label

At generate time, ZeroKMS can resolve a claim and label the tag with it
before returning. `written_by = sub` is the example. The request lists
the claims to label with. That list is separate from the key context
items to bind with, so the two intents are separate on the wire.

The value is more trustworthy than a client-written label, because the
client never had the chance to assert it. This is the recommended way to
record who wrote a value for access intelligence.

**The response returns two tags: the base tag and the labelled tag.**
The client binds the base tag into the leaf AAD. It stores the labelled
tag with the label, as it does for a label it writes itself. So every
label is outside the AAD, whoever wrote it.

The read path has one rule. ZeroKMS returns the base tag, and the
client rebuilds the AAD from it.

A server-written label is still not a bind. Dan asked on 8 November
2026 whether it becomes one, since the client could bind the labelled
tag into the AAD instead. It does not, for two reasons.

- **Nothing about the reader is checked against a label.** The labelled
  tag and the label's value are stored in the row in the clear. A reader
  presents them as they are. ZeroKMS recomputes the chain from the base
  tag and the stored labels. The check passes for any reader whose key
  context items resolve. A bind is different: ZeroKMS resolves a claim
  from the reader's token, or the reader supplies a value, and ZeroKMS
  compares that with the tag. A label asks nothing of the reader.
- **Binding the labelled tag into the AAD would add tamper evidence,
  not access control.** It would stop a label being stripped or altered
  without the AEAD failing. ZeroKMS already refuses a chain it cannot
  reproduce, so that evidence is redundant. It would also break the
  single rule above. The client would have to know which labels were
  applied before encryption and which after, to rebuild the AAD.
  Returning the base tag keeps every label the same.

One privacy consequence to state: a server-written `written_by` puts the
writer's `sub` in the row in the clear, beside the ciphertext. That is
the point of the label for access intelligence. It must be a choice the
declaration makes, never a default.

### Labelling in Rust and SQL

In Rust, `label` adds a label to an EQL value. It returns the labelled
value, so calls chain. A JSON document has one tag in its header, so it
labels the same way. Decryption is unchanged.

```rust
let sealed: TextEq = body.encrypt_into_with_context(&keyset, Scope::new(&column)).await?;
let sealed = sealed
    .label("written_from", request.ip())?
    .label("created_at", now())?;

// Read the labels without decrypting.
for label in sealed.labels() {
    println!("{} = {}", label.name(), label.value());
}

// Decrypt. The tag and the labels come from the payload.
let body: String = String::decrypt_from(sealed, &keyset).await?;
```

In SQL, `eql_v4.label_tag` does the same to a stored payload. A trigger
can label with the primary key that the database generated:

```sql
CREATE FUNCTION notes_label_body() RETURNS trigger AS $$
BEGIN
  NEW.body := eql_v4.label_tag(NEW.body, 'row_id', NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER notes_label_body
  BEFORE INSERT ON notes
  FOR EACH ROW EXECUTE FUNCTION notes_label_body();
```

### Go, and labelling many values

Labelling is local. It is an HMAC over the tag, computed in the engine,
with no call to ZeroKMS. So there is no batch to send. No bulk form is
needed.

Go's `Encrypt` seals a slice in one call. A program then labels the
values it chooses, through a `Label` method on every EQL value type.
`Labels` reads the list. Both go through the module's EQL guest, and
neither touches the network.

```go
rows, err := Encrypt(ctx, cipher, notes) // []EncryptedNote
for i := range rows {
	if err := rows[i].Body.Label("written_from", req.RemoteAddr); err != nil {
		return err
	}
	if err := rows[i].Body.Label("created_at", time.Now()); err != nil {
		return err
	}
}

for _, l := range rows[0].Body.Labels() {
	fmt.Println(l.Name, l.Value)
}
```

The dynamic interface has `label` and `labels` as operations on a stored
value, and the Go methods call them.

### The labels list in the payload

An optional `labels` list is added to the EQL payload. The list is
present only once a label has been added. A payload without it is the
rc.3 form, so the change is additive. Every EQL type has the list,
whether it stores a scalar or a JSON document. Each has one tag.

The tag itself stays where it is today: inside the ciphertext envelope,
the `c` field of the payload. So `eql_v4.label_tag` reads the tag out of
the envelope and writes the labelled tag back in. That needs the
envelope's layout in SQL. The plan's [key tag
extraction](2026-10-24-stack-encrypt-api-plan.md#typed-text-encodings-and-key-tag-extraction)
item provides it.

A bare `Ciphertext` is a raw envelope with no list. No list will be added
to it. Labels are for EQL payloads. Decided by Dan on 8 November 2026.

### Example: access intelligence for a notes table

ZeroKMS labels the value with the writer's `sub` at generate time. The
client adds two labels before the insert. The trigger adds the primary
key.

A reader selects one column and decrypts. ZeroKMS logs all four
labels when it returns the key. No reader is restricted.

```rust
let sealed: TextEq = note.body
    .encrypt_into_with_context(&keyset, Scope::new(&column))
    .await?
    .label("written_from", request.ip())?
    .label("created_at", now())?;
sqlx::query("INSERT INTO notes (body) VALUES ($1)").bind(&sealed).execute(&db).await?;

let sealed: TextEq = sqlx::query_scalar("SELECT body FROM notes WHERE id = $1")
    .bind(id)
    .fetch_one(&db)
    .await?;
let body: String = String::decrypt_from(sealed, &keyset).await?;
```

The stored payload, after the trigger. The tag is inside `c`. `hm` is
the equality term:

```json
{
  "v": 1,
  "i": {"t": "notes", "c": "body"},
  "c": "…",
  "hm": "…",
  "labels": [
    {"n": "written_by",   "v": "auth0|5f3a…"},
    {"n": "written_from", "v": "203.0.113.5"},
    {"n": "created_at",   "v": "2026-11-07T10:15:00Z"},
    {"n": "row_id",       "v": "7f3c2a9e-…"}
  ]
}
```

## What ZeroKMS must do

This work is outside this repository. The current ZeroKMS can be fixed
where it falls short, and version 2 of ZeroKMS must implement all of it.

For binds and claims:

- Accept the context name as the descriptor and the parts as lock
  context items, as it does today. No change for the first release.
- **Version 2 derives the data key over the key context items as well
  as the descriptor.** Then a bind or a claim is enforced by derivation,
  not by a check that could be skipped. A reader with a different claim
  value gets a different key, and the leaf fails to open.
- Resolve `sub` and custom claims from the verified token, as today.
  Add other provider facts as they are needed.
- Retire the decryption policy and its tag version.
- Remove the descriptor size limit. The move of the parts makes it
  unnecessary. Stop logging the descriptor in the clear.

For labels:

- The retrieve-key request includes the stored tag and the label list.
- ZeroKMS verifies the chain, and refuses a tag it cannot reproduce.
- The response returns the original tag with the key material. Today's
  pinned protocol returns key material only.
- The generate-key request includes a list of claims to label with. The
  response returns the base tag, the labelled tag, and the label.
- Policy over labels comes later. A policy can be changed. A bind
  cannot.

## Open questions

- Should version 2 of ZeroKMS also bind the format version of the
  envelope, so that a version 1 request cannot be replayed as version 2?
- Which standard label names does EQL publish first?
