# Tag refinement and caveats

Date: 7 November 2026.

Tag refinement adds a caveat to the ZeroKMS key tag of a stored value. A
caveat is a named fact about the value's row or its writing: a primary
key, a source address, or a time of writing. The value is then tied to
those facts without any change to its context, its AAD, or its queries.
ZeroKMS verifies the caveats when it returns the key. That is where
access intelligence comes from now, and where policy over the caveats
will come from later.

This document gives the design and the proposed API. The [API
plan](2026-10-24-stack-encrypt-api-plan.md) lists the work. None of the
code below is on `next` today.

## How it works

The write path:

1. The client asks ZeroKMS for a data key, with a descriptor. For an EQL
   value the descriptor is the table and column identifier.
2. ZeroKMS returns the key and a tag. The tag is derived in part from the
   descriptor.
3. Stack Encrypt binds the tag in the AAD of the ciphertext, and stores
   the tag with the ciphertext.
4. The stored tag can be refined, either in Rust after encryption, or in
   the database by a trigger, once the generated primary key is known.
5. Refining is HMAC chaining, in the style of Macaroons:
   `tag' = HMAC(tag, PAE(name, value))`. The caveat is appended to the
   payload's caveat list. Then `tag'` replaces the stored tag, inside the
   ciphertext envelope where it lives.

The read path:

1. The client sends the stored tag and the caveat list to ZeroKMS.
2. ZeroKMS derives the original tag again. It applies
   the chain of caveats to it. Then it compares the result with the tag it
   was sent.
3. ZeroKMS does what it chooses with the caveats. For now it logs them.
   Later it applies policy to them.
4. ZeroKMS returns the original tag with the key material.
5. The client rebuilds the leaf AAD with the original tag, and decrypts.

The reader passes nothing. The tag and the caveats are in the row.

## Caveats

A caveat is a name and a typed value. Both go into the MAC, through
`PAE`, the length-prefixed encoding the engine already uses for the leaf
AAD. So a name and a value cannot run into each other. Neither can be
swapped after the fact.

- **Names are the application's.** Stack Encrypt checks only that a name
  is non-empty text. ZeroKMS policy will match on names, so a customer
  wants one vocabulary. CipherStash can publish a recommended set for
  access intelligence, such as `row_id`, `created_at`, and
  `written_from`, without reserving any name.
- **Values are typed.** A timestamp and the text of a timestamp are
  different MAC inputs. Each value carries its type in the encoding, as a
  context part does, so ZeroKMS knows that `created_at` is a timestamp.
- **A name may repeat.** Two `updated_at` caveats, added at different
  times, are a history. The chain is ordered. The order is kept.
- **Values are in the clear.** They are stored beside the tag. Anyone
  who can read the row can read them. ZeroKMS verifies them through the
  chain. The AEAD does not.

## API

In Rust, `refine` adds a caveat to an EQL value. It returns the refined
value, so calls chain. A JSON document has one tag in its header, so it
refines the same way. Decryption is unchanged.

```rust
let sealed: TextEq = body.encrypt_into_with_context(&keyset, Scope::new(&column)).await?;
let sealed = sealed
    .refine("written_from", request.ip())?
    .refine("created_at", now())?;

// Read the caveats without decrypting.
for caveat in sealed.caveats() {
    println!("{} = {}", caveat.name(), caveat.value());
}

// Decrypt. The tag and the caveats come from the payload.
let body: String = String::decrypt_from(sealed, &keyset).await?;
```

In SQL, `eql_v4.refine_tag` does the same to a stored payload. A trigger
can refine with the primary key that the database generated:

```sql
CREATE FUNCTION notes_refine_body() RETURNS trigger AS $$
BEGIN
  NEW.body := eql_v4.refine_tag(NEW.body, 'row_id', NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER notes_refine_body
  BEFORE INSERT ON notes
  FOR EACH ROW EXECUTE FUNCTION notes_refine_body();
```

The dynamic interface has `refine` as an operation on a stored value, so
Go can refine a value before it writes the row. `caveats` reads the list
in the same way.

## Stored format

An optional `caveats` list is added to the EQL payload. The list is
present only once a caveat has been added. A payload without it is the
rc.3 form, so the change is additive under the plan's [stored-format
rule](2026-10-24-stack-encrypt-api-plan.md#the-stored-format-stays-compatible-with-go-rc3).
Every EQL type has the list, whether it stores a scalar or a JSON
document. Each has one tag.

The tag itself stays where it is today: inside the ciphertext envelope,
the `c` field of the payload. So `eql_v4.refine_tag` reads the tag out of
the envelope and writes the refined tag back in. That needs the
envelope's layout in SQL. The plan's [key tag
extraction](2026-10-24-stack-encrypt-api-plan.md#typed-text-encodings-and-key-tag-extraction)
item provides it.

A bare `Ciphertext` is a raw envelope with no list, so refinement starts
with EQL payloads. A type of our own can store the list as a field of its
own.

## What tag refinement is not

A caveat is not a part of the context. It is not in the query context,
so it changes no search term. It is not in the AAD, so the AEAD does not
check it. The context model is in the plan's [Query context and stored
context](2026-10-24-stack-encrypt-api-plan.md#query-context-and-stored-context).

## ZeroKMS

The read path needs ZeroKMS, and that work is outside this repository:

- The retrieve-key request includes the stored tag and the caveat list.
- ZeroKMS verifies the chain, and refuses a tag it cannot reproduce.
- The response returns the original tag with the key material. Today's
  pinned protocol returns key material only.
- Policy over caveats comes later.

ZeroKMS today limits the length of a descriptor, and logs it in the
clear. ZeroKMS version 2 is planned to remove the limit and to encrypt
the access log.

## Example: access intelligence for a notes table

The client adds two caveats before the insert. The trigger adds the
primary key. A reader selects one column and decrypts. ZeroKMS logs all
three caveats when it returns the key.

```rust
let sealed: TextEq = note.body
    .encrypt_into_with_context(&keyset, Scope::new(&column))
    .await?
    .refine("written_from", request.ip())?
    .refine("created_at", now())?;
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
  "caveats": [
    {"n": "written_from", "v": "203.0.113.5"},
    {"n": "created_at",   "v": "2026-11-07T10:15:00Z"},
    {"n": "row_id",       "v": "7f3c2a9e-…"}
  ]
}
```

## Open questions

- Should the raw `Ciphertext` envelope gain a caveat list, as a new
  version beside the rc.3 one?
- Should CipherStash publish a standard vocabulary of caveat names for
  access intelligence?
- What shape does bulk refinement take in Go, where `Encrypt` seals a
  slice in one call?
- May `refine` run after a database refinement? The chain is ordered, so
  a client-side caveat added later goes after the row ID.
