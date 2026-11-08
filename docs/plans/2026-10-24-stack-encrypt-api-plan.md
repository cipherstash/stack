# Stack Encrypt API plan

Date: 7 November 2026. Checked against `next` at commit `e4990e49b`.

Stack Encrypt encrypts each value under its own data key from ZeroKMS,
CipherStash's key service. It also makes the search terms that let
PostgreSQL query the encrypted value. The Rust crate `stack-encrypt` is the
engine. The Go SDK runs the same engine through the dynamic interface.

This plan is for the engineers who build Stack Encrypt, and for the lead
who approves its design. It has three parts:

1. [Target state](#target-state): the API we are building, shown as code.
2. [Remaining work](#remaining-work): what is left to build to reach it.
3. [Open questions and decisions to be
   made](#open-questions-and-decisions-to-be-made).

Six documents go with it:

- the [context scenarios](2026-10-24-stack-encrypt-context-examples.md),
  the acceptance matrix for how a record gets its context;
- [tag refinement and caveats](2026-11-07-stack-encrypt-tag-refinement.md),
  the design of the caveats on a key tag;
- [JSON operations](2026-10-25-stack-encrypt-json-operations.md), the
  inventory of every JSON operation, with its SQL;
- [packaging and names](2026-10-25-stack-encrypt-packaging.md), the
  proposal the naming review judges;
- [provider capabilities](2026-10-25-stack-encrypt-provider-capabilities.md),
  the proposal for keyset routing and lock context after the customer
  release;
- the [decision record](2026-10-24-stack-encrypt-api-review.md), the 22
  issues the October review found, with the decision on each. The names this plan uses as
placeholders are listed in [Names deferred to the naming
review](#names-deferred-to-the-naming-review), at the end.

## Terms

| Term | Meaning |
| --- | --- |
| AAD (additional authenticated data) | Data that encryption checks for one ciphertext, but does not encrypt. Stack Encrypt builds it from the context. See [Context and AAD](#context-and-aad) |
| ADR | An architecture decision record, in `packages/stack-encrypt/docs/adr/`. ADR-0007 says every binding runs the engine's one executor |
| Analyzer | The pipeline that turns match text into tokens: a source, such as `Words`, then stages. A match index is configured by one analyzer |
| Binding | A part of the context that ties a ciphertext to its row, such as a row ID. It is in the stored context and not in the query context. Passed as `Bind::new(..)` |
| Caveat | A named, typed fact added to a stored value's key tag by tag refinement, such as `row_id` or `created_at`. ZeroKMS verifies it. See [Tag refinement](#tag-refinement) |
| Ciphertext | One encrypted value, as the Rust `Ciphertext` type. It is stored as bytes, or as Base64 text |
| Conformance profile | A named, versioned set of test cases for one area, such as `record-contexts-v1`. Rust and Go run the same cases. The files are in `conformance/stack-encrypt/v1/` |
| Context name | The last declared scope of a field: its name by default, pinned when the Rust field is renamed. Two fields of one record never share one |
| Context | Data that a ciphertext is tied to, such as a column name or a row ID. Decryption needs the same context. See [Context and AAD](#context-and-aad) |
| Descriptor | A context rendered as text, such as `users/age`. ZeroKMS derives the data key from it and logs it at every retrieval |
| Dynamic interface | The engine's interface for languages other than Rust. It takes a declaration and values as data, not as Rust types |
| EQL (Encrypt Query Language) | The PostgreSQL types and functions in `packages/eql` that store encrypted values and answer queries on them |
| Executor | The one engine path that runs a plan: it derives each field's context, requests the keys in one batch, and seals or opens every value |
| Field marker | A constant the derive emits for each field of a record, such as `EncryptedMember::EMAIL`. It names the field, its plaintext type, its accessor, and its indexes. A typed query starts from it |
| `FieldRef` | The builder's reference to one field of the plaintext type: its name and its accessor. A field marker is a `FieldRef` with its indexes added |
| Guest | The Rust engine compiled to WebAssembly. The Go SDK runs it inside the Go process |
| Keyset | A set of keys in ZeroKMS. Every data key belongs to one keyset. A tenant can have its own keyset |
| n-gram | A run of `n` characters of a token, such as the trigrams of a word. The match index stores a Bloom filter of n-grams |
| Opaque blob | A whole value, such as a struct, encoded and sealed as one ciphertext. Nothing inside it can be searched |
| PAE | Pre-authentication encoding: a length-prefixed encoding of several values, so that two values cannot run into each other. The leaf AAD and a caveat use it |
| Passthrough field | A field stored unencrypted next to the encrypted fields. It is not authenticated |
| Plan | A record's declaration as data: each field, its context, and its indexes. The derive builds one through `encryption_plan()`; a program can build one by hand, or read one at run time. See [A request: `Planned`](#a-request-planned) |
| Planned | A value paired with a plan that is data, `Planned::new(&plan, value)`. Encrypted, queried, or decrypted with the keyset as the argument. See [A request: `Planned`](#a-request-planned) |
| Query context | All the scopes of a context, declared and caller-supplied. Search terms derive under it. See [Query context and stored context](#query-context-and-stored-context) |
| Query plan | A record plan narrowed to one field and one operator, `plan.query(field, op)`. A query value is encrypted under it. See [A query plan](#a-query-plan) |
| QueryTerm | The result of a query on the dynamic path: the operand bytes and the EQL type they bind as, known at run time |
| Request | A serialised `Planned`: the plan, the caller's context parts, and the value. The one thing a binding sends to the engine. A transport form, never stored |
| Scope | A part of the context that narrows the data and the queries over it. The declaration supplies the first scopes, such as `users` and `email`; the caller adds more, such as a tenant ID, with `Scope::new(..)` |
| Search term | A value stored next to a ciphertext, so that a query can find it without decrypting it. Equality, order, and match each use their own term |
| Stage | One step of an analyzer that maps, drops, or expands tokens, such as `Downcase`, `Stop`, `Stem`, or `Ngrams`. A serialised plan may name only the closed set of stages |
| Stored context | Every part of a value's context. The data key and the AAD derive under it |
| Stored format | Everything Stack Encrypt writes to the database. See [The stored format stays compatible with Go rc.3](#the-stored-format-stays-compatible-with-go-rc3) |
| Tag refinement | Replacing a stored key tag with an HMAC of it and a caveat, so ZeroKMS can verify the caveat when it returns the key. See [Tag refinement](#tag-refinement) |
| Target | The encrypted type that a value is stored as, such as `Ciphertext`, an EQL type like `TextEq`, or a record type |
| Vitamin C | CipherStash's Rust cryptography library, the `vitaminc-*` crates. It seals and opens leaves and derives the AAD; Stack Encrypt plans, batches, and stores |

## Target state

This section shows what a developer writes when every item in this plan is
built. A comment marks each piece of code that does not compile on `next`
today. [Remaining work](#remaining-work) says what each of those needs.

### Rust with static types

These examples use the `stack-encrypt` crate directly, with a Rust type for
each encrypted value.

#### Connect and choose a keyset

A client reads its credentials from the environment, or from the profile
that `npx stash auth login` writes. Every encryption uses one keyset. A
program can use the client's default keyset, or select another by name or
ID.

```rust
use stack_encrypt::{kms::IdentifiedBy, StackCipher};

let cipher = StackCipher::new().await?;
let keyset = cipher.default_keyset();
// Not on `next` yet: the `IdentifiedBy::name` and `IdentifiedBy::uuid`
// constructors. `name` checks the name, so it returns a `Result`.
let tenant = cipher.keyset(IdentifiedBy::name("acme")?).await?;
let by_id = cipher.keyset(IdentifiedBy::uuid(keyset_id)).await?;
```

#### Encrypt and decrypt one value

`encrypt` returns one `Ciphertext`. A context ties the ciphertext to where
it belongs, so it cannot be decrypted anywhere else.

`encrypt` accepts an owned value or a borrowed one. It wipes an owned
value, such as a `String`. It only reads a borrowed value, such as a
`&str`, so the caller is responsible for wiping the original.

```rust
use stack_encrypt::Ciphertext;

// Not on `next` yet: borrowed values such as `&str`.
let secret: Ciphertext = keyset.encrypt("secret").await?;
let plaintext: String = keyset.decrypt(secret).await?;

let number: String = read_card_number()?;
let card: Ciphertext = keyset
    .encrypt_with_context(number, "users/42/card") // wipes `number`
    .await?;

// Store the ciphertext as bytes, or as Base64 text through Serde.
let bytes: Vec<u8> = card.to_bytes();
let card = Ciphertext::from_bytes(&bytes)?;
let number: String = keyset.decrypt_with_context(card, "users/42/card").await?;
```

A value encrypted with no context is bound to nothing but its keyset.
Its ciphertext can be moved to any column or any row, and it still opens
there. Use the plain `encrypt` only for a value whose location does not
matter. `contexts()` shows such a value's context as empty.

`encrypt` accepts only single values: text, numbers, booleans, dates,
times, and decimals. A struct or a `Vec` does not compile. Use a record, a
collection, or an opaque blob instead.

#### Encrypt a record

A record type says how each field of a plaintext struct is stored. The
derive seals each encrypted field under its own context, such as
`("users", "name")`. All the fields in a record share one batch of key
requests.

```rust
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto};
use zeroize::Zeroize;

#[derive(Zeroize)]
struct User {
    id: u64,
    name: String,
    email: String,
    created_at: i64,
}

// A searchable email: its ciphertext and an equality term.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct SearchableEmail {
    ciphertext: Ciphertext,
    equality: EqualityTerm,
}

// Not on `next` yet: the record derive and `passthrough`.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: SearchableEmail,
    #[stash(passthrough)]
    created_at: i64,
}

let encrypted: EncryptedUser = user.encrypt_into(&keyset).await?;
let user = User::decrypt_from(encrypted, &keyset).await?;
```

The derives need no Serde. A program that stores an encrypted value as
JSON adds `Serialize` and `Deserialize` to the encrypted type. That is
the same as for any other type.

To tie every field to one row, the caller supplies the row ID as a part of
the context, and supplies it again to decrypt. The row ID is a binding
part. It is in the stored context, so the key and the AAD depend on it. It
is not in the query context, so a query still finds the row across the
column.

[Query context and stored context](#query-context-and-stored-context)
gives the rule. The [context
scenarios](2026-10-24-stack-encrypt-context-examples.md) show how a
declaration marks a binding; the attribute spelling is a placeholder until
the naming review.

```rust
// Not on `next` yet: `Bind`. Today the row ID is passed bare.
let encrypted: EncryptedUser = user
    .encrypt_into_with_context(&keyset, Bind::new(user_id))
    .await?;
let user = User::decrypt_from_with_context(encrypted, &keyset, Bind::new(user_id)).await?;
```

#### Store a field as an EQL type

A field can use an EQL type from the `eql-bindings` crate as its target.
The field is then stored as one EQL column, such as
`public.eql_v4_text_eq`.

Go records already do this through the dynamic interface. A field there
names its EQL type, such as `"target": "TextEq"`, and the engine runs that
type for the field. The Rust record derive does not support it yet.

```rust
use eql_bindings::v4::{integer::IntegerOrd, text::TextEq};

#[derive(Zeroize)]
struct Member {
    id: u64,
    email: String,
    age: i32,
}

// Not on `next` yet in Rust: EQL types as fields of a derived record.
// Go records do this today through the dynamic interface.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Member, context = "members")]
struct EncryptedMember {
    #[stash(passthrough)]
    id: u64,
    email: TextEq,
    age: IntegerOrd,
}
```

#### Query a field

A query encrypts the search value into the query type of the field. It uses
the same keyset and the same context as the stored value. Each EQL type has
a query type, such as `TextEqQuery` for `TextEq` and `IntegerOrdQuery` for
`IntegerOrd`. The query value binds to SQL as a parameter, and the SQL
operator chooses the comparison.

```rust
use eql_bindings::v4::{integer::IntegerOrdQuery, text::TextEqQuery};
use eql_bindings::Identifier;

let email = Identifier::for_column("members", "email")?;
let age = Identifier::for_column("members", "age")?;

// Not on `next` yet: the new traits for EQL types, and a borrowed value
// and context. Today this needs `target::legacy::EncryptInto`, an owned
// value, and an owned context.
let by_email: TextEqQuery = "alice@example.com"
    .encrypt_into_with_context(&keyset, Scope::new(&email))
    .await?;
let older: IntegerOrdQuery = 30_i32
    .encrypt_into_with_context(&keyset, Scope::new(&age))
    .await?;
```

```sql
SELECT id, email, age FROM members WHERE email = $1::eql_v4.query_text_eq;
SELECT id, email, age FROM members WHERE age > $1::eql_v4.query_integer_ord;
```

The context `Identifier::for_column("members", "email")` is the same as the
context that the record derive gives the `email` field of
`EncryptedMember`. So the query matches the stored values. A field of a
record is queried through its marker instead, so that the operator is
checked at compile time. See [Query a record field](#query-a-record-field).

A match query works in the same way, on a field with a match index. Its
answer can include rows that do not match. So the caller decrypts the rows,
and checks each one.

#### Query a record field

The derive emits one marker for each field of a record, such as
`EncryptedMember::EMAIL`. A marker names the field, its plaintext type,
its accessor, and the field's index list. It is the value the plan
builder takes to declare the field, and the value a query starts from.
The derive also emits `encryption_plan()`. It builds the record's `Plan`
through the plan builder, once, and keeps it.

A typed query starts from the marker, and has one method for each
operator the field's indexes answer. A missing operator is a compile
error: "no method named `gt`", with a message that names the field's
indexes. Scopes chain on the query. A binding cannot, because the query
builder has no `bind` method, so a query accepts scopes only, by type.
The query ends with `encrypt(&keyset)`, and its output type is the EQL
query type the marker fixes. Decided on 7 November 2026.

```rust
// Not on `next` yet: field markers, their query methods, and
// `encryption_plan()`. Today a query names a plan written by hand:
// `cipher.query(op::Eq, value).on(&plan)`.
let by_email: TextEqQuery = EncryptedMember::EMAIL
    .eq("alice@example.com")
    .scope(tenant)
    .encrypt(&keyset)
    .await?;
let adults: IntegerOrdQuery = EncryptedMember::AGE
    .between(18, 65)
    .encrypt(&keyset)
    .await?;

// error: `TextEq` has no order index, so the marker has no `gt`
EncryptedMember::EMAIL.gt("alice@example.com")
// error: the query builder has no `bind`
EncryptedMember::EMAIL.eq("alice@example.com").bind(row_id)

// The record's plan, for the dynamic interface.
let plan: &Plan = EncryptedMember::encryption_plan();
```

```sql
SELECT id, email, age FROM members WHERE email = $1::eql_v4.query_text_eq;
```

A chained scope is allowed on a query because a query has one field and
one value, so a scope cannot mean anything else. The rule that no chain state
offers context was about `.extend(..)` after `.fields()` on a record. There, a part added late looked per-field
and was not.

A typed query lowers to a [query plan](#a-query-plan) and a `Planned`
value, so the typed form and the dynamic form run the same engine
function.

#### Encrypt a JSON document

A JSON field is stored as one encrypted document in a
`public.eql_v4_json_search` column.

The simplest form encrypts straight into `JsonTreeDocument`, with the
default options. The context is the column. The default options order no
paths. They also store the whole document in its root entry, so it
decrypts in one step.

```rust
use eql_bindings::{v4::json_tree::JsonTreeDocument, Identifier};
use serde_json::json;
use stack_encrypt::json::JsonPlaintext;

let column = Identifier::for_column("customers", "profile")?;

// Not on `next` yet: the new traits for EQL types, and the public
// `JsonPlaintext`. Today this needs `target::legacy::EncryptInto`, a
// `serde_json::Value`, and an owned context.
let profile: JsonPlaintext = json!({ "name": "Ada", "age": 35 }).into();
let encrypted: JsonTreeDocument = profile
    .encrypt_into_with_context(&keyset, Scope::new(&column))
    .await?;

// On decrypt the column is checked against the one stored in the document.
let opened = JsonPlaintext::decrypt_from_with_context(encrypted, &keyset, Scope::new(&column)).await?;
let name = &opened.value()["name"]; // `opened` wipes the document when it is dropped
```

`JsonPlaintext` contains a `serde_json::Value`. It wipes the value when it
is dropped. It converts from a `serde_json::Value`, or parses JSON text with
the strict checks on JSON input. A program can also encrypt a borrowed
`&serde_json::Value`. Then the program is responsible for wiping it, as for
any [borrowed value](#encrypt-borrowed-values).

With the default options, no path has an order term. So a query cannot
compare the order of the values at a path. To order some paths, declare a
named type with typed Rust options:

```rust
use stack_encrypt::json::JsonOptions;

fn profile_options() -> Result<JsonOptions, TermError> {
    JsonOptions::new().ordering(["$.age", "$.visits[*].at"])
}

// Not on `next` yet: a JSON target with typed options.
#[derive(EncryptTarget, DecryptSource)]
#[stash(
    plaintext = JsonPlaintext,
    transparent,
    target(column = ("customers", "profile"), options = profile_options)
)]
struct EncryptedProfile(JsonTreeDocument);

let profile = JsonPlaintext::parse(r#"{"name":"Ada","age":35}"#)?;
let encrypted: EncryptedProfile = profile.encrypt_into(&keyset).await?;
let opened = JsonPlaintext::decrypt_from(encrypted, &keyset).await?;
```

#### Query a JSON document

A JSON query is a query on the document's field marker. The marker has
one method for each kind of query. A scalar field's marker has one method
for each operator in the same way (see [Query a record
field](#query-a-record-field)). A query needs two things from the field's
declaration:

- **The column context.** Each path's selector is derived under it, so the
  query must use the same context as the stored documents.
- **The options.** They say which paths have order terms, and how far a
  wildcard such as `[*]` expands. An order query on a path without order
  terms would find no rows, so Stack Encrypt refuses it.

The marker carries both, so the query names only its kind and its
values. The output type is the EQL query type, fixed by the marker.
Decided on 7 November 2026.

```rust
use eql_bindings::v4::json_tree::{JsonTreeElementsQuery, JsonTreeLeafQuery, JsonTreeQuery};

// Not on `next` yet: field markers and their query methods. The method
// names are proposals.
let ada: JsonTreeQuery = EncryptedProfile::DOCUMENT
    .contains(json!({ "name": "Ada" }))
    .encrypt(&keyset)
    .await?;
let older: JsonTreeLeafQuery = EncryptedProfile::DOCUMENT
    .at("$.age")
    .gt(30)
    .encrypt(&keyset)
    .await?;
let adults: JsonTreeLeafQuery = EncryptedProfile::DOCUMENT
    .at("$.age")
    .between(18, 65)
    .encrypt(&keyset)
    .await?;
let home: JsonTreeElementsQuery = EncryptedProfile::DOCUMENT
    .elements("$.visits[*]")
    .eq("place", "home")
    .gt("at", 15)
    .encrypt(&keyset)
    .await?;
```

```sql
SELECT id FROM customers WHERE profile @> $1::eql_v4.query_json;

-- $1 is the selector of `$.age`. $2 and $3 are the bounds.
SELECT id FROM customers
WHERE (profile -> $1::text) >= $2::eql_v4.query_json_leaf
  AND (profile -> $1::text) <= $3::eql_v4.query_json_leaf
ORDER BY eql_v4.ord_term(profile -> $1::text);

SELECT id FROM customers
WHERE eql_v4.json_tree_element_match(profile, $1::eql_v4.query_json_elements);
```

The kinds of JSON query, the marker method for each, and what each finds:

| Query | Marker method | What it finds | EQL query type |
| --- | --- | --- | --- |
| Containment | `contains(doc)`, `contained_by(doc)` | Rows whose document contains the given document, or is contained by it | `JsonTreeQuery` |
| Comparison at a path | `at(path).eq(v)`, `.gt(v)`, `.between(a, b)`, and the rest | Rows where the value at an ordered path equals, orders against, or lies between the given values | `JsonTreeLeafQuery` |
| Element match | `elements(path).eq(member, v).gt(member, v)` | Rows where one element of an array meets several conditions together | `JsonTreeElementsQuery` |
| Jsonpath predicate | `predicate(text)` | Rows where a SQL/JSON path predicate is true | `JsonTreePredicateQuery` |
| Children and child count | `children(path)` | The entries directly below one node, or how many there are | A node token |

A path is text. So an order query on a path the options do not order is
refused at run time, before any key is fetched. A scope chains on a JSON
query as on a scalar one: `.contains(doc).scope(tenant)`.

The engine already has one input type for each JSON operator, in
`stack_encrypt::dynamic`. `DocumentInput` is for containment, `AtInput`
for a comparison at a path, and `ElementsInput` for element match. The marker
methods build those same inputs, so the typed form and the dynamic form
share one set of input rules. The operand types `Contains`, `AtPath`,
`ElementMatch`, `Predicate`, and `Children` that the plan proposed earlier
are retired, replaced by these methods, on 7 November 2026.

A document encrypted straight into `JsonTreeDocument`, with no record,
has no marker. It is queried through a [query plan](#a-query-plan), as any
value under a plan that is data.

#### Encrypt a whole value as one ciphertext

`OpaqueBlob<T>` encodes any Serde value and seals it as one ciphertext. Go
writes the same format for its opaque structs. So each language can read
the blobs that the other one writes.

```rust
use stack_encrypt::blob::OpaqueBlob;

// Not on `next` yet: `OpaqueBlob`.
let sealed = keyset
    .encrypt_with_context(OpaqueBlob::new(settings), ("users", "settings"))
    .await?;
let settings: OpaqueBlob<Settings> = keyset
    .decrypt_with_context(sealed, ("users", "settings"))
    .await?;
```

#### Encrypt a collection

A `Vec` of values encrypts into a `Vec` of targets, with one batch of key
requests for the whole collection. Each element has its own data key, so
each one decrypts on its own. The order and the length of the `Vec` are
not authenticated, because a database can return rows in any order.

```rust
let column: Vec<Ciphertext> = vec![1_i32, 3, 5].encrypt_into(&keyset).await?;
let values = Vec::<i32>::decrypt_from(column, &keyset).await?;

let rows: Vec<EncryptedUser> = users.encrypt_into(&keyset).await?;
```

That is the default, because it is the common case. A caller who needs
the order and the length authenticated asks for it by type. This is the
same way that `OpaqueBlob<T>` changes how a value is sealed. The wrapper seals each
element under its position and the length of the `Vec`, as part of the
context. An element that is swapped, dropped, or added then fails to open.

```rust
use stack_encrypt::Positioned;

// Not on `next` yet: `Positioned`. The name is a proposal.
let steps: Positioned<Vec<Ciphertext>> = Positioned(vec![1_i32, 3, 5])
    .encrypt_into(&keyset)
    .await?;
let values = Positioned::<Vec<i32>>::decrypt_from(steps, &keyset).await?;
```

`Positioned` is a new stored form, so it does not change the data that
Go rc.3 writes. ADR-0010 records that stricter authentication of a
container is opt-in, by type.

#### Encrypt a byte string

A `Vec<u8>` is the exception to the collection rule. It encrypts as one
value, into one `Ciphertext`, because a byte string is almost always one
thing: a file, a key, or an image. A fixed-size array `[u8; N]` is a byte
string too. `u8` on its own is not a value that encrypts, so a `Vec<u8>`
cannot encrypt byte by byte.

A Go `[]byte` field takes the same path. The Go SDK sends the bytes to
the engine as one bytes value. The engine seals them with the same
Vitamin C code that seals a Rust `Vec<u8>`. The dynamic interface and the
Rust API share one engine, so they write the same bytes for the same
declaration (ADR-0007).

The byte string is not a special case of either language. It is a rule of
the engine.

A `Vec` of byte strings follows the collection rule. It encrypts into a
`Vec<Ciphertext>`, one for each byte string, with no wrapper type. The
byte-string rule was decided on 7 November 2026 by Dan. It is what pull
request #1501 built.

```rust
let file: Ciphertext = std::fs::read("photo.jpg")?.encrypt_into(&keyset).await?;
let photo = Vec::<u8>::decrypt_from(file, &keyset).await?;

let key: Ciphertext = [7u8; 16].encrypt_into(&keyset).await?;

let files: Vec<Ciphertext> = vec![vec![1u8, 2, 3], vec![], vec![9]]
    .encrypt_into(&keyset)
    .await?;
let opened = Vec::<Vec<u8>>::decrypt_from(files, &keyset).await?;
```

To encrypt each byte of a `Vec<u8>` as its own ciphertext, name a type
for one byte. A `Vec` of that type is an ordinary collection, so it
encrypts into one `Ciphertext` for each element. The named type is a
single value because its borrow implements Vitamin C's `Scalar`. That is
the same rule every built-in single value follows.

```rust
use stack_encrypt::Scalar;
use zeroize::Zeroize;

/// One byte, sealed on its own.
// Not on `next` yet: `#[derive(Scalar)]`. Today `Byte` needs `Encrypt`
// and `Scalar` on `&Byte`, and `FromScalar` on `Byte`, by hand.
#[derive(Zeroize, Scalar)]
struct Byte(u8);

let bytes: Vec<Byte> = vec![0u8, 1, 255].into_iter().map(Byte).collect();
let each: Vec<Ciphertext> = bytes.encrypt_into(&keyset).await?;
let opened = Vec::<Byte>::decrypt_from(each, &keyset).await?;
```

`#[derive(Scalar)]` works on a struct with one field, whose type is a
built-in single value. The derive encrypts the struct as that field, and
decrypts the field back into the struct. So `Byte` is sealed exactly as
the `u8` inside it would be, if `u8` were a single value on its own.

### The dynamic interface

The dynamic interface takes a declaration and values as data, not as Rust
types. A program uses it in two cases:

- when it learns the declaration only at run time, such as a query that
  chooses its operator and path from user input;
- when it is written in another language, such as Go.

The engine turns a declaration into the same plan that the Rust derive
builds. So the dynamic interface writes the same bytes as the static API
for the same declaration.

#### A declaration as data

A declaration names each field and its context. It also says how the field
is stored: as a passthrough field, with the indexes it lists, or as an EQL
type.

```json
{
  "id":      { "context": ["users", "id"],    "outputs": ["passthrough"], "type": "int64" },
  "email":   { "context": ["users", "email"], "target": "TextEq" },
  "age":     { "context": ["users", "age"],   "outputs": ["c", "eq", "ore"], "type": "int32" },
  "profile": { "context": ["users", "profile"],
               "target": { "name": "JsonSearch",
                           "options": { "sealed_root": true, "ordered": ["$.age"] } } }
}
```

Each row crosses the boundary as one transport frame. A query names a
field and an operator, such as `eq` or `contains`, and gives a value. In
the target state that is a [query plan](#a-query-plan) and a
[request](#a-request-planned). The engine returns the query value, with
its EQL type.

The output keys and the type names are part of the stored format, so they
cannot change. The output keys are `c`, `eq`, `match`, `ore`, `ope`, and
`passthrough`. The type names include `int64` and `string`.

#### A request: `Planned`

Anything encrypted under a plan that is data is a `Planned` value. That
is a record under a record plan, or a query value under a [query
plan](#a-query-plan).

`Planned` is a plain struct, like `OpaqueBlob` and `Positioned`. It adds
no method to any other type. The keyset is the argument. Decided on
7 November 2026.

```rust
// Not on `next` yet: `Planned`. Today the chain does this:
// `cipher.encrypt(&user).using(&plan)` and `cipher.query(op, v).on(&plan)`.
let row = Planned::new(&plan, member).encrypt(&keyset).await?;
let member: Member = Planned::new(&plan, row).decrypt(&keyset).await?;

let row = Planned::new(&plan, member)
    .encrypt_with_context(&keyset, Scope::new(tenant).bind(row_id))
    .await?;
```

A serialised `Planned` is the one request every binding sends to the
engine. It has three parts:

- the plan, by reference to one the engine holds, or inline;
- the caller's context parts, in declared order, with their types;
- the value.

The keyset stays outside, as the receiver, so a request never names a
key.

```json
{
  "plan":    "e3b0c442…",
  "context": { "scope": [42], "bind": ["7f3c2a9e-…"] },
  "value":   { "email": "alice@example.com", "age": 35 }
}
```

The engine answers with the stored row, the query term, or the plaintext.
The same shape is a conformance case, with the engine's expected answer
beside it. `contexts()` works on a request before it runs, so a binding
can show the exact context a request will use.

A request is a transport form, never a storage form. The value in it is
plaintext. So a request lives only in a wiped buffer, as the engine
already reads it (`ProtectedRef<[u8]>`), and is never logged or written to
disk. A binding that keeps a request, for a retry say, keeps it wiped.

The request's shape is not part of the stored format. It can change
with the dynamic grammar, and a change to it moves no stored byte.

Below `Planned`, `stack_encrypt::dynamic::record` has the functions that
take a declaration as a frame: `plan_with`, `encrypt_with`, `query`, and
`decrypt_with`. `Planned` calls them. Each takes a `TargetResolver`. The
resolver runs the EQL type that a field names.

On `next`, each program writes its own resolver over `eql-bindings`. In
the target state, `eql-bindings` provides it. See [A ready-made EQL
resolver](#a-ready-made-eql-resolver).

#### A query plan

A query plan is derived from a record plan. It names one field and one
operator, and so the index and the options the query runs under. It is refused where it is made if the field has no index for the
operator.

The record plan does not change. A field's indexes stay the only thing
it declares about queries, so no declaration lists the queries a program
might run.

```rust
// Not on `next` yet: query plans.
let by_email = plan.query("email", Op::Eq)?;   // refused here if no index answers Eq

let q: QueryTerm = Planned::new(&by_email, "alice@example.com")
    .encrypt_with_context(&keyset, Scope::new(tenant))
    .await?;
```

A query plan can be serialised beside its record plan, as
`{"field": "email", "op": "eq"}`. The bytes a query sends to the engine do
not change: the engine already receives the plan, the field, the
operator, and the value. They are grouped differently.

The result on the dynamic path is a `QueryTerm`: the operand bytes, and
the EQL type they bind as, known at run time. A typed query returns the
EQL query type instead, because its marker fixes it.

A typed query from a field marker lowers to a query plan and a `Planned`
value. So the typed form and the dynamic form run the same engine
function. [Query a record field](#query-a-record-field) shows the typed
form.

#### The dynamic field handle

A program whose plan is data uses the same builder through a field
handle. The handle has every operator method. Each one is checked at run
time against the plan, and returns `IndexNotDeclared` when no index
answers it. The handle has no `bind` method either.

```rust
// Not on `next` yet: the dynamic field handle.
let email = plan.field("email")?;
let q: QueryTerm = email
    .eq("alice@example.com")?        // refused here if no index answers Eq
    .scope(tenant)
    .encrypt(&keyset)
    .await?;
```

Rust is the superset. The serialised plan is checked at run time, and a
language generates its own type-checked builder over it where it can. Go
has that today: `stashgen` generates one method per field for each
operator the field's indexes answer, and asks the engine which operators
those are.

A TypeScript binding could get a generated `.d.ts`, and a Python
binding generated `.pyi` stubs. Then an editor and a type checker show
only the operators each field supports. A binding through NAPI or
PyO3 exposes the dynamic path method for method:

```ts
const q = await plan.field("email").eq("alice@example.com").scope(tenant).encrypt(keyset);
q.sqlType;   // "eql_v4.query_text_eq", from the plan, at run time
```

#### Call it from Go

A Go program declares its records with struct tags. The `stashgen`
generator reads the tags, and writes the encrypted type, its functions, and
the declaration it sends to the engine. The examples show how a customer
uses the Go SDK today, on Go `v0.1.0-rc.3`.

The `context=` tag gives the record's context. The tag on each field says
how the field is stored: as a passthrough field, as an EQL type, or with
the indexes it names.

```go
//go:generate go tool stashgen -type User
type User struct {
	_     struct{} `stash:"context=users"`
	ID    int64    `stash:"id,passthrough"`
	Email string   `stash:"email,encrypt_into=TextEq"`
	Name  string   `stash:"name,encrypt_into=TextMatch"`
	Age   int32    `stash:"age,encrypt_into=Integer"`
}

//go:generate go tool stashgen -type Customer
type Customer struct {
	_       struct{} `stash:"context=customers"`
	ID      int64    `stash:"id,passthrough"`
	Profile Profile  `stash:"profile,encrypt_into=JsonSearch(ordered=$.age;$.visits[*].at)"`
}

//go:generate go tool stashgen -type Settings
type Settings struct {
	_     struct{} `stash:"context=settings,opaque"` // sealed as one blob
	Theme string   `json:"theme"`
}
```

A `Cipher` is the client bound to one keyset. `Scope` adds a scope to the
context of every field, such as a tenant ID. `Bind` adds a binding, such
as a row ID. The generated `Encrypt` and
`Decrypt` functions take a slice. They send one ZeroKMS request for each
500 values.

```go
client, err := encrypt.NewClient(ctx)
defer client.Close()
// Not on rc.3 yet: `Scope` and `Bind`. Today `Scope` is `Extend`.
cipher := client.DefaultKeyset().Scope("tenant-42")

encrypted, err := Encrypt(ctx, cipher, people) // []EncryptedUser
opened, err := Decrypt(ctx, cipher, encrypted) // []User

term, err := Fields.Email.Eq(ctx, cipher, "bob@example.com")
// SELECT id, email, name, age FROM users WHERE email = $1::eql_v4.query_text_eq

needle, err := Fields.Profile.Contains(ctx, cipher, map[string]any{"name": "Ada"})
older, err := Fields.Profile.At.Age.Gt(ctx, cipher, 30)
visit, err := Fields.Profile.Elements.Visits.Match(ctx, cipher, encrypt.JSONReadOptions{},
	encrypt.AtPath(Paths.Profile.Visits.Place).Eq("home"),
	encrypt.AtPath(Paths.Profile.Visits.At).Gt(15),
)
```

A field has a query method only for the operators it supports, so an
unsupported query does not compile. The generator asks the engine which
operators each field supports. It does not keep its own copy of the
rules. These generated methods are Go's typed form over the dynamic plan. The
engine checks the plan at run time, and the Go compiler checks the
operators.

Code that `stashgen` wrote for rc.3 compiles and runs against the next
module without being generated again. The generated file builds its
declaration through `gensupport` calls, and the module builds the frames
it sends to the engine. So a change to the request's shape is a change
inside the module. A program generates again only to adopt a new
declaration, such as a scope or binding on a field. The generator keeps
its output identical for unchanged input, so an upgrade alone does not
change a committed `*_stash.go` file.

Two parts of the target state are not in Go yet:

- A Go program cannot set match options.
- A Go program cannot open one child of a JSON node, bound to its parent.

Both are in [Remaining work](#remaining-work).

### Rules in the target state

#### The stored format stays compatible with Go rc.3

The Go customer already uses Go `v0.1.0-rc.3`. So the data that rc.3
writes must stay readable and searchable. The stored format is everything
that Stack Encrypt writes to the database:

- ciphertexts, with their envelopes and headers;
- search terms;
- the entries of JSON documents;
- the declaration names that a stored row depends on.

The baseline is the tag `languages/golang/v0.1.0-rc.3`, at commit
`114e08448`. It includes the `eql-v4-install.sql` bundle attached to that
release.

The code and the APIs can still change in ways that break callers. A change
to the stored format must keep rc.3 data readable and searchable, or add a
new format version beside it. See [Changes that would alter the stored
format](#changes-that-would-alter-the-stored-format).

#### Context and AAD

The context is the data that a ciphertext is tied to, such as a column
name or a row ID. The field's declaration supplies part of the context,
such as `users/age`. The caller can supply the rest, such as a row ID.

Stack Encrypt uses the context in three ways:

1. **To derive the data key.** Stack Encrypt sends the context to ZeroKMS
   as a text descriptor, such as `users/age`. ZeroKMS needs the same
   descriptor to derive the key again.
2. **To build the AAD of each ciphertext.** The AAD is data that
   encryption checks without encrypting it. Stack Encrypt builds it from
   the context and the place of the value in its record. The AAD also
   includes the format version, the keyset ID, and the key tag.
3. **To derive the search terms** for the field.

A different context gives a different key and a different AAD, so
decryption fails.

A parameter that takes the caller's context is named `context`. The name
`aad` is used only for a value that is an AAD. Some public methods do not
follow this rule yet. See [Name context parameters
`context`](#name-context-parameters-context).

Sources: the module documentation of `packages/stack-encrypt/src/cipher.rs`
describes the descriptor and the AAD. The module documentation of
`packages/stack-encrypt/src/target/context.rs` describes the search terms.

#### Query context and stored context

Decided on 7 November 2026. Every part of a context is a scope or a
binding. The declaration supplies the first scopes: the record name, then
the field's context name. The caller supplies the rest.

- **The query context** is all the scopes: the declared ones, then the
  caller's. Search terms derive under it. A query supplies the caller's
  scopes, and matches every row stored under the same query context.
- **The stored context** is the query context followed by the bindings.
  The data key and the AAD derive under it.

A field's **context name** is the last declared scope. It is the field's
name by default. It can be pinned when the Rust field is renamed, so that
stored data keeps opening.

The context name is always the last declared scope, so two fields of one
record never share a context. If they did, they would share a key and an
AAD, and a ciphertext copied between the two columns would open. ADR-0006
records this.

A part of the context is one of two kinds. The declaration says which,
and fixes the order: the scopes first, then the bindings.

| Kind of part | Verb | Example | In the query context | In the descriptor | In the AAD | Verified by |
| --- | --- | --- | --- | --- | --- | --- |
| Scope | `scope` | A record name, a field's context name, or a tenant ID | Yes | Yes | Yes | ZeroKMS and the AEAD |
| Binding | `bind` | A row's UUID | No | Yes | Yes | ZeroKMS and the AEAD |


The words were decided on 7 November 2026. A caller scopes a value with a
scope. A scope narrows the data and the queries over it. A caller binds a
value with a binding. A binding ties the ciphertext to its row and leaves
the queries as they are.

"Extend" and "extension" are no longer used. Go `Extend` becomes `Scope`, with
`Extend` kept as a deprecated alias until Go 0.1.0. `Bind` is added to
Go.

A part is a scope unless the declaration marks it as a binding, because
that is what Go rc.3 writes. A binding can be stored in the row as a context field,
so the reader takes it from the row. ZeroKMS logs the descriptor at every key retrieval, so every scope and
binding is in the access log. The descriptor has a length limit. It is also sent to ZeroKMS, so the
part leaves the customer's system.

ZeroKMS version 2 is planned to remove the limit and to encrypt the
access log.

A caveat added by [tag
refinement](2026-11-07-stack-encrypt-tag-refinement.md) is not a part of
the context. ZeroKMS verifies it. It is in neither the query context
nor the AAD.

The use case is access intelligence. Each value is bound to its row by a
client-generated UUID, and a query by column or by tenant still finds it.
The facts of a row's writing, such as the address it came from, are
caveats, not bindings.

#### A developer can see the context

Decided on 7 November 2026. A wrong context is silent: a query matches
nothing, or a row opens somewhere it should not. So every declaration
and every call can show the context it uses, before any key is fetched.

```rust
// Not on `next` yet: `contexts()` and `context()`.

// For a declaration: each field, its query context, and its stored
// context, with a placeholder for every part the caller supplies.
println!("{}", EncryptedUser::encryption_plan().contexts());
// email
//   query context:  users / email / {tenant: u64}
//   stored context: users / email / {tenant: u64} / {row: Uuid}
//   search terms:   under the query context

// For a call: the exact context, with the caller's values filled in.
let call = EncryptedUser::EMAIL.eq("alice@example.com").scope(42_u64);
println!("{}", call.context());
// query context:  users / email / 42u64
```

The output shows each part's type, because `7u64`, `7i64`, the text `7`,
and the bytes `37` are four different contexts. The descriptor that
ZeroKMS logs is coarser, so it is not enough on its own. A call's context
can include the caller's values, such as a tenant ID or an IP address.
The plan form shows placeholders instead, so it is the one to put in
logs.

The same output serves a unit test. A testing feature of the crate gives assertions over it. A developer can
pin the context of a field or a call, and the build fails when it
changes. The Go module has the same
assertions, in a testing package.

```rust
// Not on `next` yet: the `testing` feature and `assert_context!`.
#[cfg(test)]
mod tests {
    use stack_encrypt::testing::assert_context;

    #[test]
    fn email_is_scoped_to_the_tenant_and_bound_to_the_row() {
        assert_context!(
            EncryptedUser::EMAIL,
            query = ["users", "email", scope::<u64>()],
            stored = ["users", "email", scope::<u64>(), bind::<Uuid>()],
        );
    }
}
```

#### Tag refinement

Tag refinement adds a caveat, a named fact, to the ZeroKMS key tag of a
stored value. The value is then tied to its row and to the facts of its
writing. Its context, its AAD, and its queries do not change.
ZeroKMS verifies the caveats when it returns the key, and logs them.
That log is where access intelligence comes from.

[Tag refinement and caveats](2026-11-07-stack-encrypt-tag-refinement.md)
has the design.

```rust
// Not on `next` yet: `refine` and `caveats`.
let sealed: TextEq = sealed
    .refine("written_from", request.ip())?
    .refine("created_at", now())?;
let body: String = String::decrypt_from(sealed, &keyset).await?;
```

```sql
-- In a trigger, once the primary key is known.
NEW.body := eql_v4.refine_tag(NEW.body, 'row_id', NEW.id::text);
```

#### Other rules

- **Rust and Go behave the same.** Every built-in capability has the same
  meaning and the same stored bytes in Rust and in Go. The conformance
  profiles test this. A custom Rust query stage can be Rust-only. It is
  then marked as not portable.
- **Checks run before keys are used.** Every check that needs no key runs
  before Stack Encrypt asks ZeroKMS for a key, or loads an index key.
- **Encryption wipes an owned plaintext.** `encrypt` and `encrypt_into` wipe an
  owned plaintext, including when they fail. They only read a borrowed
  plaintext, so the caller is responsible for wiping it. Stack Encrypt
  wipes every copy it makes. A decrypted value is an ordinary owned value.
  The caller is responsible for wiping it.
- **Context is passed by reference.** A method that takes a context
  borrows it while the request runs. So a program can use one context for
  a write, a query, and a read without cloning it. An owned context also
  works.
- **Context is explicit.** A declaration lists the parts the caller must
  supply, each with its kind and type. A part that is not declared is
  refused. A declaration can mark a part as optional. That is the rare
  case, because a query that omits an optional part matches nothing and
  gives no error. Stack Encrypt does not use a type's `Default`
  implementation to decide. Decided on 7 November 2026.
- **The dynamic grammar can declare required parts too,** with their kind
  and type, so the Go generator can require them when it generates the
  code. Its default stays "any part or none", because Go rc.3 callers use
  that, and the stored bytes are the same either way.
- **`encrypt` or `encrypt_into`.** `encrypt_into` is for the case where
  the caller names the output type. `encrypt` is for the case where a
  marker or a plan fixes it: a query from a marker, or a `Planned` value.
  `keyset.encrypt(value)` and `value.encrypt_into::<T>` follow this rule
  on `next` today.
- **Rust is the superset.** The plain serialised plan is checked at run
  time by the engine. A language generates its own type-checked builder
  over it where it can, as `stashgen` does for Go. A capability lands in
  Rust first, and the dynamic grammar adopts it by an explicit change.
- **Each element of a collection stands alone.** Each element has its own
  data key. Each element is authenticated on its own.
- **Match text is analysed by one pipeline.** A typed configuration can
  use any stage, including a customer's own. A serialised plan can name
  only the closed dynamic subset, and every reader runs exactly the
  stages it names.
- **Order terms do not answer equality.** An order-revealing encryption
  (ORE) term does not answer an equality query. A field that needs both
  declares both indexes.

## Remaining work

The work is in the order that the customer needs it. The Go customer
release comes first, then the stored format, then the Rust API, then the
query engine. The crate moves and the key provider work come after the
customer release.

### 1. The Go customer release

#### Finish the specification around the conformance profiles

- **What to build.** JSON Schema files for declarations, requests, and
  responses. Protocol version identifiers. A release compatibility matrix.
  Tests that exchange new JSON values between languages.
- **Why.** The specification lets another language implement the dynamic
  interface and get the same results.
- **Done already.** Conformance profiles exist for these areas (#1460,
  #1461, #1462, #1469, #1491, #1492, #1493):
  - the declaration grammar;
  - runtime values and value kinds;
  - stored reads and context;
  - queries;
  - EQL and JSON;
  - the lifecycle of values and keys.

  The profiles are experimental. They do not certify a whole SDK.
- **Finished when** these are all true:
  - the profiles are no longer experimental;
  - the schemas exist;
  - the version identifiers exist;
  - the compatibility matrix lists rc.3.

#### Open one child of a JSON node, bound to its parent

- **What to build.** An operation that opens one child value of a JSON
  node, and checks that the child belongs to that parent. This is J17 in
  the [JSON operations](2026-10-25-stack-encrypt-json-operations.md)
  document. J14 is the matching SQL.
- **Why.** Today a program must read and open the parent's whole subtree to
  see one child.
- **Done already.** Nothing.
- **Finished when** Go can open one child, and the `eql-json-v1`
  conformance profile covers it.

#### Configurable match options in Go

- **What to build.** Match options that a Go program can set, as the
  stages of the analyzer's dynamic subset: the tokeniser, the filters,
  and the n-gram length. Issue #1112 tracks the part in the generator.
  [Match configuration: one analyzer](#match-configuration-one-analyzer)
  has the design.
- **Why.** Today Go uses only the default match options.
- **Done already.** Words of two letters can be searched (#1397).
- **Finished when** a Go field can declare match options, and its queries
  use the same options as its stored terms.

#### Freeze the release candidate

- **What to build.** Fixed test vectors for the JSON storage format and the
  matching EQL bundle, recorded as the rc.3 baseline.
- **Why.** The vectors make sure that later work keeps rc.3 data readable
  and searchable.
- **Done already.** The conformance jobs run in CI.
- **Finished when** CI fails on any change to the stored bytes of rc.3
  data.

#### Replace the temporary Vitamin C pins in Go

- **What to build.** Replace the Go module's pseudo-versions of Vitamin C
  with released module tags.
- **Why.** A final Go release cannot depend on unreleased commits.
- **Done already.** Prereleases can keep the pins, so rc.3 uses them.
- **Finished when** the release workflow accepts a final version.

### 2. The stored format

#### Changes that would alter the stored format

Each change below would alter the stored format if it were built as first
planned. Each one must keep rc.3 data readable and searchable, or add a new
format version beside it.

| Planned change | What it would alter |
| --- | --- |
| Search terms under the query context | A new form of search term, beside the rc.3 form, where terms derive under every part |
| Text encodings as field targets (Base64 and Base85) | How a ciphertext is written as text in a column |
| The `SealedValue` envelope and the JSON header version | The offsets of the key tag, and header version 1, which rc.3 writes |
| Configurable match options | The terms of columns written with the rc.3 defaults |

#### Opaque blobs

- **What to build.** `OpaqueBlob<T>` in Rust, using Vitamin C's storage
  profile. The storage profile is Vitamin C's versioned byte format for an
  opaque value that is stored.
- **Why.** Go rc.3 already writes opaque structs in this format, so Rust
  must read them.
- **What the blob guarantees.**
  - The stored bytes are one sealed leaf under one data key.
  - The envelope contains what is needed to fetch the key again. The
    caller never saves an initialisation vector or a key tag separately.
  - A different context fails to open the blob.
  - Stack Encrypt owns the matching encode and decode pair.
  - The format's identifier and version are inside the encrypted payload,
    so decoding never guesses a codec from unauthenticated metadata.
  - The blob reuses the outer ciphertext envelope. Its payload is a new,
    explicit format, and never reinterprets bytes sealed earlier.
  - A change to the application's own type still needs explicit handling.
    A codec version does not migrate it.
- **Constant time is a requirement to investigate, not a property.**
  Strings, lengths, enum variants, errors, allocations, and the Serde code
  a user writes all add work that depends on the values. So arbitrary
  `Serialize` and `Deserialize` cannot be constant time as a whole. Before any such claim, define three things. Which types are supported.
  Which shape and length information is public. Which limits apply to
  custom implementations.
  Authentication finishes before the blob is decoded. Check: `serdect`,
  already a dependency, for its exact guarantees and whether any of them
  apply to the blob codec. Its guarantees for encoding bytes do not extend
  to arbitrary objects.
- **Done already.** Go writes and reads the format (#1369, #1370). #1503
  adds `OpaqueBlob`, and is in review.
- **Finished when** Rust and Go each open blobs that the other wrote, and
  the conformance profiles cover it.

#### Tag refinement: the work

Decided on 7 November 2026. [Tag refinement and
caveats](2026-11-07-stack-encrypt-tag-refinement.md) has the design.

- **What to build.**
  - `refine(name, value)` on every EQL type and on a JSON document. It
    computes `HMAC(tag, PAE(name, value))`, stores the result as the tag,
    and appends the caveat to the payload's list.
  - `eql_v4.refine_tag(payload, name, value)`, the same in SQL, for a
    trigger that refines with the generated primary key. The tag is
    inside the ciphertext envelope, so this needs the envelope layout from
    [key tag extraction](#typed-text-encodings-and-key-tag-extraction),
    for writing as well as reading.
  - `refine` and `caveats` as operations of the dynamic interface, so Go
    can refine a value before it writes the row, and read the caveats.
  - `caveats()` on a stored value, to read the list without decrypting.
  - The optional `caveats` list in every EQL payload type.
  - On decrypt, send the stored tag and the caveats to ZeroKMS, and
    rebuild the leaf AAD from the original tag it returns.
- **Why.** Access intelligence needs each value tied to its row and to
  the facts of its writing. A caveat does that without touching the
  context, the AAD, or the queries.
- **Stored format.** The list is present only once a caveat is added, so
  a payload without one is the rc.3 form. The change is additive.
- **Depends on ZeroKMS.** The read path needs the retrieve-key request to
  carry the caveats, and the response to return the original tag. That
  work is outside this repository.
- **Done already.** `Ciphertext::key_tag` reads the tag in Rust (#1404).
  The leaf AAD already binds the original tag.
- **Finished when** these are all true:
  - the example in the tag refinement document round-trips through a
    trigger, in Rust and in Go;
  - a changed caveat, or a changed tag, is refused by ZeroKMS;
  - the EQL conformance profile covers the `caveats` list.

#### Typed text encodings and key tag extraction

- **What to build.**
  - `to_base64` and `to_base85` methods on `Ciphertext`. They return the
    existing `Base64Text` and `Base85Text` types, not `String`.
  - Field targets that store a ciphertext as text. Their working names are
    `Base64Ciphertext` and `Base85Ciphertext`. Each one checks both the text
    and the envelope.
  - A SQL and PL/pgSQL function that reads the ZeroKMS key tag from a stored
    ciphertext. It must check the version and the lengths before it reads.
- **Why.** Some columns store ciphertext as text. SQL needs to read the key
  tag for tag refinement.
- **Limits.** PostgreSQL can decode Base64, but not Base85. So SQL can read
  the key tag from Base85 text only if we supply a decoder. Reading the tag
  does not authenticate it.
- **Done already.** `Ciphertext` is stored as bytes, and Serde writes it as
  Base64. `Ciphertext::key_tag` reads the tag in Rust (#1404).
- **Finished when** the methods and targets exist, and Rust, Go, and SQL
  test vectors show the same key tag for the same stored value.

### 3. The Rust API

#### Record derives

- **What to build.** The `EncryptTarget` and `DecryptSource` derives for
  records, with passthrough fields, nested records, and stored context.
  The existing `from` attribute renames a source field. It is extended to
  passthrough fields.
- **Where the derive lives.** On the encrypted struct. That struct is
  the declaration. Each field's type says how the field is stored, and a
  field's indexes come from its target type, such as `SearchableEmail` or
  `IntegerOrd`. The plaintext struct carries no attributes, so it can
  come from another crate. Decided on 7 November 2026, as area four of
  the query design review. The query artifact's derive on the plaintext
  struct generates the encrypted struct. It is not planned. It could
  return later as a convenience that produces this form.
- **Two safety rules.** A plaintext field with no counterpart in the
  encrypted struct is a compile error, so no field is dropped silently.
  A field is stored in the clear only where `passthrough` is written on
  it. Together they give what the artifact's "encrypted unless marked
  plaintext" default gives, stated on the struct a developer reads.
- **Why.** The derives give the [record example](#encrypt-a-record). The
  encrypted struct is what goes in the row, so a developer reads the
  stored shape, and adds `Serialize` or `sqlx` derives, in one place.
- **Done already.** One value (#1404) and collections (#1501). #1504 adds
  the record derives, and is in review. `#[stash(from = "..")]` already
  renames the source field of an encrypted field
  (`stack-encrypt-derive/src/attrs.rs`).
- **Finished when** these are both true:
  - a mixed record, with passthrough and encrypted fields, and a searchable
    record round-trip as tests;
  - a `tests/ui` case shows that a plaintext field with no counterpart
    fails to compile.

#### EQL types as fields

- **What to build.** EQL types such as `TextEq` and `JsonTreeDocument` as
  field types of the Rust record derive. In Rust today, an EQL type works
  only on its own, through the older structural API, with a
  `NonEmpty<Identifier>` context. The EQL types do derive the structural
  `EncryptFrom` and `DecryptInto`. A record still cannot use them as
  fields.
  A record with a `TextEq` field, built against `next` on 7 November 2026,
  fails with three errors. `NonEmpty<Identifier>` and
  `ExpectedContext<Identifier>` do not implement `From<CallerContext>`, and
  the record derive gives each field a `CallerContext`.
- **The smallest fix.** Convert a `CallerContext` of two parts into an
  `Identifier`, with the table first and the column second. `Identifier`
  already gives the same context as that pair, so the stored bytes do not
  change.
- **Why.** This gives the [EQL field example](#store-a-field-as-an-eql-type)
  and the [JSON example](#encrypt-a-json-document).
- **Done already.** The dynamic interface supports EQL fields, so Go
  records use them today. A field there names its EQL type, and the engine
  looks the type up by name through `eql-bindings` (the `TargetResolver`
  in `dynamic/record.rs`). `Identifier` already gives the same context as
  the `(table, column)` pair that a record derive builds.
- **Finished when** these are all true:
  - a Rust record with EQL fields encrypts, decrypts, and queries through
    the new API;
  - it writes the same bytes as a Go record with the same declaration.

#### A ready-made EQL resolver

- **What to build.** A `TargetResolver` in `eql-bindings`, behind its
  `targets` feature. It runs the EQL type that a field of a dynamic
  declaration names, for encryption, decryption, and queries.
- **Why.** On `next`, every Rust program that uses
  `stack_encrypt::dynamic::record` with EQL types writes its own resolver.
  The EQL tests and the Go guest each have a copy.
- **Done already.** The functions it calls exist in `eql-bindings`:
  `encrypt_with`, `decrypt`, and `query` in `v4::targets` and
  `encryption::targets`.
- **Finished when** the tests and the Go guest use the resolver from
  `eql-bindings`, and their own copies are deleted.

#### Static JSON queries

- **What to build.** One method for each kind of JSON query on a JSON
  document's field marker. The methods are `contains` and `contained_by`;
  `at(path)` with the comparison operators; `elements(path)` with its
  member conditions; `predicate`; and `children`. Each method builds the input type the
  dynamic interface already has for that operator, and `encrypt(&keyset)`
  returns the EQL query type. The marker supplies the column and the
  options. The dynamic parser keeps reading into the same input types, so
  there is one definition of each input.
- **Names.** The method names above are proposals. The operand types
  `Contains`, `AtPath`, `ElementMatch`, `Predicate`, and `Children` that
  this plan proposed earlier are retired, on 7 November 2026.
- **Why.** On `next`, a Rust program needs a plan for any JSON query, and
  needs the dynamic interface for element match, predicates, and children.
  Go already has typed methods for these.
- **Done already.** The input types and their parsing rules, as private
  types in `stack_encrypt::dynamic::json_query`. Typed containment and
  comparison at a path, through a plan (`op::Contains`, `op::AtPath`). The
  EQL query types exist in `eql-bindings`.
- **Finished when** these are both true:
  - the [JSON query example](#query-a-json-document) compiles;
  - an order query on a path the options do not order is refused before
    any key is fetched.

#### Field markers and the encryption plan

Decided on 7 November 2026, as difference six of the context artifact
review.

- **What to build.** The derive emits one marker for each field, as an
  associated constant such as `EncryptedMember::EMAIL`. The marker has
  the field's name, its plaintext type, its accessor, and its index list. The marker
  is the `FieldRef` the plan builder takes, and the value a query starts
  from. The index list is what lets the marker offer one method per
  operator, resolved at compile time. The derive also emits
  `encryption_plan()`. It returns the record's `Plan`, built once through
  the plan builder with the markers as its arguments. A query from a
  marker lowers to a [query plan](#a-query-plan). Typed Rust option
  factories, and the same options read from data in the dynamic
  interface.
- **Why.** A query must use the same declaration as the stored values. The
  caller must not write a second plan by hand. One marker type serves the
  builder and the query, so the derive lowers to the builder with no
  second mechanism.
- **Done already.** `FieldRef` and `pick` exist in `plan/field_ref.rs`.
  The derive already lowers a structural record to the builder. Queries
  work through a plan written by hand: `cipher.query(op, value).on(&plan)`.
  `Answers` on a target type is today's compile-time lookup of the index
  for an operator. The marker's index list extends it to a record field.
- **A hand-built plan gets the same handles.** A typed Rust program
  that writes its plan by hand names the plaintext type once,
  `Plan::<Member>::context("members")`, so every `pick!` is checked
  against it. `build()` returns the plan and one marker per field, in
  declaration order, of the same type the derive emits. So a hand-built
  plan and a derived one query the same way, with the same compile-time
  checks. The builder keeps the context review's shape,
  `Plan::context(..).fields()`, with the field verbs after it. Decided on
  7 November 2026, as area three of the query design review.

  ```rust
  // Not on `next` yet: markers from `build()`, and `Plan::<Member>`.
  let (members, (email, age)) = Plan::<Member>::context("members")
      .fields()
      .encrypt_index(pick!(email), (Equality, Match::<EnglishSearch>::new()))
      .encrypt_index(pick!(age), (Equality, Ore))
      .build()?;

  let q: TextEqQuery = email.eq("alice@example.com").encrypt(&keyset).await?;
  email.gt("alice@example.com")   // error: no order index on this field
  ```

- **Cannot fail.** `build()` refuses a repeated field name or a shared context name.
  The derive sees every field, so it refuses those at compile time, and
  `encryption_plan()` returns `&'static Plan`, not a `Result`. The
  hand-written builder keeps the runtime check. The dynamic grammar needs
  it.
- **Later.** A compile-time duplicate-field check for the hand-written
  builder, through a type-level list of markers, stays a follow-up, as the
  artifact says.
- **Finished when** these are all true:
  - the [marker example](#query-a-record-field) compiles;
  - the compile-fail cases in `tests/ui` cover an operator the field's
    indexes do not answer;
  - tests show that a query cannot run without its plan or its required
    context.

#### A request: `Planned` and its serialised form

Decided on 7 November 2026, as area one of the query design review.

- **What to build.**
  - `Planned::new(&plan, value)`, with `encrypt`, `encrypt_with_context`,
    `decrypt`, and `decrypt_with_context`, for a record under a record
    plan and a query value under a query plan.
  - The request format: the plan by reference or inline, the context
    parts in declared order with their types, and the value. The engine
    reads it from a wiped buffer and answers with the row, the query term,
    or the plaintext. The keyset is never in it.
  - Query plans: `plan.query(field, op)`, refused where it is made if no
    index answers the operator, and serialisable beside the record plan.
  - The dynamic field handle, `plan.field(name)`, with every operator
    method checked at run time.
  - `QueryTerm` as the dynamic path's query result: the operand bytes and
    the EQL type they bind as.
  - `contexts()` on a request, before it runs.
- **Why.** One shape for every binding. A binding then has no logic of
  its own, so it cannot drift. The same shape is a conformance case. A plan
  that is data is checked at run time, and a language adds its own typed
  builder over it where it can.
- **Rules.** A request is a transport form, never a storage form, because
  its value is plaintext. It is never logged or written to disk. Its shape
  is not part of the stored format.
- **Done already.** The guest already sends the engine a plan frame, then
  a value frame for each call, through `plan_with`, `encrypt_with`,
  `query`, and `decrypt_with` in `dynamic::record`. The request names and
  groups what those functions already receive.
- **Finished when** these are all true:
  - every case in the conformance corpus is a request with the engine's
    expected answer beside it;
  - a Go program generated for rc.3 runs against the module that sends
    requests, without being generated again;
  - the chain in `plan/chain.rs` is gone.

#### Context from fields and from the caller

- **What to build.** One mechanism for where a field's context comes
  from: the plan builder. The derive and the dynamic grammar lower to it.
  A field's context comes from one of three sources:
  - the declaration, through `Plan::context(record_name)`, the only way
    to put the record name in a plan, with each field's context name
    after it;
  - a row field stored unsealed in the record, so the reader takes it
    from the row. A reader may pass it on decrypt to check it;
  - the caller, on every write, query, and read, as a scope or a
    binding.

  Parts are separate and ordered: the declared scopes, the caller's
  scopes, then the bindings. Grouping is available inside one part. Nothing
  is read from the plaintext on one side and from the caller on the
  other. Decided on 7 November 2026, with the context artifact.
- **Why.** A program must never need to open a ciphertext to learn the
  context that opens it. One mechanism keeps Rust and Go writing the same
  bytes.
- **Scenarios.** The [context
  examples](2026-10-24-stack-encrypt-context-examples.md) are the
  acceptance matrix: eight scenarios, from a static context alone to an
  EQL type with its column as the context. Two earlier scenarios were removed, because
  each sealed a value that was also another field's context, so nothing
  could open without the plaintext.
- **Done already.** The order in which parts are joined is fixed and
  tested in Rust and Go (#1491). The context inputs `RequiredContext`,
  `NoCallerContext`, and `OptionalContext` exist (#1404). #1504 adds
  `ContextExtension` and `ExpectedContext`, and is in review.
  `ContextExtension` is renamed for the scope vocabulary, in the naming
  review. The plan builder's
  `.context(..)` and `.context_field(..)` and the derive's
  `#[stash(context_field)]` are the forms this replaces.
- **Required parts.** A Rust declaration lists the parts the caller must
  supply, with kind and type. The context artifact proposed that for its
  one kind of part; this extends it to bindings. An undeclared part is refused. Optional is
  the marked case. The dynamic grammar can declare required parts; its
  default stays "any", and the Go generator requires a declared part at
  compile time. `RequiredContext`, `OptionalContext`, and `NoCallerContext`
  (#1404) are the three states this keeps.
- **Finished when** these are both true:
  - all eight scenarios run as tests in Rust and Go, through the
    builder;
  - a Rust call with an undeclared part fails to compile.

#### Query context and stored context

- **What to build.** The binding kind of part, in the declaration and in
  the dynamic grammar. Search terms derive under the query context, and the
  key and the AAD under the stored context. A binding can be a context
  field stored in the row. The order is fixed: the scopes, then the
  bindings.
- **Why.** Access intelligence needs each value bound to its row, and
  found by a column or tenant query. The facts of a row's writing are
  [caveats](2026-11-07-stack-encrypt-tag-refinement.md), not bindings. [Query context and stored
  context](#query-context-and-stored-context) has the rule.
- **Vocabulary.** The Rust chain's `.extend(..)` is removed; the context
  argument carries the scopes and bindings instead. Go `Extend` becomes
  `Scope`, with `Extend` as a deprecated alias until 0.1.0. `Bind` is added
  to Go. The context contract and the conformance README say "scope"
  instead of "extension". The frozen vectors do not change, because no key
  on the wire names the operation.
- **Done already.** Nothing. Today every part is in both contexts.
- **Finished when** these are all true, in Rust and in Go:
  - a record with a binding row ID encrypts;
  - a column query finds it;
  - it fails to open under another row ID;
  - the stored bytes of a record with no binding are unchanged.

#### One context argument, and paired entry points

Decided on 7 November 2026, as differences two and five of the context
artifact review. The rules are in the target state. See [the context
argument](#other-rules) and [`Planned`](#a-request-planned). This item
records only the work.

- **What to build.** The `Scope` and `Bind` value types, with the order
  fixed by type. The paired entry points on the typed API, and `Planned`
  with `encrypt`, `encrypt_with_context`, `decrypt`, and
  `decrypt_with_context`. `Planned` replaces the chain in `plan/chain.rs`,
  and with it every chain state and its `.context(..)`, `.extend(..)`,
  and `.keyset(..)`. A stored part passed on decrypt is checked against
  the row before any key is fetched. That check is what `ExpectedContext`
  does today. It stops being a public type.
- **Why.** The typed API already pairs its entry points (#1404). A value
  for the context reads the same on both layers. A builder state for the
  context, and a part added later in a chain, are the mistakes the context
  artifact describes.
- **Done already.** The scalar pairs (#1404). The record pairs, in #1504.
  The chain's `encrypt`, `query`, and `open`, with `.extend(..)` and
  `.context(..)` on several states. `Planned` replaces them.
- **Order of calls.** The keyset is chosen first. It is the receiver of
  the scalar entry points, `keyset.encrypt(..)`, and the argument of every
  other verb, `encrypt(&keyset)`. There is no `using` method.
- **Rename.** `Scope<'a, K>` in `dynamic::record` and `CipherScope` in the
  owned API both mean the cipher a call runs under. Both are renamed in
  the naming review, so that `Scope` means a part of the context.
- **Finished when** these are all true:
  - the examples in [Target state](#target-state) compile;
  - the compile-fail cases in `tests/ui` cover a binding in a query, and
    a scope after a bind;
  - `plan/chain.rs` is gone, and `Planned` runs every test it ran.

#### Show the context

Decided on 7 November 2026.

- **What to build.** Two ways to see a context before any key is fetched:
  - `contexts()` on a `Plan`, listing each field's query context and
    stored context, with a typed placeholder for every caller-supplied
    part. The derive's `encryption_plan()` gives it to every record, and
    a hand-built plan has it too.
  - `context()` on a prepared call. It gives the exact query context and
    stored context the call will use, with the caller's values filled in.
    Each part shows its type. A call with no context shows an empty
    context, as such.

  Both render through the same code that derives the key descriptor and
  the AAD, so what a developer sees is what the engine uses. The dynamic
  interface has the same two forms. So `stashgen` can print a Go record's
  contexts. A Go call can show its context.
- **Assertions for tests.** A `testing` feature of `stack-encrypt`, with
  `assert_context!` over a field marker, a plan, or a prepared call. It
  compares the query context and the stored context, with types, against
  what the test states, and names the first part that differs. The Go
  module has the same in a testing package, such as `encrypttest`, so a
  Go test can pin a record's contexts the same way. Both read the same
  output as `contexts()` and `context()`, so a test and a log never
  disagree.
- **Why.** A wrong context loses data silently. A query under the wrong
  context matches nothing and gives no error. A developer who cannot see
  the context cannot find the mistake. A test that cannot state the
  context cannot catch a change to it.
- **Done already.** `Descriptor` renders a context as text, and
  `ContextMismatch` reports the stored descriptor. Neither shows the
  types, and neither is reachable from a plan or a call.
- **Finished when** these are all true:
  - a test pins the output of `contexts()` for each of the [context
    scenarios](2026-10-24-stack-encrypt-context-examples.md);
  - a conformance case shows that Rust and Go print the same context for
    the same declaration;
  - the [context scenarios](2026-10-24-stack-encrypt-context-examples.md)
    each carry an `assert_context!` test, in Rust and in Go.

#### Name context parameters `context`

These public methods in `packages/stack-encrypt/src/cipher.rs` take a
context through a parameter named `aad`:

- `KeysetCipher::encrypt_tree`;
- `KeysetCipher::decrypt_tree`;
- `StackCipher::decrypt`;
- `PendingStackCipherText::plan`, whose bound is Vitamin C's `IntoAad`;
- `PendingStackCipherText::seal`;
- `PendingStackCipherText::into_pending`.

Rename each parameter to `context`. This breaks the Rust API only. It does
not change the stored format. Renaming Vitamin C's `IntoAad` trait is a
follow-up in Vitamin C. The Go SDK and the dynamic interface have no public
parameter named `aad`.

#### Pass context by reference

- **What to build.** Let every method that takes a context accept a
  borrowed context, such as `&Identifier`. The request borrows the context
  for as long as it runs. `eql-bindings` needs `IntoContext` for
  `&Identifier`.
- **Why.** On `next`, every context is taken by value. A program that uses
  one column context for a write and a query must clone it for each call.
- **Done already.** Stack Encrypt implements `IntoContext` for `&Label`.
  The context inputs, such as `RequiredContext`, still need an owned value.
- **Finished when** the examples in this plan pass a context by reference,
  with no clone, and compile.

#### Encrypt borrowed values

- **What to build.** Let `encrypt` and `encrypt_with_context` accept a
  borrowed single value, such as `&str`, `&[u8]`, or `&i64`. Keep the
  current behaviour for an owned value.
- **Why.** A program that encrypts a string literal must write
  `"secret".to_owned()` on `next`. The copy adds nothing, because a literal
  cannot be wiped.
- **How.** The engine already reads an owned value through a borrow
  (`ScalarRef` in `scalar.rs`). But `OpaqueEncode` requires `Zeroize` and
  `'static`, so `&str` does not meet it. A borrowed value needs its own
  bound, and the request borrows the value for as long as it runs.
- **Done already.** Owned single values (#1404).
- **Finished when** `keyset.encrypt("secret")` compiles, and a test shows
  that Stack Encrypt wipes its own copies of a borrowed value.

#### A public `JsonPlaintext`

- **What to build.** A public `stack_encrypt::json::JsonPlaintext`, with:
  - `From<serde_json::Value>`;
  - `parse(&str)`, with the strict checks on JSON input;
  - `value()`, to read the document by reference.

  Encryption into a JSON target accepts a `JsonPlaintext`, or a borrowed
  `&serde_json::Value`. Decryption returns a `JsonPlaintext`.
- **Why.** The new traits need a plaintext that can be wiped.
  `serde_json::Value` does not implement `Zeroize`. Rust's orphan rule
  stops this repository adding that, so a wrapper is needed. A program
  that already has a `serde_json::Value` must not have to print it and
  parse it again.
- **Done already.** `stack_encrypt::dynamic::json::JsonPlaintext` wraps a
  `serde_json::Value`, and wipes it when it is dropped. It is part of the
  dynamic interface. It has only `value()`. The strict parser exists as
  `stack_encrypt::json::parse_text`.
- **Finished when** the JSON examples in this plan compile, and a test
  shows that a dropped `JsonPlaintext` leaves no plaintext behind.

#### Constructors for `IdentifiedBy`

- **What to build.** Two constructors that select a keyset:
  - `IdentifiedBy::name(&str)`. It checks the name, so it returns a
    `Result`;
  - `IdentifiedBy::uuid(Uuid)`.
- **Why.** On `next`, selecting a keyset by name needs
  `IdentifiedBy::Name("acme".to_string().into())`. The `.into()` converts
  the `String` into the `Name` type. That conversion does not check the
  name. Only `Name::try_from(&str)` checks it: at most 64 characters, not
  empty, and only `A-Z a-z 0-9 _ - /`.
- **Where.** `IdentifiedBy` and `Name` are in the `zerokms-protocol` crate.
  The `cipherstash-suite` repository publishes that crate. Rust allows inherent methods only in
  the crate that defines the type. So the constructors go in
  `zerokms-protocol`. Stack Encrypt re-exports `IdentifiedBy` from
  `stack_encrypt::kms`, so callers get them through that path.
- **Done already.** `StackCipher::keyset` takes `impl Into<IdentifiedBy>`,
  and `IdentifiedBy` implements `From<Uuid>` and `From<Name>`.
- **Finished when** a released `zerokms-protocol` has both constructors,
  and the examples in this plan compile.

#### Authenticate the order and length of a collection

- **What to build.** A wrapper type, `Positioned<Vec<T>>`, that seals each
  element under its position and the length of the collection. Opening
  checks both, so a swapped, dropped, or added element fails. The dynamic
  interface needs the same form, so that Go can declare it.
- **Why.** The default collection does not authenticate order or length,
  because a database returns rows in any order. Some callers store a
  sequence whose order matters, such as the steps of a workflow. ADR-0010
  says this is opt-in, by type. It does not exist yet.
- **Done already.** Nothing. The default collection (#1501).
- **Finished when** a test shows that each of swapping, dropping, and
  adding an element fails to open, in Rust and in Go.

#### A derive for a single-value type

- **What to build.** `#[derive(Scalar)]`, for a struct with one field
  whose type is a built-in single value, such as `struct Byte(u8)` or
  `struct Token(String)`. It gives the type what `OpaqueEncode` and
  `OpaqueDecode` need: `Encrypt` and `Scalar` on its borrow, and
  `FromScalar` on the type. Each one forwards to the field.
- **Why.** A newtype is how a caller changes the rule for a value, such as
  encrypting a `Vec<u8>` byte by byte. On `next`, the three
  implementations are written by hand. `FromScalar` is not documented for
  that use.
- **Done already.** `OpaqueEncode` and `OpaqueDecode` already accept any
  type that meets those bounds. Vitamin C documents a hand-written
  `Blob(Vec<u8>)` newtype.
- **Finished when** the [byte example](#encrypt-a-byte-string) compiles
  with the derive and no hand-written implementation.

#### Remove the structural API

- **What to build.** Remove `EncryptFrom`, `DecryptInto`, `encrypt_as`, and
  the helpers in `target::legacy`. Move EQL, Go, and the guest to the new
  API in the same change. Rename the plan builder's output method to
  `target`.
- **Why.** Two APIs for the same job make the right one hard to find.
- **Done already.** The new API exists beside the old one. Issue #1488
  tracks the removal.
- **Finished when** the old API is gone, and every consumer uses the new
  API.

#### Wipe plaintext in the remaining cases

- **What to build.** Wipe the parts of a Serde value that were decoded
  before a later part failed. Add an adapter that wipes a decrypted value
  when it is dropped.
- **Why.** Plaintext must not stay in freed memory.
- **Done already.** Collections wipe the values decoded before a failure.
  Cancellation and drop are tested (#1493, #1501).
- **Finished when** the lifecycle conformance profile covers both cases.

### 4. The query engine

#### One definition of each operator

Decided on 7 November 2026, as area two of the query design review.

- **What to build.** Each operator exists once, as its `op` type, such as
  `op::Eq` and `op::Between`. One macro generates the dynamic enum and
  its wire names from those types. A marker's query method, the dynamic
  handle's method, and a query plan's operator all resolve to the same
  type. So `eq`, `"eq"`, and `op::Eq` are three faces of one operator.
- **The dynamic enum's name.** It is public, because a program building a
  query plan writes it: `plan.query("email", Op::Eq)`. The engine's enum
  is `OpSpec` today. The plan writes `Op`; the rename is for the naming
  review.
- **`Matches` loses its case parameter.** On `next`, `op::Matches<C>`
  has a case parameter. The match index's configuration has a case too.
  The two can disagree. A disagreement is refused at query time. The field's configuration
  is now the only one, so case belongs to the index alone. `Matches`
  becomes a plain operator, as the dynamic `"matches"` already is.
- **An inverted range is let through.** `between(65, 18)` derives both
  bounds and matches nothing, as commit `8b5fc57b6` decided. The engine
  does not know which bound the caller meant. The `InvertedRange` error
  asked for in #1279 predates that commit and is dropped.
- **Stored format and wire.** Unchanged. A query sends the operator's wire name. That name does not change.
- **Finished when** these are all true:
  - the dynamic enum is generated from the `op` types;
  - `Matches` has no type parameter;
  - a test shows that each operator's three faces name the same operator.

#### Match configuration: one analyzer

Decided on 7 November 2026, as area five of the query design review. The
design is the query artifact's; the four adjustments below are the
plan's.

- **What to build.**
  - An analyzer pipeline, typed first: `Words.downcase().stop(..).stem(..).ngrams(3)`,
    built like an iterator chain. The order is checked by type, so a
    stemmer after n-grams does not compile. Any type that implements
    `Stage` can join, so a customer's own filter needs no change to the
    crate.
  - A closed dynamic subset, `StageSpec`: `Words`, `Whole`, `Downcase`,
    `Stop`, `Stem`, `Ngrams`, `EdgeNgrams`, `Shingles`. A plan names its
    stages, and every reader of the plan runs exactly those: Rust, the Go
    verify path, and EQL. A typed stage joins the subset by an explicit
    change. Until then a configuration that uses it is typed-only, and a
    serialised plan that names it is refused with `NotPortable`.
  - Case stated once, as whether `downcase()` is in the analyzer.
  - Two types: `Match<O>`, with the options in the type, and
    `Match<Dynamic>`, with the options in the value. Both derive terms
    through one `sem::match_terms`. A stored field and its query agree by
    type on the typed path, and by reading one plan entry on the dynamic
    path.
  - Versioned stop lists and stemmers, such as `english@1`. Changing a
    list is a new id, never a silent change to stored terms.
  - Refusals written once, in the `sem` functions, for both paths: empty
    text, text that cannot be normalised, and invalid options.
- **Stored format.** A declaration is data that a stored row depends on.
  A rc.3 declaration, `{tokenizer, downcase, short_words}`, keeps loading,
  mapped to the equivalent stage list. A conformance case shows that the
  mapped list produces the same terms as rc.3, for both tokenisers. New
  declarations may write `analyzer` instead.
- **Short words.** The short-word channel (#1397) is a stage in the
  analyzer, not a sibling index. A second filter is a second index only
  if it answers a different operator. The privacy question about short
  words stays open as it is.
- **Go.** A struct tag's match options are the stages of the dynamic
  subset. `stashgen` asks the engine which stages exist, and keeps no
  list of its own. This is what [configurable match options in
  Go](#configurable-match-options-in-go) builds.
- **EQL.** EQL's match configuration has a tokeniser and token filters.
  `EqlMatch` uses only stages that map onto them. Edge n-grams and
  shingles stay Stack-only until EQL supports them.
- **`expected_tokens` is dropped.** It is an optional prior for the
  false-positive estimate in `op::Stats`, `None` by default, and a data
  plan never declares one. `Stats::measured(rows, ..)` stays. Decided on
  7 November 2026.
- **Breaking.** Every hand-written `MatchConfig` changes shape. This lands
  as a `!` commit with a changelog entry.
- **Finished when** these are all true:
  - the rc.3 mapping conformance case passes in Rust and Go;
  - a `tests/ui` case shows a stemmer after n-grams fails to compile;
  - a serialised plan naming a typed-only stage is refused with
    `NotPortable`;
  - EQL, Go, and Rust produce the same terms for the same stage list.

#### The engine's rules, and the order of the work

Decided on 8 November 2026, as areas six and seven of the query design
review. The rules are the query artifact's.

- **Six rules.**
  1. A query runs on the field's own index, with that index's
     configuration. There is no default index and no `.via`. A query starts from the
     field's marker, so the rule is true by construction.
  2. A field declares at most one index per operator. `(Equality, Ore)`
     is allowed, because they answer different operators. `(Ore, Ope)`,
     `(Ore, OreBlock)`, and two match indexes are refused when the plan is
     built. So the lookup returns zero or one index, on both paths.
  3. An index declares its operators once. The typed lookup, the dynamic
     lookup, and the plan validation all derive from that one
     declaration. There is no second table in the dynamic path, and no
     third in `eql-bindings`.
  4. Refusals are part of deriving the term. They are written once, in
     the `sem` functions, for both paths.
  5. The typed path is strict at compile time. The dynamic path checks
     the same rules at run time. Both lower to the same functions.
  6. Rust is the superset. The dynamic path is a named subset.
- **The dynamic plan's shape.** A field's indexes become a closed
  `FieldIndexes` enum of the valid shapes, generated from the index
  declarations: equality optional, at most one match index, at most one
  of `Ore`, `Ope`, and `OreBlock`. Deserialising is validation. A plan
  with two match indexes has no variant, so the boundary refuses it.
  Order is canonicalised, so the two spellings `[ore, equality]` and
  `[equality, ore]` name one shape.

  `index_for(op)` is one match with no priority order. The wire keys
  `c`, `eq`, `match`, `ore`, and `ope` do not change, so the stored
  format is untouched. Until the enum lands, the dynamic plan keeps
  `Vec<IndexSpec>`, with a one-table lookup over each index's declared
  operators.
- **`check_query` stays, for Go.** The Go SDK promises to refuse a bad
  query before it resolves a keyset, and calls `dynamic::check_query` for
  that. It becomes a thin call into the `sem` functions, with no cipher.
  The typed path has no separate check step: a saving on the error path
  alone does not justify a trait method.
- **The order of the work.** Four steps, each shippable on its own, each
  removing one copy of something:
  1. One declaration per index and operator. `OpSpec` is generated from
     the `op` types. Each index declares its operators and admitted
     plaintexts once, and `index_for` reads them. Overlap is refused on
     both paths. A test shows the typed and dynamic faces agree.
  2. Derivation once, refusals once. The `sem` query functions, the
     analyzer in place of `MatchCase`, and `Match<Dynamic>` arrive.
     `check`, `verifier`, `admit`, `QueryToken`, `check_input`, and the
     second tokenisation go. This is the `!` commit. It closes #1318 and
     #1279, with #1279's `InvertedRange` item dropped.
  3. Typed field markers with their index lists, the per-operator query
     methods, `Planned`, and the removal of `DefaultIndex`, `.via`,
     `PlanError::IndexOptions`, and `PlanError::MatchCase`.
  4. `FieldIndexes` on the dynamic plan.
- **Issues.** #1318 and #1279 are closed by steps 1 and 2. #1309, short
  tokens, is a stage in the analyzer. #1326, the SSE investigation, is
  independent: a future SSE index is one more index declaration.
- **ADRs.** ADR-0009 describes `Supports`, `Answers`, `DefaultIndex`, and
  `.via`. The `MatchConfig` documentation says a field and its query agree "by
  construction". That is true only for one-value plans today. Both
  are amended, not contradicted in silence.
- **Finished when** these are all true:
  - every index's operators appear in one declaration, and a test shows
    the typed and dynamic lookups agree on every index;
  - a plan with two match indexes, or with `Ore` and `Ope`, is refused on
    both paths;
  - `DefaultIndex`, `.via`, `MatchCase`, and `PlanError::IndexOptions`
    are gone;
  - ADR-0009 and the `MatchConfig` documentation are amended.

### 5. After the customer release

- **Packaging and names.** Crate moves, the shared format crate, and the
  final names. The [packaging
  document](2026-10-25-stack-encrypt-packaging.md) has the proposal.
- **Key providers.** Choosing keysets from data, and ZeroKMS lock context,
  as optional capabilities of a key provider. The [provider capabilities
  document](2026-10-25-stack-encrypt-provider-capabilities.md) has the
  proposal.

## Open questions and decisions to be made

The lead who approves this plan decides each question.

| Question | Options | Recommendation |
| --- | --- | --- |
| What is the name of the wrapper that authenticates a collection's order and length? | `Positioned<Vec<T>>`. Or a name chosen in the naming review | `Positioned`. Decide in the naming review |
| For each change that would alter the stored format, should it keep the rc.3 format or add a new version? | Keep rc.3 data readable and searchable. Or add a version beside it | Decide for each change when it is designed |
| Should the dynamic path share the typed derivation itself, through `Index<ValueFrame>` implementations per index kind? | One executor for both paths, as ADR-0007 asks. Or the `sem` functions stay the shared layer, and the two paths keep their own callers | Decide after `FieldIndexes` lands, as its own step |
| Should keysets be chosen from data, and should Stack Encrypt use ZeroKMS lock context? | Optional capabilities of a key provider. Or leave them out | Optional capabilities, after the customer release |
| What privacy claim can be made for match terms of short words? | Accept what they reveal, and document it. Or change how short words are stored | No recommendation yet. Merging #1397 did not show that they reveal nothing new |
| Which crate should own `Base64Text` and `Base85Text`? | A small Vitamin C encoding crate. Or keep them in `eql-bindings` | A small Vitamin C crate, re-exported by Stack Encrypt and EQL |
| What names and crate layout should the final API use? | The proposal in the packaging document | Review the proposal after the customer release |

### Names deferred to the naming review

The naming review is the [packaging and names](#5-after-the-customer-release)
item: a review of every public name, against the packaging document's
proposal, after the customer release. These names are placeholders until
then. Each one is used consistently in this plan so that the review
changes a name, not a design.

| Placeholder | What it names |
| --- | --- |
| `Planned`, `QueryTerm`, `Request` | A value under a plan, the dynamic query result, and the serialised request |
| `Op` | The public dynamic operator enum, `OpSpec` today |
| `Scope<'a, K>` and `CipherScope` | The cipher a call runs under; both renamed so that `Scope` means a part of the context |
| `Positioned<Vec<T>>` | The wrapper that authenticates a collection's order and length |
| `contains`, `at`, `elements`, `predicate`, `children` | The JSON query methods on a document's marker |
| `contexts()`, `context()`, `assert_context!`, the `testing` feature, `encrypttest` | Showing and asserting a context, in Rust and Go |
| `Base64Ciphertext`, `Base85Ciphertext` | Field targets that store a ciphertext as text |
| `#[derive(Scalar)]` | The derive for a single-value newtype |
| `caveats`, `refine`, `refine_tag` | The caveat list in an EQL payload, and the operations that add to it |
| The declaration attributes `scope(..)` and `bind(..)` | How a declaration marks its parts |
| `ContextExtension` | The caller-supplied context input of #1504, renamed for the scope vocabulary |
| `TargetDefinition` | The packaging document's name for `Plan`, a record's declaration as data. One name is chosen |
| `Plan::context(..).fields()`, `encrypt_index`, `pick!` | The hand-built plan builder. The query artifact's `EncryptionPlan::record(..)` and `.field(..)` are the alternative spellings |
| `stack_encrypt::Cipher` | The packaging document's name for the execution handle. It is Vitamin C's `Cipher` trait too, so the review chooses another name or accepts the clash |
