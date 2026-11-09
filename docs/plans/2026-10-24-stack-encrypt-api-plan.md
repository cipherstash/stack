# Stack Encrypt API plan

Date: 8 November 2026. Checked against `next` at commit `e4990e49b`.
Revised 9 November 2026: the derive emits the combinators, not the plan
builder, and `Planned` is a target (ADR-0007, amended).

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

Three documents go with it:

- the [context scenarios](2026-10-24-stack-encrypt-context-examples.md),
  the acceptance matrix for how a record gets its context;
- [binds, claims, and labels](2026-11-08-stack-encrypt-key-policy.md),
  the design of key policy: what ties a value to a fact, and what only
  records one;
- [packaging and names](2026-10-25-stack-encrypt-packaging.md), the
  proposal the naming review judged on 8 November 2026.

The naming review of 8 November 2026 decided every public name this plan
uses. [Names decided in the naming
review](#names-decided-in-the-naming-review), at the end, records each
decision.

## Contents

- [Terms](#terms)
- [Target state](#target-state)
  - [Rust with static types](#rust-with-static-types)
  - [The dynamic interface](#the-dynamic-interface)
  - [Rules in the target state](#rules-in-the-target-state)
- [Remaining work](#remaining-work)
  - [1. The Go module](#1-the-go-module)
  - [2. The stored format](#2-the-stored-format)
  - [3. The Rust API](#3-the-rust-api)
  - [4. The query engine](#4-the-query-engine)
  - [5. Packaging, and two key provider features](#5-packaging-and-two-key-provider-features)
- [Open questions and decisions to be made](#open-questions-and-decisions-to-be-made)
  - [Names decided in the naming review](#names-decided-in-the-naming-review)

## Terms

| Term | Meaning |
| --- | --- |
| AAD (additional authenticated data) | Data that encryption checks for one ciphertext, but does not encrypt. Stack Encrypt builds it from the context. See [Context and AAD](#context-and-aad) |
| ADR | An architecture decision record, in `packages/stack-encrypt/docs/adr/`. ADR-0007 says every binding runs the engine's one executor |
| Access intelligence | The record of who retrieved which key, and for which value, built from ZeroKMS's log of key retrievals. Labels are what make the record useful |
| Analyzer | The pipeline that turns match text into tokens: a source, such as `Words`, then stages. A match index is configured by one analyzer |
| Binding | A part of the context that ties a ciphertext to its row, such as a row ID. It is in the stored context and not in the query context. Passed as `Bind::new(..)` |
| Claim | A binding whose value the key provider resolves from the caller's verified token, such as `sub`. The client names it and never sees the value. See [Claims the key provider resolves](#claims-the-key-provider-resolves) |
| Cipher | The Rust connection to ZeroKMS, with credentials and the key provider: `Cipher::new()`. `cipher.keyset(..)` resolves a `Keyset`, and `cipher.decrypt(..)` opens values from any keyset it holds. Today `StackCipher` |
| Ciphertext | One encrypted value, as the Rust `Ciphertext` type. It is stored as bytes, or as Base64 text |
| Conformance profile | A named, versioned set of test cases for one area, such as `record-contexts-v1`. Rust and Go run the same cases. The files are in `conformance/stack-encrypt/v1/` |
| Context | Data that a ciphertext is tied to, such as a column name or a row ID. Decryption needs the same context. See [Context and AAD](#context-and-aad) |
| Descriptor | The string a key request names its key under. ZeroKMS derives the data key from it. Today the whole context is rendered into it, such as `users/age`. Under envelope version 2 it is the name scopes only: the record name and the field name |
| Dynamic interface | The engine's interface for languages other than Rust. It takes a declaration and values as data, not as Rust types |
| EQL (Encrypt Query Language) | The PostgreSQL types and functions in `packages/eql` that store encrypted values and answer queries on them |
| Executor | The combinators in `target/`: the one engine path that runs every declaration. The derive's generated code and `Planned` both compose them. The executor derives each field's context, requests the keys in one batch, and seals or opens every value |
| Field marker | A constant the derive emits for each field of a record, such as `EncryptedMember::EMAIL`. It names the field, its plaintext type, its accessor, and its indexes. A typed query starts from it |
| Guest | The Rust engine compiled to WebAssembly. The Go SDK runs it inside the Go process |
| Key tag | The HMAC ZeroKMS returns with a data key. A reader must present it to get the key again. Stack Encrypt binds it into every leaf's AAD |
| Keyset | A set of keys in ZeroKMS. Every data key belongs to one keyset. A tenant can have its own keyset. In Rust, `Keyset` is also the handle bound to one keyset, which encrypt and query calls take. Today `KeysetCipher` |
| Leaf | One sealed value inside a stored record or document: the unit the AEAD encrypts, with its own data key and AAD |
| Label | A named, typed fact added to a stored value's key tag after encryption, such as `row_id` or `written_by`. ZeroKMS verifies it and logs it. It restricts no reader. See [Labels](#labels) |
| Key header | The Base64 field `h` of an EQL payload: the header version, the keyset ID, the IV, and the key tag, as the v4 JSON document stores them today. `label_tag` rewrites it. A bare `Ciphertext` keeps the same facts inside its envelope |
| Key request item | One part of the stored context as a key request sends it to ZeroKMS beside the descriptor: a name and value, or a claim. The ZeroKMS protocol calls the list `context` |
| Name scope | A declared scope that names the record or a field. A field's name scope is its last declared scope, pinned when the Rust field is renamed (ADR-0006). Two fields of one record never share one |
| n-gram | A run of `n` characters of a token, such as the trigrams of a word. The match index stores a Bloom filter of n-grams |
| Opaque blob | A whole value, such as a struct, encoded and sealed as one ciphertext. Nothing inside it can be searched |
| PAE | Pre-authentication encoding: a length-prefixed encoding of several values, so that two values cannot run into each other. The leaf AAD and a label use it |
| Passthrough field | A field stored unencrypted next to the encrypted fields. It is not authenticated |
| Plan | The dynamic interface's declaration of a record, as data: each field, its context, and its indexes. A binding sends one, and the engine reads it at run time. No Rust program builds one by hand, and the derive does not emit one. See [A value under a plan: `Planned`](#a-value-under-a-plan-planned) |
| Planned | A value paired with a plan that is data, `Planned::new(&plan, value)`, with the context parts a call supplies. It is a target, so the owned entry points encrypt, query, and decrypt it, with the keyset as the argument. Its serialisation is what a binding sends for an operation. See [A value under a plan: `Planned`](#a-value-under-a-plan-planned) |
| Query artifact, context artifact | Two design documents Dan wrote as Claude artifacts, one on queries and one on context. This plan compared them with itself on 8 November 2026 and records every decision. Dan deletes the artifacts after this plan merges |
| Query context | All the scopes of a context, declared and caller-supplied. Search terms derive under it. See [Query context and stored context](#query-context-and-stored-context) |
| Query plan | A record plan narrowed to one field and one operator, `plan.query(field, op)`. A query value is encrypted under it. See [A query plan](#a-query-plan) |
| QueryTerm | The result of a query on the dynamic path: the operand bytes and the EQL type they bind as, known at run time |
| Serialised `Planned` | A `Planned` as a binding sends it: the plan, the caller's context parts, and the value. A transport form, never stored. For a check, a binding sends a serialised `Plan` alone. See [A value under a plan: `Planned`](#a-value-under-a-plan-planned) |
| Scope | A part of the context that narrows the data and the queries over it. The declaration supplies the first scopes, such as `users` and `email`; the caller adds more, such as a tenant ID, with `Scope::new(..)` |
| Search term | A value stored next to a ciphertext, so that a query can find it without decrypting it. Equality, order, and match each use their own term |
| Stage | One step of an analyzer that maps, drops, or expands tokens, such as `Downcase`, `Stop`, `Stem`, or `Ngrams`. A serialised plan may name only the closed set of stages |
| Stored context | Every part of a value's context. The data key and the AAD derive under it |
| Stored format | Everything Stack Encrypt writes to the database. See [The stored format stays compatible with Go rc.3](#the-stored-format-stays-compatible-with-go-rc3) |
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

The connection is a `Cipher`. A keyset resolved on it is a `Keyset`,
and every encrypt and query call takes a `&Keyset`. Decrypt takes a
`&Cipher` or a `&Keyset`, because a stored value names its own keyset.

```rust
use stack_encrypt::{kms::IdentifiedBy, Cipher, Keyset};

// Not on `next` yet: the names. Today `Cipher` is `StackCipher` and
// `Keyset` is `KeysetCipher`.
let cipher = Cipher::new().await?;
let keyset: Keyset = cipher.default_keyset();
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
let card: Ciphertext = keyset    .encrypt_with_context(number, "card-number") // wipes `number`
    .await?;

// Store the ciphertext as bytes, or as Base64 text through Serde.
let bytes: Vec<u8> = card.to_bytes();
let card = Ciphertext::from_bytes(&bytes)?;
let number: String = keyset.decrypt_with_context(card, "card-number").await?;
```

A plain string is a context. `Scope::new("card-number")` would mean the
same thing. It is not needed here. The kind of a part matters only
where there are search terms. A `Ciphertext` has none.

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

// Not on `next` yet: the record derive, `passthrough`, and `scope =`,
// which is `context =` today.
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

let encrypted: EncryptedUser = user.encrypt_into(&keyset).await?;
let user = User::decrypt_from(encrypted, &keyset).await?;
```

`scope = "users"` is the record's name and its first scope. The derive
adds each field's name as the next scope, so `users` then `email` are the
declared scopes of the `email` field. `scope(..)` and `bind(..)` add the
parts that come from the caller or the row. The attribute, the data
plan's context, and Go's `scope=` tag use one word for it.
Decided by Dan on 8 November 2026.

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
declaration marks a binding. The naming review confirmed the attribute
spelling `bind(..)` on 8 November 2026.

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
#[stash(struct = Member, scope = "members")]
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
`EncryptedMember::EMAIL`. A marker names the field, the context the
derive sealed it under (the record's scope, then the field's identity),
and the field's target type, whose `Answers` impls are the field's index
list. It is the value a query starts from. The derive emits no plan: the
marker is enough for a query, and a binding sends a plan of its own.
Built on 10 November 2026 (pull request #1595): the marker has no
plaintext type and no accessor, because the derive sees the record's
field types and not the plaintext struct's, and a query value converts
from the borrowed form a caller has (`&str` to `String`) through
`ToOwned`. So an equality marker takes a value of any type its index
accepts, unless the field states its query type with
`#[stash(query = String)]`. A field whose type is several indexes, a
nullable field, and a record field (through `.field(..)`) have operator
methods too (#1596).

A typed query starts from the marker, and has one method for each
operator the field's indexes answer. A missing operator is a compile
error: "no method named `gt`", with a message that names the field's
indexes. A record that lists a caller scope gives its markers the
scope's type, and the query has no `encrypt` until `.scope(..)` is given
once, with a value of that type; a record with no caller scope gives a
query that is ready at once. A binding cannot be given, because the
query type has no `bind` method, so a query accepts its scope only, by
type. The query ends with `encrypt(&keyset)`, and its output type is the
EQL query type the marker fixes. Decided on 7 November 2026.

```rust
// On `next` since pull request #1595, with the index's query term as
// the output type (`EqualityTerm`, `RangeQuery<OreTerm<u32>>`,
// `MatchQuery`); the EQL query types follow with the EQL owned
// implementations. A value is passed by value; a string literal as it is.
let by_email: TextEqQuery = EncryptedMember::EMAIL
    .eq("alice@example.com")
    .scope(tenant)
    .encrypt(&keyset)
    .await?;
let adults: IntegerOrdQuery = EncryptedMember::AGE
    .between(18, 65)
    .scope(tenant)
    .encrypt(&keyset)
    .await?;

// error: `TextEq` has no order index, so the marker has no `gt`
EncryptedMember::EMAIL.gt("alice@example.com")
// error: the query builder has no `bind`
EncryptedMember::EMAIL.eq("alice@example.com").bind(row_id)
```

```sql
SELECT id, email, age FROM members WHERE email = $1::eql_v4.query_text_eq;
```

A chained scope is allowed on a query because a query has one field and
one value, so a scope cannot mean anything else. The rule that no chain state offers context, in [One context argument, and paired entry points](#one-context-argument-and-paired-entry-points), was about `.extend(..)` after `.fields()` on a record. There, a part added late looked per-field
and was not.

A typed query lowers from its marker to the term combinator, under the
marker's context. A dynamic query lowers a [query plan](#a-query-plan)
to the same combinator through `Planned`. The equivalence suite checks
that the two agree (ADR-0007, amended 9 November 2026).

#### Encrypt a JSON document

A JSON field is stored as one encrypted document in a
`public.eql_v4_json_search` column. That column type, the Rust type
`JsonTreeDocument`, and the dynamic target `JsonSearch` are three names
for the one stored type.

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

With the default options, no path has an ordering term. So a query cannot
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
- **The options.** They say which paths have ordering terms, and how far a
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
| Containment | `contains(doc)`, `contained_by(doc)`, and `at(path).eq(v)` | Rows whose document contains the given document, or is contained by it. Equality of a scalar at a path is containment of a one-entry document, so `at(path).eq(v)` lowers to it | `JsonTreeQuery` |
| Comparison at a path | `at(path).gt(v)`, `.lt(v)`, `.between(a, b)`, and the rest | Rows where the value at an ordered path orders against, or lies between, the given values | `JsonTreeLeafQuery` |
| Element match | `elements(path).eq(member, v).gt(member, v)` | Rows where one element of an array meets several conditions together | `JsonTreeElementsQuery` |
| Jsonpath predicate | `predicate(text)` | Rows where a SQL/JSON path predicate is true | `JsonTreePredicateQuery` |
| Children and child count | `children(path)` | The entries directly below one node, or how many there are | A node token |

A path is text. So an order query on a path the options do not order is
refused at run time, before any key is fetched.

Two limits of the SQL stay, from the reference page's sections on
comparing a value at a path and on what the SQL cannot do. Sorting rows by a path through an array
needs a rule the application chooses, such as `MIN` or `MAX` over the
matches. The supported way to the plaintext of every match at such a
path is a subtree read with a wildcard bound. The [EQL v4 reference
page](../../packages/eql/docs/reference/json-tree.md) gives the SQL for
each query. A scope chains on a JSON
query as on a scalar one: `.contains(doc).scope(tenant)`.

The engine already has one private input type for each JSON operator,
in `stack_encrypt::dynamic`. `DocumentInput` is for containment, `AtInput`
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
[serialised `Planned`](#a-value-under-a-plan-planned). The engine returns the query value, with
its EQL type.

The output keys and the type names are part of the stored format, so they
cannot change. The output keys are `c`, `eq`, `match`, `ore`, `ope`, and
`passthrough`. The type names include `int64` and `string`.

#### A value under a plan: `Planned`

Anything encrypted under a plan that is data is a `Planned` value. That
is a record under a record plan, or a query value under a [query
plan](#a-query-plan).

`Planned` is a plain struct, like `OpaqueBlob` and `Positioned`. It adds
no method to any other type. Decided on 7 November 2026.

`Planned` is a target in the owned API's sense. The stored row type
implements `EncryptTarget<Planned<..>>`, and `Planned<StackCipherText>`
implements `DecryptSource`. Both compose the combinators from the plan
when they run. So `encrypt_into` and `decrypt_from` run it, with the
keyset as the argument. Made a target after the combinator spike of
9 November 2026 (ADR-0007, amended).

```rust
// On `next` since pull request #1595. The value under a data plan is
// the dynamic interface's value, a `ValueFrame` of the record's fields,
// and the stored row is a `StackCipherText`. A typed struct uses the
// derive, not a plan.
let row: StackCipherText = Planned::new(&plan, values).encrypt_into(&keyset).await?;
let values = ValueFrame::decrypt_from(Planned::new(&plan, row), &keyset).await?;

let row: StackCipherText = Planned::new(&plan, values)
    .encrypt_into_with_context(&keyset, Scope::new(tenant).bind(row_id))
    .await?;
```

A serialised `Planned` is what a binding sends for an operation. A
serialised `Plan` alone is what it sends for a check, an operator list,
or a query plan. There is no separate request type. A `Planned` has
three parts:

- the plan, by reference to one the engine holds, or inline;
- the caller's context parts, in declared order, with their types;
- the value.

The keyset stays outside, as the receiver, so a `Planned` never names a
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
beside it. `contexts()` works on a `Plan` before any value exists, with
a placeholder for each part the caller supplies. `context()` on a
prepared call, a `Planned` with its context parts attached, shows the
exact context that call will use. See [Show the
context](#show-the-context).

A serialised `Planned` is a transport form, never a storage form. The
value in it is plaintext. So it lives only in a wiped buffer, as the
engine already reads it (`ProtectedRef<[u8]>`), and is never logged or
written to disk. A binding that keeps one, for a retry say, keeps it
wiped.

The serialised `Planned`'s shape is not part of the stored format. It can change
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
// On `next` since pull request #1595. A query value is a `ValueFrame`.
let by_email = plan.query("email", Op::Eq)?;   // refused here if no index answers Eq

let q: QueryTerm = Planned::new(&by_email, ValueFrame::of("alice@example.com")?)
    .encrypt_into_with_context(&keyset, Scope::new(tenant))
    .await?;
```

A query plan can be serialised beside its record plan, as
`{"field": "email", "op": "eq"}`. The bytes a query sends to the engine do
not change: the engine already receives the plan, the field, the
operator, and the value. They are grouped differently.

The result on the dynamic path is a `QueryTerm`: the operand bytes, and
the EQL type they bind as, known at run time. A typed query returns the
EQL query type instead, because its marker fixes it.

A typed query from a field marker lowers to the term combinator
directly, with no plan. The dynamic form lowers its query plan to the
same combinator through `Planned`. [Query a record
field](#query-a-record-field) shows the typed form.

#### The dynamic field handle

A program whose plan is data uses the same builder through a field
handle. The handle has one method per scalar operator, and `op(..)` for
any operator, the JSON ones included. Each one is checked at run time
against the plan, and returns `operator_not_answered` when no index
answers it. A field that names an EQL type takes its resolver at the
handle, `plan.field_with(name, &resolver)`. The handle has no `bind`
method either.

```rust
// On `next` since pull request #1595. A query value is a `ValueFrame`.
let email = plan.field("email")?;
let q: QueryTerm = email
    .eq(ValueFrame::of("alice@example.com")?)?   // refused here if no index answers Eq
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

The `scope=` tag gives the record's name, its first scope. The tag on each field says
how the field is stored: as a passthrough field, as an EQL type, or with
the indexes it names.

```go
//go:generate go tool stashgen -type User
type User struct {
	_     struct{} `stash:"scope=users"`
	ID    int64    `stash:"id,passthrough"`
	Email string   `stash:"email,encrypt_into=TextEq"`
	Name  string   `stash:"name,encrypt_into=TextMatch"`
	Age   int32    `stash:"age,encrypt_into=Integer"`
}

//go:generate go tool stashgen -type Customer
type Customer struct {
	_       struct{} `stash:"scope=customers"`
	ID      int64    `stash:"id,passthrough"`
	Profile Profile  `stash:"profile,encrypt_into=JsonSearch(ordered=$.age;$.visits[*].at)"`
}

//go:generate go tool stashgen -type Settings
type Settings struct {
	_     struct{} `stash:"scope=settings,opaque"` // sealed as one blob
	Theme string   `json:"theme"`
}
```

As in Rust, a `Cipher` is the connection. A `Keyset` is the cipher bound
to one keyset. The naming review of 8 November 2026 chose one vocabulary
for both languages; on rc.3 the two are `Client` and `Cipher`.

`Scope` adds a scope to the context of every field, such as a
tenant ID. `Bind` adds a binding, such
as a row ID. The generated `Encrypt` and
`Decrypt` functions take a slice. They send one ZeroKMS request for each
500 values.

```go
cipher, err := encrypt.NewCipher(ctx)
defer cipher.Close()
// Not on rc.3 yet: `Scope`, `Bind`, and the names. On rc.3 the
// connection is `Client` and the keyset-bound handle is `Cipher`.
// Today `Scope` is `Extend`.
keyset := cipher.DefaultKeyset().Scope("tenant-42")

encrypted, err := Encrypt(ctx, keyset, people) // []EncryptedUser
opened, err := Decrypt(ctx, keyset, encrypted) // []User

term, err := Fields.Email.Eq(ctx, keyset, "bob@example.com")
// SELECT id, email, name, age FROM users WHERE email = $1::eql_v4.query_text_eq

needle, err := Fields.Profile.Contains(ctx, keyset, map[string]any{"name": "Ada"})
older, err := Fields.Profile.At.Age.Gt(ctx, keyset, 30)
visit, err := Fields.Profile.Elements.Visits.Match(ctx, keyset, encrypt.JSONReadOptions{},
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
module without being generated again, with one exception. The generated file names the keyset-bound handle's type. So the handle
rename from the naming review needs one regeneration. The program
renames its own call sites with it.

The generated file builds its
declaration through `gensupport` calls, and the module builds the frames
it sends to the engine. So a change to the serialised `Planned`'s shape is a change inside the
module. A program generates again only to adopt a new
declaration, such as a scope or binding on a field. The generator keeps its output identical for unchanged input. So an
upgrade alone does not change a committed `*_stash.go` file, apart from
the one regeneration the handle rename needs.

Two parts of the target state are not in Go yet:

- A Go program cannot set match options.
- A Go program cannot open one child of a JSON node, bound to its parent.

Both are in [Remaining work](#remaining-work).

### Rules in the target state

#### The stored format stays compatible with Go rc.3

Decided on 7 November 2026 by Dan: "The stored data must not break as of
now. The Go customer has already started implementation with rc.3. We can
make breaking changes to the code/API but not the stored format."

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
   with each key request. Today the whole context is rendered into a text
   descriptor, such as `users/age`. Under the planned envelope version 2, the name scopes are the
   descriptor. Each part is a key request item. ZeroKMS needs the same request to derive the key again.
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
the field's name scope. The caller supplies the rest.

- **The query context** is all the scopes: the declared ones, then the
  caller's. Search terms derive under it. A query supplies the caller's
  scopes, and matches every row stored under the same query context.
- **The stored context** is the query context followed by the bindings.
  The data key and the AAD derive under it.

The kind of a part is not in the derivation. Two contexts with the same
parts in the same order give the same key, the same AAD, and the same
descriptor, whatever their kinds. The kind decides only which parts are
in the query context. rc.3 data has no kinds. This rule is what keeps it
deriving the same way. Decided by Dan on 8 November 2026.

A field's **name scope** is its last declared scope: the field's name by
default. It can be pinned when the Rust field is renamed, so that
stored data keeps opening.

The name scope is always the last declared scope, so two fields of one
record never share a context. If they did, they would share a key and an
AAD, and a ciphertext copied between the two columns would open. ADR-0006
records this.

A part of the context is one of two kinds. The declaration says which,
and fixes the order: the scopes first, then the bindings.

| Kind of part | Verb | Example | In the query context | Sent to ZeroKMS | In the AAD | Verified by |
| --- | --- | --- | --- | --- | --- | --- |
| Scope | `scope` | A record name, a field's name scope, or a tenant ID | Yes | Yes | Yes | ZeroKMS and the AEAD |
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
so the reader takes it from the row.

Every scope and binding is sent to ZeroKMS, so each part leaves the
customer's system, and ZeroKMS logs it at every key retrieval. Today the parts travel in the descriptor. The descriptor has a length
limit. Under envelope
version 2 they travel as [key request
items](#context-parts-as-key-request-items), with no limit. ZeroKMS
version 2 is planned to encrypt the access log.

A [label](2026-11-08-stack-encrypt-key-policy.md#labels) is not a part
of the context. ZeroKMS verifies it. It is in neither the query context
nor the AAD.

The use case is access control: a value that must stay in its row. Each
value is bound to its row by a client-generated UUID, and a query by
column or by tenant still finds it.
The facts of a row's writing, such as the address it came from, are
labels, not bindings.

#### A developer can see the context

Decided on 7 November 2026. A wrong context is silent: a query matches
nothing, or a row opens somewhere it should not. So every declaration
and every call can show the context it uses, before any key is fetched.

```rust
// Not on `next` yet: `contexts()` and `context()`.

// For a declaration: each field, its query context, and its stored
// context, with a placeholder for every part the caller supplies.
println!("{}", EncryptedUser::contexts());
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

#### Labels

A label adds a named fact to the ZeroKMS key tag of a stored value,
after encryption. The row and the facts of its writing are then recorded on the value.
ZeroKMS can verify the record.

Its context, its AAD, and its queries do not change.
ZeroKMS verifies the labels when it returns the key, and logs them.
That log is where access intelligence comes from.

A label restricts no
reader. A bind does. [Binds, claims, and
labels](2026-11-08-stack-encrypt-key-policy.md) has the design and the
rules that keep the two apart.

```rust
// Not on `next` yet: `label` and `labels`.
let sealed: TextEq = sealed
    .label("written_from", request.ip())?
    .label("created_at", now())?;
let body: String = String::decrypt_from(sealed, &keyset).await?;
```

```sql
-- In a trigger, once the primary key is known.
NEW.body := eql_v4.label_tag(NEW.body, 'row_id', NEW.id::text);
```

#### Other rules

- **One context argument.** The caller's parts arrive in one chain,
  `Scope::new(..)`, `Bind::new(..)`, or `Scope::new(..).bind(..)`, through
  the `_with_context` entry point. No chain state offers context. The
  entry points accept the chain through a trait bound, `impl ContextParts`.

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
- **Ordering terms do not answer equality.** An order-revealing encryption
  (ORE) term does not answer an equality query. A field that needs both
  declares both indexes.

## Remaining work

Everything in this section is work to implement. Each item ends with the
issues and pull requests that track it, checked on 8 November 2026.
`next` was still at `e4990e49b`, the plan's last check.

An issue that a merged pull request says it closes can stay open,
because GitHub closes issues only on the default branch. So an open
issue here may be done. It is in five groups:
the Go module, the stored format, the Rust API, the query engine, and
packaging with two key provider features. The Go customer's
release happened in late October 2026, so the groups are no longer
ordered around it. The [stored-format
rule](#the-stored-format-stays-compatible-with-go-rc3) is what that
release leaves behind.

### 1. The Go module

#### Finish the specification around the conformance profiles

- **What to build.** JSON Schema files for declarations, requests, and
  responses. Protocol version identifiers. A compatibility matrix of releases.
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
  - the lifecycle of values and keys.  The profiles are experimental. They do not certify a whole SDK. Three pull requests are in review. Pull request #1505 adds value,
  refusal, and raw-frame corpora. Pull request #1506 adds a fresh Rust
  and Go artifact exchange. Pull request #1507 consolidates the tests.
- **Tracked in.** Issues #1477, #1478, #1479, #1481, #1490, and #1314 are open. Issue #1512 is open for cross-language queries through PostgreSQL. Issues #1471 to #1476 and #1480 are closed. Pull requests #1505, #1506, and #1507 are open, stacked on #1503. Pull request #1506 adds `conformance/stack-encrypt/exchange-contract.md` and a placeholder for the released-version matrix.
- **Finished when** these are all true:
  - the profiles are no longer experimental;
  - the schemas exist;
  - the version identifiers exist;
  - the compatibility matrix lists rc.3.

#### Open one child of a JSON node, bound to its parent

- **What to build.** An operation that opens one child value of a JSON
  node, and checks that the child belongs to that parent. Today `eql_v4.json_tree_children` returns the child entries. Go's
  `JSONSelection.Open` opens one entry for each document, and refuses a
  group with more than one entry for a selector. The contract for every
  JSON operation is `conformance/stack-encrypt/eql-json-contract.md` on
  `next`; the SQL is the [EQL v4 reference
  page](../../packages/eql/docs/reference/json-tree.md).
- **Why.** Today a program must read and open the parent's whole subtree to
  see one child. That transfers more data and reveals a different set of
  tokens.
- **Done already.** Nothing.
- **Tracked in.** No issue. Pull request #1353, the Go JSON plan document, lists it as remaining.
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
- **Tracked in.** Issue #1112 is open. Issues #1398 and #1399 are open for match-index follow-ups. Issue #1299 is an open question on short substrings. Issue #1396 is closed. Pull request #1397 is merged.
- **Finished when** a Go field can declare match options, and its queries
  use the same options as its stored terms.

#### Freeze the rc.3 stored format in test vectors

- **What to build.** Fixed test vectors for the JSON storage format and the
  matching EQL bundle, recorded as the rc.3 baseline.
- **Why.** The vectors make sure that later work keeps rc.3 data readable
  and searchable.
- **Done already.** The conformance jobs run in CI. Two fixtures are
  frozen: `stored_rows_v1.json` since 18 October 2026, and the Go rows
  that `eql_v4_test.go` never regenerates. Both predate the rc.3 tag of
  2 November 2026, so neither is labelled rc.3.
- **Tracked in.** No dedicated issue. Issue #1119 is closed. It froze `stored_rows_v1.json` on 18 October 2026. Issue #1490 is open. It covers stable gates and supported conformance versions.
- **Finished when** CI fails on any change to the stored bytes of rc.3
  data.

#### Replace the temporary Vitamin C pins in Go

- **What to build.** Replace the Go module's pseudo-versions of Vitamin C
  with released module tags.
- **Why.** A final Go release cannot depend on unreleased commits.
- **Done already.** Prereleases can keep the pins, so rc.3 uses them.
- **Tracked in.** No direct issue. Pull request #1369, merged, introduced the pin. Issue #1253 is open. It would bring the frame codec into the Go module and remove the dependency instead.
- **Finished when** the release workflow accepts a final version.

### 2. The stored format

#### Changes that would alter the stored format

Each change below would alter the stored format if it were built as first
planned. Each one must keep rc.3 data readable and searchable, or add a new
format version beside it.

| Planned change | What it would alter |
| --- | --- |
| Search terms under the query context | A new form of search term, beside the rc.3 form, where terms derive under every part |
| A key header `h` beside a Base85 `c`, in EQL payloads | The shape of every scalar EQL payload. Payload version 2, beside rc.3's version 1 |
| The `SealedValue` envelope and the JSON header version | The offsets of the key tag, and header version 1, which rc.3 writes |
| Configurable match options | The terms of columns written with the rc.3 defaults |
| Context parts as key request items | The descriptor a key is derived under, and so the data key itself. A new envelope version marks the new form |

- **Tracked in.** Draft pull request #1524 defines a version 2 leaf header of its own. The next item records the conflict.

#### Context parts as key request items

Decided on 8 November 2026. [Binds move from the descriptor to key request items](2026-11-08-stack-encrypt-key-policy.md#binds-move-from-the-descriptor-to-key-request-items)
has the design.

- **What to build.** New values send each scope and binding to ZeroKMS  as a key request item. Each item is a name with a value, never the
  part's kind, because [the kind is not in the
  derivation](#query-context-and-stored-context). The descriptor shrinks to the name scopes: the record name and the field
  name.
  The `SealedValue` format version becomes `0x02` for
  these values. On decrypt, the engine reads the version byte and sends
  the request in the form the value was written with.
- **Why.** The descriptor is one string of at most 512 bytes. ZeroKMS
  logs it and cannot parse it. Items are structured. They have no size
  limit. Claims use the same channel, so a scope, a binding, and a
  claim travel the same way.
- **Conflict.** Draft pull request #1524, from the key-vendor work on
  `main`, defines its own version 2 leaf. It starts with `0x02`, then the
  key backend, the key mode, the keyset ID, the IV, the tag, and the
  ciphertext. Two
  changes cannot both own `0x02`. Either they merge into one version 2
  header that carries both, or one takes the next byte. Decide with the
  key-vendor work before either lands.
- **Stored format.** Version 1 values keep the rc.3 descriptor rendering. That rendering stays in the engine until the last such
  value is gone. The change is additive: nothing written by rc.3 is re-encrypted.
- **Done already.** `SealedValue` has the version byte, bound into the
  leaf AAD, and the rendering of a context into a descriptor is frozen
  and documented in `packages/stack-encrypt/src/descriptor.rs`.
- **Tracked in.** No issue. Related: issue #1067, open, says Stack Encrypt never sends key request items to ZeroKMS. Issue #1487 is open. Draft pull request #1524 claims the same version byte, `0x02`.
- **Finished when** these are all true:
  - a version 2 value round-trips, and a version 1 value from the rc.3
    vectors still decrypts;
  - a context longer than 512 bytes encrypts;
  - a conformance case covers both versions.

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
- **Tracked in.** Issue #1484 is open. It closes when #1503 merges. Issues #1367 and #1113 are closed. Pull request #1503 is open. Pull requests #1369 and #1370 are merged. Pull request #1506 adds the Rust and Go exchange of sealed blobs.
- **Finished when** Rust and Go each open blobs that the other wrote, and
  the conformance profiles cover it.

#### Labels: the work

Decided on 7 and 8 November 2026. [Binds, claims, and
labels](2026-11-08-stack-encrypt-key-policy.md#labels) has the design.

- **What to build.**
  - `label(name, value)` on every EQL type and on a JSON document. It
    computes `HMAC(tag, PAE(name, value))`, stores the result as the tag,
    and appends the label to the payload's list.
  - `eql_v4.label_tag(payload, name, value)`, the same in SQL, for a
    trigger that labels with the generated primary key. The tag is in the payload's key header `h`, so `label_tag` reads and
    writes one Base64 field. [A key header beside a Base85
    ciphertext](#a-key-header-beside-a-base85-ciphertext) defines it.
  - `label` and `labels` as operations of the dynamic interface, so Go
    can label a value before it writes the row, and read the labels.
  - `labels()` on a stored value, to read the list without decrypting.
  - The optional `labels` list in every EQL payload type.
  - On decrypt, send the stored tag and the labels to ZeroKMS, and
    rebuild the leaf AAD from the original tag it returns.
- **Why.** Access intelligence needs each value tied to its row and to
  the facts of its writing. A label does that without touching the
  context, the AAD, or the queries, and without restricting any reader.
- **Stored format.** The list is present only once a label is added, so
  a payload without one is the rc.3 form. The change is additive.
- **Depends on ZeroKMS.** The read path needs the retrieve-key request to
  carry the labels, and the response to return the original tag. That
  work is outside this repository. Labels written by ZeroKMS itself, and
  policy over labels, are deferred to the ZeroKMS version 2 work. The
  key policy document's [Still to
  explore](2026-11-08-stack-encrypt-key-policy.md#still-to-explore)
  section records the thinking.
- **Done already.** `Ciphertext::key_tag` reads the tag in Rust (#1404).
  The leaf AAD already binds the original tag.
- **Tracked in.** No issue. Related: issue #1067, open.
- **Finished when** these are all true:
  - the example in the key policy document round-trips through a
    trigger, in Rust and in Go;
  - a changed label, or a changed tag, is refused by ZeroKMS;
  - the conformance profile for EQL covers the `labels` list.

#### A key header beside a Base85 ciphertext

Decided by Dan on 8 November 2026. An EQL payload separates what
retrieving the key needs from the ciphertext itself, as the v4 JSON
document already does. A bare `Ciphertext` does not change: its envelope
keeps the keyset ID, the IV, and the tag inside, and Serde writes it as
Base64.

- **What to build.**
  - A key header field `h` in every scalar EQL payload, in Base64. Its
    layout is the JSON tree header's: the header version, the keyset
    ID, the IV, and the key tag.
  - The `c` field contains the ciphertext without that header, in Base85.
    No SQL function decodes it. The JSON tree's node ciphertext is
    the same type.
  - This is payload version 2. Version 1, the rc.3 form, keeps Base64
    `c` with the header inside, and stays readable.
  - `eql_v4.label_tag` reads the tag from `h` with PostgreSQL's own
    Base64 decoder, and writes the labelled tag back into `h`. It never
    parses `c`. The same function serves a JSON document, whose tag is
    already in `h`.
  - A `to_base64` method on the bare `Ciphertext`, returning the existing
    `Base64Text` type. One field target that stores a bare ciphertext as
    text, with the working name `Base64Ciphertext`.
- **Why.** Labelling must be a one-field update in SQL. With the tag in
  `h`, PL/pgSQL never needs the envelope's layout, in either encoding.
  The header also gives SQL the keyset ID without decoding anything
  else, and Base85 saves about a quarter of Base64's overhead on `c`.
- **Rule.** The tag moves into `h`. It is not copied. After labelling,
  the base tag must be gone from the row. The chain is one-way only if
  no one can read the base tag back.
- **Done already.** The v4 JSON document has `h` with this layout and a
  Base85 `c` (`eql-bindings`, `v4/json_tree.rs`). `Ciphertext::key_tag`
  reads the tag of a bare ciphertext in Rust (#1404). `Base64Text` and
  `Base85Text` exist in `eql_bindings::encoding`.
- **Tracked in.** Issue #1485 is open. It asked for key tag extraction
  from the envelope. This item replaces that with the header field.
- **Finished when** these are all true:
  - a version 2 scalar payload round-trips in Rust and Go, and a version
    1 payload from the rc.3 vectors still decrypts;
  - `eql_v4.label_tag` labels a scalar and a JSON document through `h`
    alone, and Rust reads the tag it wrote;
  - the conformance corpus has both versions.

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
- **Tracked in.** Issue #1483 is open. It closes when #1504 merges. Issue #1482 is still open although #1501 merged with "Closes #1482". It needs a manual close. Pull request #1504 is open. Pull requests #1404 and #1501 are merged. Pull request #1504 lands `scope = ".."` and `DeclaredScopes`, the names the naming review chose. Its record derives emit the combinators (ADR-0007, amended 9 November 2026).
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
- **Tracked in.** Issue #1486 is open, in part. No dedicated issue. Pull request #1504 defers the EQL owned implementations. `eql-bindings` builds against the crates.io `stack-encrypt`, so a `stack-encrypt` release must come first.
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
- **Tracked in.** No issue.
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
- **Tracked in.** Issue #1459 is open. It is exactly this item. Issue #1486 is open.
- **Finished when** these are both true:
  - the [JSON query example](#query-a-json-document) compiles;
  - an order query on a path the options do not order is refused before
    any key is fetched.

#### Field markers and the encryption plan

Decided on 7 November 2026, as difference six of the context artifact
review.

- **What to build.** The derive emits one marker for each field, as an
  associated constant such as `EncryptedMember::EMAIL`. The marker has
  the field's name, its plaintext type, its accessor, and its index
  list. It is the value a query starts from. The index list is what lets
  the marker offer one method per operator, resolved at compile time. A
  query from a marker lowers to the term combinator under the marker's
  context. Typed Rust option factories, and the same options read from
  data in the dynamic interface.
- **Why.** A query must use the same declaration as the stored values.
  The caller must not write a second plan by hand. The marker holds the
  declaration the derive wrote, so the query term and the stored term
  come from one source.
- **Done already.** `Answers` on a target type is the compile-time
  lookup of the index for an operator; a marker's methods are bound by
  it, so the marker's index list is its target type's `Answers` impls.
  Pull request #1595 lands the markers, their query methods and
  `assert_context!` over a marker (`src/marker.rs`, `tests/markers.rs`,
  `tests/ui/marker_*.rs`). The fix for #1596 gives a field of several
  indexes, a nullable field and a record field their operator methods,
  and a field its query type (`#[stash(query = ..)]`). The chain query
  `cipher.query(op, value).on(&plan)` still exists until #1488 removes
  it.
- **No hand-built plan.** The review of 7 November 2026 gave a
  hand-built plan the same markers, through `Plan::<Member>::scope(..)`
  with `pick!`. That is withdrawn. No Rust program builds a plan by hand.
  A program whose declaration is data uses `Planned`. The builder is
  removed with the structural API (ADR-0007, amended 9 November 2026).
- **Cannot fail.** The derive sees every field, so it refuses a repeated
  field name or a shared name scope at compile time. A typed index set
  that repeats an index, `(Equality, Equality)`, is refused at compile
  time too. Today the builder refuses it at run time, so that check
  lands with the builder's removal. The dynamic grammar keeps its
  run-time checks.
- **Tracked in.** Issue #1486 is open; pull request #1595 closes it.
  Issue #1596, the operator methods the markers lacked, is closed by the
  pull request stacked on #1597.
- **Finished when** these are all true:
  - the [marker example](#query-a-record-field) compiles, with the
    index's query term as the output type; the EQL query types come
    with the EQL owned implementations;
  - the compile-fail cases in `tests/ui` cover an operator the field's
    indexes do not answer (`marker_operator_not_answered`), a binding
    on a query (`marker_query_has_no_bind`), and a missing, mistyped or
    repeated scope (`marker_query_needs_its_scope`);
  - tests show that a query cannot run without its plan or its required
    context (`tests/markers.rs`, `tests/planned.rs`).

#### `Planned` and its serialised form

Decided on 7 November 2026, as area one of the query design review.

- **What to build.**
  - `Planned::new(&plan, value)`, a target. It implements `EncryptTarget`
    and `DecryptSource` by composing the combinators from the plan, so
    `encrypt_into`, `decrypt_from`, and their `_with_context` forms run
    it. It serves a record under a record plan and a query value under a
    query plan.
  - Two wire shapes. A serialised `Plan` alone serves a check, an
    operator list, or a query plan. A serialised `Planned` serves
    encrypt, query, and decrypt. It contains the plan by reference or
    inline, the context parts in declared order with their types, and
    the value. The engine reads it from a wiped buffer. It answers with
    the row, the query term, or the plaintext. The keyset is never in it.
  - Query plans: `plan.query(field, op)`, refused where it is made if no
    index answers the operator, and serialisable beside the record plan.
  - The dynamic field handle, `plan.field(name)`, with every operator
    method checked at run time.
  - `QueryTerm` as the dynamic path's query result. It contains the operand
    bytes and the EQL type they bind as.
  - `contexts()` on a `Plan` and on a `Planned`, before either runs.
- **Why.** One shape for every binding. A binding then has no logic of
  its own, so it cannot drift. The same shape is a conformance case. A plan
  that is data is checked at run time, and a language adds its own typed
  builder over it where it can.
- **Rules.** A serialised `Planned` is a transport form, never a storage
  form, because its value is plaintext. It is never logged or written to disk. Its shape
  is not part of the stored format.
- **Done already.** `Planned`, the query plan, the field handle,
  `QueryTerm` and `contexts()` on a `Plan` and a `Planned` are on pull
  request #1595 (`src/dynamic/planned.rs`, `tests/planned.rs`). `Planned` calls `encrypt_with`, `query_term` and
  `decrypt_with` in `dynamic::record` and `dynamic::query`, under the
  plan extended by the caller's parts. The guest still sends the engine
  a plan frame, then a value frame for each call. The serialised
  `Planned` names and groups what those functions already receive, and
  is not built yet.
- **Tracked in.** Issue #1486 is open, in part. Issue #1594 is the
  serialised `Planned`, the Go module sending it, and the corpus
  rewrite, split from pull request #1595. On the Go side, issue #1116 is open to hide or rename `record.Plan`. Issue #1307 is open for a Go plan-building API, for types `stashgen` cannot tag. It builds a data plan, so the Rust builder's removal does not affect it.
- **Finished when** these are all true:
  - every case in the conformance corpus is a serialised `Plan` or
    `Planned` with the engine's expected answer beside it;
  - a Go program generated for rc.3 runs against the module that sends
    serialised `Planned` values, apart from the one regeneration the
    handle rename needs;
  - the chain in `plan/chain.rs` and the builder in `plan/build.rs`
    are gone.

#### Context from fields and from the caller

- **What to build.** One set of combinators for where a field's context
  comes from. The derive emits them. The dynamic grammar lowers to them
  through `Planned`. A field's context comes from one of three sources:
  - the declaration: `scope = ".."` on a record, or the plan's context
    in the data grammar, with each field's name scope after it;
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
  `NoCallerContext`, and `OptionalContext` exist (#1404). `ExpectedContext` exists on `next`, in `target/context.rs`. #1504 adds
  `DeclaredScopes`, makes `ExpectedContext` a context input, and is in
  review.
  The naming review of 8 November 2026 decided that `ContextExtension`
  goes: the `Scope::new(..).bind(..)` chain is the input. The plan builder's
  `.context(..)` and `.context_field(..)` and the derive's
  `#[stash(context_field)]` are the forms this replaces.
- **Required parts.** A Rust declaration lists the parts the caller must
  supply, with kind and type. The context artifact proposed that for its
  one kind of part; this extends it to bindings. An undeclared part is refused. Optional is
  the marked case. The dynamic grammar can declare required parts; its
  default stays "any", and the Go generator requires a declared part at
  compile time. `RequiredContext`, `OptionalContext`, and `NoCallerContext`
  (#1404) are the three states this keeps.
- **Tracked in.** Issue #1487 is open. Issue #1120 is open: a second `.extend()` replaces the first. It closes when the chain goes. Issue #1308 is open for Go identity independent of the column. Issue #1475 is closed. Pull request #1491 is merged. Pull request #1504 is open.
- **Finished when** these are both true:
  - all eight scenarios run as tests in Rust and Go, on both paths: the
    derive, and `Planned`;
  - a Rust call with an undeclared part fails to compile.

#### Query context and stored context

- **What to build.** The binding kind of part, in the declaration and in
  the dynamic grammar. Search terms derive under the query context, and the
  key and the AAD under the stored context. A binding can be a context
  field stored in the row. The order is fixed: the scopes, then the
  bindings.
- **Why.** Access control needs each value bound to its row, and still
  found by a column or tenant query. The facts of a row's writing are
  [labels](2026-11-08-stack-encrypt-key-policy.md#labels), not bindings. [Query context and stored
  context](#query-context-and-stored-context) has the rule.
- **Vocabulary.** The Rust chain's `.extend(..)` is removed; the context
  argument carries the scopes and bindings instead. Go `Extend` becomes
  `Scope`, with `Extend` as a deprecated alias until 0.1.0. `Bind` is added
  to Go. The context contract and the conformance README say "scope"
  instead of "extension". The frozen vectors do not change, because no key
  on the wire names the operation.
- **Done already.** Nothing. Today every part is in both contexts.
- **Tracked in.** Issue #1487 is open. It is exactly this item. Its pull request adds the binding kind to the derive, the dynamic grammar, and Go, and the `record-bindings-v1` conformance profile. Issue #1067 is open and related.
- **Finished when** these are all true, in Rust and in Go:
  - a record with a binding row ID encrypts;
  - a column query finds it;
  - it fails to open under another row ID;
  - the stored bytes of a record with no binding are unchanged.

#### One context argument, and paired entry points

Decided on 7 November 2026, as differences two and five of the context
artifact review. The rules are in the target state. See [the context
argument](#other-rules) and [`Planned`](#a-value-under-a-plan-planned). This item
records only the work.

- **What to build.** The `Scope` and `Bind` value types, with the order
  fixed by type. The paired entry points on the typed API. They run
  `Planned` too, because it is a target. `Planned` replaces the chain in
  `plan/chain.rs`,
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
- **One handle reference.** `Scope<'a, K>` in `dynamic::record` and
  `CipherScope` in the owned API both reduce to a connection and an
  optional keyset ID. The naming review of 8 November 2026 replaced both
  with one borrowed value, `CipherRef<'c, K>`, built by `From<&Cipher>`
  and `From<&Keyset>`. The entry points take `impl Into<CipherRef>`, and
  the Go guest builds one from its keyset selector. A `Keyset` reference
  refuses a foreign leaf with `ForeignKeyset`. A `Cipher` reference opens leaves from any keyset the client has.
- **Tracked in.** Issue #1488 is open. It is the chain removal. Issue #1120 is open. Pull request #1504 is open and adds the record pairs.
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
    part. The derive emits `contexts()` on every record directly, and a
    data plan has it too.
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
- **Tracked in.** Issue #1568, with the two items below. Its first pull
  request lands `contexts()`, `context()`, `assert_context!`, and the Go
  `encrypttest` package for the declarations that exist today. The
  scenarios that need `scope(..)` and `bind(..)` land with #1487, and the
  field-marker form with #1486.
- **Finished when** these are all true:
  - a test pins the output of `contexts()` for each of the [context
    scenarios](2026-10-24-stack-encrypt-context-examples.md);
  - a conformance case shows that Rust and Go print the same context for
    the same declaration;
  - the [context scenarios](2026-10-24-stack-encrypt-context-examples.md)
    each carry an `assert_context!` test, in Rust and in Go.

#### Name context parameters `context`

These public methods on today's types in
`packages/stack-encrypt/src/cipher.rs` take a context through a parameter
named `aad`:

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

- **Tracked in.** Issue #1568.

#### Pass context by reference

- **What to build.** Let every method that takes a context accept a
  borrowed context, such as `&Identifier`. The request borrows the context
  for as long as it runs. `eql-bindings` needs `IntoContext` for
  `&Identifier`.
- **Why.** On `next`, every context is taken by value. A program that uses
  one column context for a write and a query must clone it for each call.
- **Done already.** Stack Encrypt implements `IntoContext` for `&Label`,
  the old context path type that [Apply the naming
  review](#apply-the-naming-review) removes.
  The context inputs, such as `RequiredContext`, still need an owned value.
- **Tracked in.** Issue #1568. A stored EQL type still takes its
  `NonEmpty<Identifier>` by value: Rust's orphan rule keeps
  `From<&NonEmpty<T>>` for `NonEmpty<T>` out of this repository, so that
  impl is a follow-up in Vitamin C.
- **Finished when** the examples in this plan pass a context by reference,
  without moving it, and compile. The parts are cloned into the call.

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
- **Tracked in.** No issue. Issue #1468, open, a Vitamin C buffer type, is adjacent.
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
- **Tracked in.** No issue. Pull request #1504 names `serde_json::Value` not being `Zeroize` as what blocks configured nested targets. This item unblocks them.
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
- **Done already.** Today's `StackCipher::keyset` takes
  `impl Into<IdentifiedBy>`,
  and `IdentifiedBy` implements `From<Uuid>` and `From<Name>`.
- **Tracked in.** No GitHub issue. The `cipherstash-suite` repository has issues disabled. It is where `zerokms-protocol` lives.
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
- **Tracked in.** No issue.
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
- **Tracked in.** No issue.
- **Finished when** the [byte example](#encrypt-a-byte-string) compiles
  with the derive and no hand-written implementation.

#### Apply the naming review

Decided by Dan on 8 November 2026, one name at a time. [Names decided in
the naming review](#names-decided-in-the-naming-review) has the full
table.

- **What to build.** The renames. Each is a breaking change to the Rust
  API and none changes the stored format.
  - `StackCipher` becomes `Cipher`, and `KeysetCipher` becomes `Keyset`.
  - In Go, `Client` becomes `Cipher`, with `NewCipher`, and the
    keyset-bound `Cipher` becomes `Keyset`. Generated files are
    regenerated, and the generator's output changes for every input.
  - `CipherScope` and `dynamic::Scope` are replaced by one `CipherRef`.
  - The old context path type `Label` is removed, with `IntoLabel` and
    Go's `ContextLabel()`. A plan's context is its declared `Scope`
    parts, so `Label` is free for the key tag fact.
  - The ZeroKMS unit of work `Request` is made crate-private with
    `Pending::request`, built on stack-kms's `GenerateKeyPayload` and
    `RetrieveKeyPayload`. There is no public request type. A binding
    sends a serialised `Plan` or `Planned`.
  - `OpSpec` becomes `Op`.
  - `context = ".."` becomes `scope = ".."`, and Go's `context=` tag becomes `scope=`. The builder's
    `Plan::context(..)` goes with the builder.
  - The marker trait `op::QueryTerm` becomes `Query`, and
    `LabelledTarget` becomes `Stored`. `dynamic::QueryTerm` stays.
  - `ContextExtension` is removed. `EncryptionPlan` is never added.
- **Why.** The plan used placeholders so that the review could change a
  name without changing a design. The review is done, so the code can
  follow.
- **Done already.** Nothing. Every name above is still the old one on
  `next`.
- **Tracked in.** Issue #1489 is open for naming and packaging. Issues #1116 and #1307 are open for the Go names. Pull request #1504 is open. It lands `scope = ".."` and `DeclaredScopes`, as the review decided.
- **Finished when** no old name remains in the public API, the examples
  in [Target state](#target-state) compile under the new names, and the
  packaging glossary matches.

#### Remove the structural API

- **What to build.** Remove `EncryptFrom`, `DecryptInto`, `encrypt_as`, and
  the helpers in `target::legacy`. Remove the plan builder:
  `plan/build.rs`, `plan/chain.rs`, `plan/value.rs`, and
  `plan/field_ref.rs`, with `pick!`, `FieldRef`, `Runs`, and `Opens`.
  `Plan::encryption` moves into `Planned` (ADR-0007, amended 9 November
  2026). Remove the context path type `Label` and `IntoLabel`: a plan's
  context is its declared `Scope` parts, and the guest sends parts, not
  a path. Move EQL, Go, and the guest to the new API in the same change.
  Keep an entry point for a standalone borrowed value. `encrypt_as(&value,
  ..)` goes with the structural API, and the owned entry points take the
  value by value.
  The removal of `Label` is also listed in [Apply the naming
  review](#apply-the-naming-review); it happens once, here.
- **Why.** Two APIs for the same job make the right one hard to find.
- **Done already.** The new API exists beside the old one. The first
  pull request for #1488 makes `Planned` the one lowering of a data plan:
  `dynamic::planned::compose` and `opening` build each field's combinator
  from the parsed plan, and `encrypt_with`, `decrypt_with`, `contexts()`
  and the checks read them. The dynamic path no longer uses the plan
  builder. Those functions do not yet build a `Planned`: they run the
  lowering themselves. That inversion, the builder, the chain, the old
  traits and `Label` are still to be removed.
- **Tracked in.** Issue #1488 is open. Its first pull request is the
  lowering; the removals follow it.
- **Finished when** the old API is gone, and every consumer uses the new
  API.

#### Wipe plaintext in the remaining cases

- **What to build.** Wipe the parts of a Serde value that were decoded
  before a later part failed. Add an adapter that wipes a decrypted value
  when it is dropped.
- **Why.** Plaintext must not stay in freed memory.
- **Done already.** Collections wipe the values decoded before a failure.
  Cancellation and drop are tested (#1493, #1501).
- **Tracked in.** Issue #1468 is open: a Vitamin C buffer type. Issue #1458 is open: data keys by reference. Issue #1480 is closed. Pull request #1503 is open. A decrypted `OpaqueBlob<T>` wipes its value when it is dropped, and its `into_inner` returns a `Zeroizing<T>`. The pull request records the partial Serde decode as a known gap. A drop-wiping adapter for a single value, such as `Zeroizing<String>`, needs Vitamin C to implement `FromScalar` for `Zeroizing<T>`. Pull requests #1493 and #1501 are merged.
- **Finished when** the conformance profile for the lifecycle covers both cases.

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
  is `OpSpec` today. The plan writes `Op`. The naming review confirmed it on 8 November 2026.
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
- **Tracked in.** The pull request for #1279, #1318, #1317, #1321 and #1233 does this area's `Op` enum and the `Matches` case change. Issues #1319 and #1321 were open; #1321 closes with that pull request. Issue #1320, the inverted-range rule, is closed: this plan's decision superseded it.
- **Finished when** these are all true:
  - the dynamic enum is generated from the `op` types;
  - `Matches` has no type parameter;
  - a test shows that each operator's three faces name the same operator.

#### Match configuration: one analyzer

Decided on 7 November 2026, as area five of the query design review. The
design is the query artifact's; the adjustments below are the plan's.

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
- **Tracked in.** Issues #1319, #1112, #1398, #1399, and #1299 are open. Issue #1309 is closed. Pull request #1397 is merged.
- **Finished when** these are all true:
  - the conformance case for the rc.3 mapping passes in Rust and Go;
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
  1. One declaration per index and operator. `Op`, `OpSpec` today, is
     generated from the `op` types. Each index declares its operators and admitted
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
  4. `FieldIndexes` on the dynamic plan. The dynamic path then shares
     the typed derivation itself, through `Index<ValueFrame>`
     implementations per index kind. Both paths run the one executor
     that ADR-0007 asks for. Dan closed this question on 8 November
     2026.
- **Issues.** #1318 and #1279 are closed by steps 1 and 2. #1309, short
  tokens, is a stage in the analyzer. The searchable-encryption investigation is
  independent: a future SSE index is one more index declaration.
- **ADRs.** ADR-0009 describes `Supports`, `Answers`, `DefaultIndex`, and
  `.via`. The `MatchConfig` documentation says a field and its query agree "by
  construction". That is true only for one-value plans today. Both
  are amended, not contradicted in silence.
- **Tracked in.** Steps 1 and 2 are one pull request, which closes #1279, #1318, #1317, #1321 and #1233 (rule 2, the second order index). It brings `prepare`, the `sem::query` rules and `Op`, and drops `Matches`'s case parameter; the analyzer of "Match configuration: one analyzer" is its own work (#1319). Steps 3 and 4 are #1486 and #1488.
- **Finished when** these are all true:
  - every index's operators appear in one declaration, and a test shows
    the typed and dynamic lookups agree on every index;
  - a plan with two match indexes, or with `Ore` and `Ope`, is refused on
    both paths;
  - `DefaultIndex`, `.via`, `MatchCase`, and `PlanError::IndexOptions`
    are gone;
  - ADR-0009 and the `MatchConfig` documentation are amended.

### 5. Packaging, and two key provider features

- **Packaging and names.** Crate moves, the shared format crate, and the
  final names. The [packaging
  document](2026-10-25-stack-encrypt-packaging.md) has the proposal.
- **Split the leaf cipher.** One small clean-up inside the crate, below.
- **Keyset selection and claims.** Two optional features of the ZeroKMS
  key provider, below. Nothing else in this plan depends on them, and no
  merged pull request implements either.

#### Split the leaf cipher into sealing and opening

Vitamin C's `Cipher` trait has a `seal` method and an `open` method.
Stack implements it twice, in `packages/stack-encrypt/src/cipher.rs`:
`MintedKeys` only seals, and `BoundKeys` only opens. Each type still has
to provide the other method, and that method only returns an error.

Fix this in the packaging pass. One option splits the trait into a
sealing capability and an opening capability. Another changes the
internal adapter in some other way. Decide this separately from the
[retirement of `AsyncCipher`](2026-10-25-stack-encrypt-packaging.md#retire-asynccipher)
in the packaging document.

- **Tracked in.** No issue. Draft pull request #1522 reworks the stack-kms key source traits. It is adjacent.

#### Choose the keyset from the data

Today the caller resolves a keyset by hand and passes it to every call,
as [Connect and choose a keyset](#connect-and-choose-a-keyset) shows.
The proposal lets a declaration name the plaintext field that contains
the keyset, so a record selects its own keyset:

```rust
// Proposed. `tenant_id` holds the keyset's name. `id(field = "..")`
// selects by UUID instead.
#[stash(struct = User, scope = "users", keyset(name(field = "tenant_id")))]
struct EncryptedUser { /* .. */ }

// The call takes the client, and the record selects the keyset.
let encrypted: EncryptedUser = user.encrypt_into(&cipher).await?;
let encrypted: Vec<EncryptedUser> = users.encrypt_into(&cipher).await?;
```

Rules for the proposal:

- A missing, unknown, unauthorised, or disabled keyset is an error. There
  is no fallback to the default keyset.
- The selector resolves before any key is fetched. A batch is split by
  resolved keyset. The results keep the order of the input.
- A keyset selector selects a keyset. It does not add its field to the
  context. A scope does not select a keyset.
- Where the business tenant ID is not the keyset's name, the application
  supplies an explicit mapping. The declaration never carries code.
- A query has no record to read, so the caller supplies the keyset, or a
  typed input that the declaration maps to one. No query term compares
  across keysets: a search over several keysets is one term per keyset.
- Decryption uses the keyset ID stored with the ciphertext, as today. It
  never resolves a name again.
- If the caller passes a keyset and the record selects one, the two must
  match, or the call is refused. Neither wins silently.

- **Tracked in.** No Rust issue. Related open issues: #1048, the Go eager keyset; #735, a keyset mismatch is silently unsearchable; #561, a per-operation keyset in TypeScript; #1312, Go control-plane keysets. Issue #832 is closed. Pull request #1407, open, is the Go control SDK.

#### Claims the key provider resolves

A claim is a binding whose value the key provider resolves from the
caller's verified token. The `sub` of a JSON Web Token (JWT) is one.
The client names it and never sees the value, so a claim is in the
stored context and never in the query context. Only a reader whose
token resolves to the same value gets the key.

[Binds, claims, and
labels](2026-11-08-stack-encrypt-key-policy.md#claims) has the design.
The plan's rules:

- A claim is declared on the type, `bind(claim = sub)`, and never added
  on one call. A per-call claim could make a row unreadable to everyone
  else without anyone noticing.
- The claim type belongs to the provider: `zerokms::Claim::Sub` and
  `zerokms::Claim::Custom(name)`. A `ResolvesClaims` trait gates it.
  A declaration with a claim fails to compile against a keyset whose
  provider does not implement the trait. A dynamic declaration with a
  claim part is refused at load on such a provider, before any key I/O.
- A claim is strict by construction. Lose the claim, lose the data.
  Where a fact only needs recording, the plan recommends a
  [label](#labels) instead.
- The claim resolves from the bearer token on the request. The
  `@cipherstash/stack` native entry does not yet send the caller's
  own token on each call (#1565). A claim on that path waits for that fix.

```rust
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Note, scope = "notes", bind(claim = sub))]
struct EncryptedNote {
    body: Ciphertext,
}

let encrypted: EncryptedNote = note.encrypt_into(&keyset).await?;
let note = Note::decrypt_from(encrypted, &keyset).await?;
```

- **Tracked in.** Issue #1565 is open. Issue #1067 is open: Stack Encrypt never sends key request items to ZeroKMS. That is the prerequisite. Issue #1045 is closed.

## Open questions and decisions to be made

The lead who approves this plan decides each question.

| Question | Options | Recommendation |
| --- | --- | --- |
| For each change that would alter the stored format, should it keep the rc.3 format or add a new version? | Keep rc.3 data readable and searchable. Or add a version beside it | Decide for each change when it is designed |
| Should a record choose its keyset from a plaintext field? | The declaration in [Choose the keyset from the data](#choose-the-keyset-from-the-data). Or the caller keeps resolving the keyset by hand | The declaration |
| Should this plan ask ZeroKMS version 2 to derive the data key over the key request items, not only the descriptor? | Yes, so a bind or a claim is enforced by derivation. Or keep the tag check as the only enforcement. The version 2 work decides | Yes. The [key policy document](2026-11-08-stack-encrypt-key-policy.md#what-zerokms-must-do) asks for it |
| Which change owns envelope version `0x02`: this plan's key request items, or #1524's key backend header? | One version 2 header that carries both, shared with the EQL key header `h`. Or separate bytes | One header. Decide with the key-vendor work before either lands |
| What privacy claim can be made for match terms of short words? | Accept what they reveal, and document it. Or change how short words are stored | No recommendation yet. Merging #1397 did not show that they reveal nothing new |
| Which Vitamin C crate should own `Base64Text` and `Base85Text`? | A new Vitamin C types crate that also holds key types. Or a small encoding crate | Vitamin C owns them, decided by Dan on 8 November 2026. The crate is to be confirmed, probably the types crate |
| What crate layout should the final API use? | The proposal in the packaging document | Review the layout proposal when the crate moves begin. The names are decided |

### Names decided in the naming review

Dan decided each name on 8 November 2026, one at a time, against the
packaging document's proposal and the names already on `next`. The
[Apply the naming review](#apply-the-naming-review) item carries the
renames.

| Name | Decision |
| --- | --- |
| `Cipher`, `Keyset` | The connection, today `StackCipher`, and the handle bound to one keyset, today `KeysetCipher`. Decrypt through a `Cipher` opens values from any keyset it holds. The clash with Vitamin C's `Cipher` trait is accepted. Go renames to match: `encrypt.Client` becomes `Cipher`, with `NewCipher`, and the keyset-bound `encrypt.Cipher` becomes `Keyset`. A Go program regenerates once |
| `CipherRef<'c, K>` | One borrowed value for both paths, a connection and an optional keyset ID, built by `From<&Cipher>` and `From<&Keyset>`. Replaces the `CipherScope` trait and the `dynamic::Scope` enum. A design decision, not only a name |
| `Plan` | A record's declaration as data. `TargetDefinition` is dropped |
| `Plan::scope(..).fields(..)`, `encrypt_index`, `passthrough`, `query`, `pick!` | Removed. The hand-built plan builder, settled on 4 October 2026, goes with the structural API. The derive emits the combinators, and `Planned` lowers a data plan to them (ADR-0007, amended 9 November 2026). `EncryptionPlan::record(..).field(..)` is dropped |
| `Label`, `label`, `labels`, `label_tag` | The key tag fact and its operations. The old context path type of that name, a field's declared scopes as `users/email`, is removed: those are `Scope` parts. Go's `ContextLabel()` goes with it |
| No `Request` type | A binding sends a serialised `Plan` alone for a check, an operator list, or a query plan, and a serialised `Planned` for encrypt, query, and decrypt. The ZeroKMS unit of work that is `Request` today becomes crate-private, built on stack-kms's payload types |
| `Query`, `Stored` | Two marker traits on the term types. `Query` marks a value a query sends, today `op::QueryTerm`. `Stored` marks a stored index term, today `LabelledTarget`. `EqualityTerm` and the order terms implement both; `MatchTerms` only `Stored`; `MatchQuery` only `Query`. `QueryToken` stays the run-time guard |
| `QueryTerm` | The dynamic field handle's result, unchanged |
| `Op` | The public dynamic operator enum, today `OpSpec` |
| The chain `Scope::new(..)`, `Bind::new(..)`, `Scope::new(..).bind(..)` | The caller-supplied context input. No separate type; `ContextExtension` from #1504 goes. A trait bound, `impl ContextParts`, names what an entry point accepts |
| `JsonTreeDocument`, `JsonTreeQuery`, `JsonTreeLeafQuery`, `JsonTreeElementsQuery`, `JsonTreePredicateQuery` | Kept. The SQL domain `eql_v4_json_search` and the dynamic target `JsonSearch` are the other two names of the one stored type |
| `Planned`, `Positioned<Vec<T>>`, `Claim`, `ResolvesClaims`, `#[derive(Scalar)]`, `Base64Ciphertext` | Confirmed. `Base64Ciphertext` is the text form of a bare `Ciphertext`, which keeps its header inside. EQL payloads instead carry a Base64 key header `h` beside a Base85 `c`, as the JSON tree does. There is no `Base85Ciphertext` target |
| `contains`, `at`, `elements`, `predicate`, `children` | The JSON query methods on a document's marker. Confirmed |
| `contexts()`, `context()`, `assert_context!`, the `testing` feature, `encrypttest` | Showing and asserting a context, in Rust and Go. Confirmed |
| `scope(..)`, `bind(..)`, `bind(claim = ..)`, `keyset(name(field = ..))` | The declaration attributes. Confirmed |
| `stack-kms` to `stack-zerokms` | Not decided. The crate rename is part of the crate layout question, which stays open |
| `scope = ".."`, Go `scope=` | The record's name is its first scope, so the attribute and the Go tag both say `scope`. Today they say `context = ".."` and `context=`. The builder's `Plan::scope(..)` was part of this decision and goes with the builder. Decided by Dan on 8 November 2026 |
| `plan.query(field, op)`, `plan.field(name)`, `IndexNotDeclared`, `FieldIndexes`, `StageSpec`, `Match<Dynamic>`, `NotPortable` | The dynamic interface names. Confirmed |
