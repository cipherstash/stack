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

The history of each decision is in the [review
log](2026-10-24-stack-encrypt-api-review.md).

## Terms

| Term | Meaning |
| --- | --- |
| AAD (additional authenticated data) | Data that encryption checks for one ciphertext, but does not encrypt. Stack Encrypt builds it from the context. See [Context and AAD](#context-and-aad) |
| Binding | A part of the context that ties a ciphertext to its row, such as a row ID. It is in the stored context and not in the query context. Passed as `Bind::new(..)` |
| Caveat | A named, typed fact added to a stored value's key tag by tag refinement, such as `row_id` or `created_at`. ZeroKMS verifies it. See [Tag refinement](#tag-refinement) |
| Ciphertext | One encrypted value, as the Rust `Ciphertext` type. It is stored as bytes, or as Base64 text |
| Conformance profile | A named, versioned set of test cases for one area, such as `record-contexts-v1`. Rust and Go run the same cases. The files are in `conformance/stack-encrypt/v1/` |
| Context name | The last declared scope of a field: its name by default, pinned when the Rust field is renamed. Two fields of one record never share one |
| Context | Data that a ciphertext is tied to, such as a column name or a row ID. Decryption needs the same context. See [Context and AAD](#context-and-aad) |
| Dynamic interface | The engine's interface for languages other than Rust. It takes a declaration and values as data, not as Rust types |
| EQL (Encrypt Query Language) | The PostgreSQL types and functions in `packages/eql` that store encrypted values and answer queries on them |
| Guest | The Rust engine compiled to WebAssembly. The Go SDK runs it inside the Go process |
| Keyset | A set of keys in ZeroKMS. Every data key belongs to one keyset. A tenant can have its own keyset |
| Opaque blob | A whole value, such as a struct, encoded and sealed as one ciphertext. Nothing inside it can be searched |
| Passthrough field | A field stored unencrypted next to the encrypted fields. It is not authenticated |
| Query context | All the scopes of a context, declared and caller-supplied. Search terms derive under it. See [Query context and stored context](#query-context-and-stored-context) |
| Scope | A part of the context that narrows the data and the queries over it. The declaration supplies the first scopes, such as `users` and `email`; the caller adds more, such as a tenant ID, with `Scope::new(..)` |
| Search term | A value stored next to a ciphertext, so that a query can find it without decrypting it. Equality, order, and match each use their own term |
| Stored context | Every part of a value's context. The data key and the AAD derive under it |
| Stored format | Everything Stack Encrypt writes to the database. See [The stored format stays compatible with Go rc.3](#the-stored-format-stays-compatible-with-go-rc3) |
| Tag refinement | Replacing a stored key tag with an HMAC of it and a caveat, so ZeroKMS can verify the caveat when it returns the key. See [Tag refinement](#tag-refinement) |
| Target | The encrypted type that a value is stored as, such as `Ciphertext`, an EQL type like `TextEq`, or a record type |

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
let user = User::decrypt_from(encrypted, &cipher).await?;
```

The derives need no Serde. A program that stores an encrypted value as
JSON adds `Serialize` and `Deserialize` to the encrypted type. That is
the same as for any other type.

To tie every field to one row, the caller supplies the row ID as a part of
the context, and supplies it again to decrypt. The row ID is a binding
part. It is in the stored context, so the key and the AAD depend on it. It
is not in the query context, so a query still finds the row across the
column.

[Query context and stored context](#query-context-and-stored-context) gives the rule.
The API for declaring a binding is an [open
question](#open-questions-and-decisions-to-be-made).

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
`EncryptedMember`. So the query matches the stored values.

A match query works in the same way, on a field with a match index. Its
answer can include rows that do not match. So the caller decrypts the rows,
and checks each one.

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

A JSON query works like a [scalar query](#query-a-field). An operand type
encrypts into its EQL query type with `encrypt_into`, the same verb as
every other value. A query needs two things from the field's declaration:

- **The column context.** Each path's selector is derived under it, so the
  query must use the same context as the stored documents.
- **The options.** They say which paths have order terms, and how far a
  wildcard such as `[*]` expands. An order query on a path without order
  terms would find no rows, so Stack Encrypt refuses it.

With the default options, the operand needs only the column. The caller
passes it as the context, as a scalar query does:

```rust
use eql_bindings::v4::json_tree::{JsonTreeLeafQuery, JsonTreeQuery};
use stack_encrypt::json::{AtPath, Contains};

// Not on `next` yet: the public JSON operand types.
let ada: JsonTreeQuery = Contains(json!({ "name": "Ada" }))
    .encrypt_into_with_context(&keyset, Scope::new(&column))
    .await?;
```

With custom options, the operand names the target type of the field. The
target's declaration supplies the column and the options. An order query
on a path that the target does not order is refused.

```rust
use eql_bindings::v4::json_tree::JsonTreeElementsQuery;
use stack_encrypt::json::ElementMatch;

// Not on `next` yet: the public JSON operand types.
let ada: JsonTreeQuery = Contains::<EncryptedProfile>(json!({ "name": "Ada" }))
    .encrypt_into(&keyset)
    .await?;
let older: JsonTreeLeafQuery = AtPath::<EncryptedProfile>::gt("$.age", 30)
    .encrypt_into(&keyset)
    .await?;
let adults: JsonTreeLeafQuery = AtPath::<EncryptedProfile>::between("$.age", 18, 65)
    .encrypt_into(&keyset)
    .await?;
let home: JsonTreeElementsQuery = ElementMatch::<EncryptedProfile>::at("$.visits[*]")
    .eq("place", "home")
    .gt("at", 15)
    .encrypt_into(&keyset)
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

The kinds of JSON query, and what each one finds:

| Query | What it finds | EQL query type |
| --- | --- | --- |
| Containment | Rows whose document contains the given document, or is contained by it | `JsonTreeQuery` |
| Comparison at a path | Rows where the value at an ordered path equals, orders against, or lies between the given values | `JsonTreeLeafQuery` |
| Element match | Rows where one element of an array meets several conditions together | `JsonTreeElementsQuery` |
| Jsonpath predicate | Rows where a SQL/JSON path predicate is true | `JsonTreePredicateQuery` |
| Children and child count | The entries directly below one node, or how many there are | A node token |

The operand types are named `Contains`, `AtPath`, and `ElementMatch`,
with `Predicate` for a jsonpath predicate and `Children` for the entries
below a node. The user agreed these names on 7 November 2026.

The operand types are not new. The dynamic interface already has one
private input type for each operator, in `stack_encrypt::dynamic`:

- `DocumentInput` for containment;
- `AtInput` for a comparison at a path;
- `ElementsInput` for element match.

The dynamic parser reads the JSON object a binding sends into one of
them. The engine then derives the operand from it. The static form makes
those types public, with constructors. The parser reads into the same
types, so both forms share one set of input rules.

The public forms do not exist on `next`. Today a Rust program queries a
JSON document [through a plan](#query-through-a-plan). A plan is part
of the dynamic interface. The dynamic interface is still the right tool for a
query known only at run time, such as a jsonpath predicate that a user
types.

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
`Vec<Ciphertext>`, one for each byte string, with no wrapper type.

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

The user agreed this behaviour on 7 November 2026. It is what pull
request #1501 built.

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

Each row crosses the boundary as one transport frame. A query names a field
and an operator, such as `eq` or `contains`, and gives a value. The engine
returns the query value, with its EQL type.

The output keys and the type names are part of the stored format, so they
cannot change. The output keys are `c`, `eq`, `match`, `ore`, `ope`, and
`passthrough`. The type names include `int64` and `string`.

#### Query through a plan

On `next`, a Rust program queries a JSON document through a plan. The plan
is the declaration as data, so this is the dynamic interface with typed
operators. `stack_encrypt::op` names the operator. `on` names the plan, and the plan
supplies the column and the options:

```rust
use stack_encrypt::{json::JsonPath, op, NonEmpty};

// Containment: documents that contain this document.
let ada = keyset
    .query(op::Contains, &json!({ "name": "Ada" }))
    .on(&plan)
    .await?;

// A comparison at a path. `$.age` must be an ordered path.
let older = keyset
    .query(op::AtPath(op::Gt), &("$.age", 30))
    .on(&plan)
    .await?;
let adults = keyset
    .query(op::AtPath(op::Between), &("$.age", (18, 65)))
    .on(&plan)
    .await?;

// The selector of a path, for `->` in SQL.
let age = keyset
    .json_selector(&JsonPath::parse("$.age")?, NonEmpty::new(column.clone())?)
    .await?;
```

The query values convert to the EQL query types: `JsonTreeQuery` for
containment, and `JsonTreeLeafQuery` for a comparison at a path.

A chain call that needs a scope or a binding takes it through the paired
entry point, as the typed API does:

```rust
// Not on `next` yet: the paired chain entry points and `Scope`.
let by_tenant = keyset
    .query_with_context(op::Eq, "alice@example.com", Scope::new(tenant))
    .on(&plan)
    .await?;
let user: User = keyset
    .decrypt_with_context(encrypted, Scope::new(tenant).bind(row_id))
    .using(&plan)
    .await?;
```

Three kinds of JSON query have no typed operator on `next`. They exist
only as data, through `stack_encrypt::dynamic::query_term`, with the
operator named as text:

- element match: `"element_match"`;
- jsonpath predicates: `"match"`;
- children and child count: `"children"` and `"child_count"`.

Go has generated methods for the first two, such as
`Fields.Profile.Elements.Visits.Match`.

#### Query through a field marker

The derive emits one marker for each field of a record, such as
`EncryptedMember::EMAIL`. A marker names the field, its plaintext type,
and its accessor. It is the value the plan builder takes to declare the
field, and the value a query takes to select it.

The derive also emits `encryption_plan()`. It builds the record's `Plan`
through the plan builder, once, and keeps it. A query through a marker
reaches that plan itself. Decided on 7 November 2026.

```rust
use stack_encrypt::op;

// Not on `next` yet: field markers, `encryption_plan()`, and `using` for
// a query. Today a query names a plan written by hand:
// `cipher.query(op::Eq, value).on(&plan)`.
let by_email = keyset
    .using(EncryptedMember::EMAIL)
    .query(op::Eq, "alice@example.com")
    .await?;
let adults = keyset
    .using(EncryptedMember::AGE)
    .query(op::Between, &(18, 65))
    .await?;
let ada = keyset
    .using(EncryptedProfile::DOCUMENT)
    .query(op::Contains, &json!({ "name": "Ada" }))
    .await?;

// The same plan, for the chain and the dynamic interface.
let plan: &Plan = EncryptedMember::encryption_plan();
```

```sql
SELECT id, profile FROM customers WHERE profile @> $1::eql_v4.query_json;
```

Whether `using` comes before `query`, as above, or after it, is decided
with the query design. A program can also build a `Plan` by hand, from a
declaration it reads at run time, and select it with `using`.

Below the definition, `stack_encrypt::dynamic::record` has the functions
that take a declaration as a frame: `plan_with`, `encrypt_with`, `query`,
and `decrypt_with`. Each takes a `TargetResolver`. The resolver runs the EQL
type that a field names.

On `next`, each program writes its own resolver over
`eql-bindings`. In the target state, `eql-bindings` provides it. See [A
ready-made EQL resolver](#a-ready-made-eql-resolver).

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
operators each field supports. It does not keep its own copy of the rules.

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
| Binding | `bind` | A row's UUID, or the IP address of the writer | No | Yes | Yes | ZeroKMS and the AEAD |


The words were decided on 7 November 2026. A caller scopes a value with a
scope. A scope narrows the data and the queries over it. A caller binds a
value with a binding. A binding ties the ciphertext to its row and leaves
the queries as they are.

"Extend" and "extension" are no longer used. Go `Extend` becomes `Scope`, with
`Extend` kept as a deprecated alias until Go 0.1.0. `Bind` is added to
Go.

A part is a scope unless the declaration marks it as a binding, because
that is what Go rc.3 writes. A binding can be stored in the row as a context field,
so the reader takes it from the row. ZeroKMS logs the descriptor at every
key retrieval, so a binding such as the writer's IP address is in the
access log. The descriptor has a length limit. It is also sent to ZeroKMS, so the
part leaves the customer's system.

ZeroKMS version 2 is planned to remove the limit and to encrypt the
access log.

A caveat added by [tag
refinement](2026-11-07-stack-encrypt-tag-refinement.md) is not a part of
the context. ZeroKMS verifies it. It is in neither the query context
nor the AAD.

The use case is access intelligence. Each value is bound to its row by a
client-generated UUID. A query by column or by tenant still finds it.

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
let call = keyset
    .using(EncryptedUser::EMAIL)
    .query_with_context(op::Eq, "alice@example.com", Scope::new(42_u64));
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
- **Each element of a collection stands alone.** Each element has its own
  data key. Each element is authenticated on its own.
- **Order terms do not answer equality.** An order-revealing encryption
  (ORE) term does not answer an equality query. A field that needs both
  declares both indexes.

## Remaining work

The work is in the order that the customer needs it. The Go customer work
comes first. The Rust API work follows, and the crate moves come after the
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

- **What to build.** Match options that a Go program can set: the
  tokeniser, the filters, and the n-gram length. Issue #1112 tracks the
  part in the generator.
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
- **Done already.** Go writes and reads the format (#1369, #1370). #1503
  adds `OpaqueBlob`, and is in review.
- **Finished when** Rust and Go each open blobs that the other wrote, and
  the conformance profiles cover it.

#### Tag refinement

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
  records, with passthrough fields, renamed fields, nested records, and
  stored context.
- **Why.** The derives give the [record example](#encrypt-a-record).
- **Done already.** One value (#1404) and collections (#1501). #1504 adds
  the record derives, and is in review.
- **Finished when** the public examples for mixed and searchable records
  run as tests.

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

- **What to build.** Make the dynamic interface's input types public.
  There is one for each kind of JSON query: containment, comparison at a
  path, element match, jsonpath predicate, and reads of children. Give
  each one constructors, and an `EncryptTarget` implementation that
  encrypts it into its EQL query type. The target type of the field
  supplies the column and the options. The dynamic parser keeps reading
  into the same types, so there is one definition of each input.
- **Names.** `Contains`, `AtPath`, `ElementMatch`, `Predicate`, and
  `Children`, in `stack_encrypt::json`. Agreed on 7 November 2026.
- **Why.** On `next`, a Rust program needs a plan for any JSON query, and
  needs the dynamic interface for element match, predicates, and children.
  Go already has typed methods for these.
- **Done already.** The input types and their parsing rules, as private
  types in `stack_encrypt::dynamic::json_query`. Typed containment and
  comparison at a path, through a plan (`op::Contains`, `op::AtPath`). The
  EQL query types exist in `eql-bindings`.
- **Finished when** the [static JSON query
  example](#query-a-json-document) compiles, and an order
  query on a path the target does not order is refused.

#### Field markers and the encryption plan

Decided on 7 November 2026, as difference six of the context artifact
review.

- **What to build.** The derive emits one marker for each field, as an
  associated constant such as `EncryptedMember::EMAIL`, with the field's
  name, its plaintext type, and its accessor. The marker is the `FieldRef`
  the plan builder takes, and the handle a query takes. The derive also
  emits `encryption_plan()`. It returns the record's `Plan`, built once
  through the plan builder with the markers as its arguments. `using`
  selects a plan or a marker, for encryption and for a query; `on` goes.
  Typed Rust option factories, and the same options read from data in the
  dynamic interface.
- **Why.** A query must use the same declaration as the stored values. The
  caller must not write a second plan by hand. One marker type serves the
  builder and the query, so the derive lowers to the builder with no
  second mechanism.
- **Done already.** `FieldRef` and `pick` exist in `plan/field_ref.rs`.
  The derive already lowers a structural record to the builder. Queries
  work through a plan written by hand: `cipher.query(op, value).on(&plan)`.
- **Cannot fail.** `build()` refuses a repeated field name or a shared context name.
  The derive sees every field, so it refuses those at compile time, and
  `encryption_plan()` returns `&'static Plan`, not a `Result`. The
  hand-written builder keeps the runtime check. The dynamic grammar needs
  it.
- **Later.** A compile-time duplicate-field check for the hand-written
  builder, through a type-level list of markers, stays a follow-up, as the
  artifact says.
- **Finished when** the [marker example](#query-through-a-field-marker)
  compiles, and tests show that a query cannot run without its plan or its
  required context.

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
  `ContextExtension` is renamed for the scope vocabulary; its new
  name is decided with the field reference design. The plan builder's
  `.context(..)` and `.context_field(..)` and the derive's
  `#[stash(context_field)]` are the forms this replaces.
- **Required parts.** A Rust declaration lists the parts the caller must
  supply, with kind and type, as the artifact's `refined_by::<T>()` does,
  extended to bindings. An undeclared part is refused. Optional is
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
- **Why.** Access intelligence needs each value bound to its row, and found
  by a column or tenant query. [Two scopes of one
  context](#query-context-and-stored-context) has the rule.
- **Vocabulary.** The Rust chain's `.extend(..)` is removed; the context
  argument carries the scopes and bindings instead. Go `Extend` becomes
  `Scope`, with `Extend` as a deprecated alias until 0.1.0. `Bind` is added
  to Go. The context contract and the conformance README say "scope"
  instead of "extension". The frozen vectors do not change, because no key
  on the wire names the operation.
- **Done already.** Nothing. Today every part is in both scopes.
- **Finished when** these are all true, in Rust and in Go:
  - a record with a binding row ID encrypts;
  - a column query finds it;
  - it fails to open under another row ID;
  - the stored bytes of a record with no binding are unchanged.

#### One context argument, and paired entry points

Decided on 7 November 2026, as differences two and five of the context
artifact review.

- **What to build.** The context argument is one of three values, built
  before the call: `Scope::new(..)`, `Bind::new(..)`, or
  `Scope::new(..).bind(..)`. Several of one kind chain:
  `Scope::new(tenant).scope(region).bind(id)`. The order is fixed by type:
  after the first `bind`, `scope` is not offered. `Scope::new((a, b))` is
  one grouped part. That is a different context from two parts.
  Both layers take it through paired entry points:
  - the typed API: `encrypt` with `encrypt_with_context`; `encrypt_into`
    with `encrypt_into_with_context`; `decrypt_from` with
    `decrypt_from_with_context`;
  - the chain: `encrypt` with `encrypt_with_context`; `query` with
    `query_with_context`; `decrypt` with `decrypt_with_context`. The
    chain's `open` is renamed `decrypt`. No chain state offers
    `.context(..)`, `.extend(..)`, `.scope(..)`, `.bind(..)`, or
    `.keyset(..)`. The keyset is chosen before the chain starts.

  A query entry point accepts a `Scope` and nothing else, so a binding in
  a query does not compile. A part whose source is a row field is read
  from the plaintext on encrypt. On decrypt, a stored part may be passed,
  and is then checked against the row before any key is fetched. That
  check is what `ExpectedContext` does today; it stops being a public
  type.
- **Why.** The typed API already pairs its entry points (#1404). A
  value for the context reads the same on both layers. A builder
  state for the context, and a part added later in a chain, are the
  mistakes the artifact describes.
- **Done already.** The scalar pairs (#1404). The record pairs, in
  #1504. The chain's `encrypt`, `query`, and `open`, with `.extend(..)`
  and `.context(..)` on several states.
- **Order of calls.** The keyset is chosen first. It is the receiver of
  every entry point: `keyset.encrypt(..)`, `keyset.using(..)`. Whether
  `using` comes before or after `query` is decided with the query design.
  Difference seven of the context artifact review, 7 November 2026.
- **Rename.** `Scope<'a, K>` in `dynamic::record` and `CipherScope` in the
  owned API both mean the cipher a call runs under. Both are renamed in
  the naming review, so that `Scope` means a part of the context.
- **Finished when** these are all true:
  - the examples in [Target state](#target-state) compile;
  - the compile-fail cases in `tests/ui` cover a binding in a query, and
    a scope after a bind;
  - the chain has no `.context`, `.extend`, or `.keyset` state.

#### Show the context

Decided on 7 November 2026.

- **What to build.** Two ways to see a context before any key is fetched:
  - `contexts()` on a `Plan`, listing each field's query context and
    stored context, with a typed placeholder for every caller-supplied
    part. The derive's `encryption_plan()` gives it to every record, and
    a hand-built plan has it too.
  - `context()` on a prepared call. It gives the exact query context and
    stored context the call will use, with the caller's values filled in.
    Each part shows its type.

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
- **Finished when** these are both true:
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
- **Finished when** the public examples pass a context by reference, with
  no clone, and compile.

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

### 4. After the customer release

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
| How does a declaration mark a binding in the context, in Rust and in the dynamic grammar? | A kind on each part of the declaration, in the derive, the plan builder, and the Go struct tag. The spelling depends on the context vocabulary and the field reference design, decided with the context artifact | Decide with differences three to seven of the context artifact |
| Should keysets be chosen from data, and should Stack Encrypt use ZeroKMS lock context? | Optional capabilities of a key provider. Or leave them out | Optional capabilities, after the customer release |
| What privacy claim can be made for match terms of short words? | Accept what they reveal, and document it. Or change how short words are stored | No recommendation yet. Merging #1397 did not show that they reveal nothing new |
| Which crate should own `Base64Text` and `Base85Text`? | A small Vitamin C encoding crate. Or keep them in `eql-bindings` | A small Vitamin C crate, re-exported by Stack Encrypt and EQL |
| What names and crate layout should the final API use? | The proposal in the packaging document | Review the proposal after the customer release |
