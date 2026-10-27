# stashgen

`stashgen` writes the Go code that encrypts a struct with Stack Encrypt.
You declare how each field is encrypted with `stash` tags.
`stashgen` writes the encrypted type and the functions that encrypt, decrypt and search it.
Your program calls those functions, and it never builds or names a plan.

## Use the SDK

1. Add the generator to your module.
   This needs Go 1.26.10 or later (or 1.27.3 or later on 1.27):
   those are the first releases whose `crypto/x509` blocks the compromised eMudhra intermediate CAs
   ([CVE-2026-111943](https://github.com/golang/go/issues/82345)).
   The module's `go` line requires 1.26.10, so under the default `GOTOOLCHAIN=auto` an older local Go downloads and switches to 1.26.10.
   A minimum cannot exclude 1.27.0 to 1.27.2, which are also vulnerable: do not build with those.

   ```sh
   go get -tool github.com/cipherstash/stack/languages/golang/cmd/stashgen
   ```

2. Put a `stash` tag on every exported field of the struct, and a `go:generate` comment beside it.

   ```go
   //go:generate go tool stashgen -type User
   type User struct {
   	_     struct{} `stash:"context=users"`
   	ID    int64    `stash:"id,passthrough"`
   	Email string   `stash:"email,encrypt_into=TextEq"`
   	Name  string   `stash:"name,encrypt_into=TextEq"`
   }
   ```

3. Run the generator.
   It writes `user_stash.go` beside the struct.

   ```sh
   go generate ./...
   ```

4. Commit the generated file.

5. Call the generated functions where you write and read.

   ```go
   encrypted, err := users.Encrypt(ctx, cipher, people)
   opened, err := users.Decrypt(ctx, cipher, encrypted)
   query, err := users.Fields.Email.Eq(ctx, cipher, "bob@example.com")
   ```

6. Store the encrypted type.
   Each `encrypt_into` field is one EQL column: `eql.TextEq` implements `driver.Valuer` and `sql.Scanner`, so a database library binds and scans it as the JSON a `public.eql_v4_text_eq` column holds. Stack Encrypt writes EQL v4; see the `encrypt` package README for the EQL types it produces and the Go field type each takes.

7. Run the generator again after each change to the struct or to a tag.
   A change to the fields of the struct stops the build until you do.

8. In CI, run the generator and fail when a generated file changes.

   ```sh
   go generate ./... && git diff --exit-code && test -z "$(git status --porcelain)"
   ```

   `git diff` sees only files git already tracks; the `git status` check also fails on a generated file that was never committed.

The rest of this file is the reference.

## Struct tags

The first part of a tag is the field's name, which is the column name in a database.

| Tag | Meaning |
|---|---|
| `` _ struct{} `stash:"context=users"` `` | the context of every field in the struct |
| `stash:"email,encrypt_into=TextEq"` | seal the field into one EQL value, with the terms that EQL type has |
| `stash:"notes,encrypt"` | seal the field, with no index |
| `stash:"email,encrypt,index=equality;match"` | seal the field, and derive each index beside it |
| `stash:"score,index=ore"` | derive the index alone; no ciphertext is stored, so `Decrypt` leaves the field at its zero value |
| `stash:"profile,encrypt_into=JsonSearch(ordered=$.age)"` | on a `json.RawMessage`, or a struct, map or slice type: store the field as an encrypted JSON document; see "Encrypted JSON documents" |
| `stash:"attrs,index=json"` | refused: a JSON document is stored with `encrypt_into=JsonSearch`, not as an index beside a ciphertext |
| `stash:"id,passthrough"` | store the field as it is |
| `stash:"tenant,context_field"` | the field's value is the context of every other field in the struct, in place of a `context=` tag; stored as it is |
| `stash:"-"` | leave the field out |
| `` _ struct{} `stash:"context=documents,opaque"` `` | seal the struct as one value |
| `stash:"born,encrypt_into=DateEq,null=sql"` | on a field declared over a pointer (`*encrypt.Date`): how it stores `nil`, `null=sealed` or `null=sql`; see "Optional fields" |

A struct has one context: either a `_ struct{}` field with `context=`, or one field with `context_field`, not both.
A `context_field` is a `string` whose value is a label such as `"tenants/acme"`, segments separated by `/`.
Every other field is sealed under that value, so each row is bound to the context it names, and a sealed value copied to another tenant's row does not decrypt there.
The field is stored as it is, in the clear and unauthenticated like a `passthrough` field, so the row names its own context when it is read.
`Decrypt` opens each row under the context it stores; `cipher.Context("tenants/acme")` names the context every row through the cipher is under, and refuses a row stored under another with `encrypt.ErrContextMismatch`.
A query on such a type derives its term under the context the cipher names, so it takes a cipher from `Context`.

> **Take care**
>
> The name and the `context=` value are part of the encryption context of each stored value.
> If you change either one, the rows that you stored before the change do not decrypt, and queries do not find them.
> Do not change them after you store rows. No tag can rename a column and keep its context yet.

> **Take care**
>
> Do not encrypt a decrypted value again to update its row.
> After `Decrypt`, each index-only field is zero, so `Encrypt` stores the term for zero, and a query on that field then matches the wrong rows with no error.
> To update one column, use its `Fields` entry, such as `Fields.Email.Encrypt`.

The index names are `equality`, `match`, `ore`, `ope` and `json`.
A `match` index stores text with no token (an empty string, separator-only text, or text shorter than the n-gram length of 3 characters) as the empty filter, which no query matches, so an optional or short value can live under `match`; the empty filter tells a reader of the column that the value is one of those.
A match query of such text is refused, because an empty filter as a query would match every row.
An EQL `TextMatch` field is stricter: see below.
An index takes its options in parentheses after its name, separated by commas: `index=equality;match(k=3)`.
This build refuses an index with options: a query term is derived with the default options only, so a stored term with other options would never match one.
These words are the same as the Rust API's words for the same behaviour, with two that only Go has.
`opaque` seals the whole struct as one `bytes` field holding a storage blob (see "What crosses the binding").
`json` names the JSON index, which a field reaches only through `encrypt_into=JsonSearch`.

### Encrypted JSON documents

A field with `encrypt_into=JsonSearch` is stored as one encrypted JSON document, an `eql.JSONSearch` in a `public.eql_v4_json_search` column.
For a complete generated model and PostgreSQL query flow, see the [runnable typed-document example](../../encrypt/example/json/README.md).
Declare it as a struct, map or slice type, or as a `json.RawMessage` that holds the document's JSON text:

```go
type Profile struct {
	Name   string  `json:"name"`
	Age    int64   `json:"age"`
	Visits []Visit `json:"visits"`
}

type Customer struct {
	_       struct{}        `stash:"context=customers"`
	ID      int64           `stash:"id,passthrough"`
	Profile Profile         `stash:"profile,encrypt_into=JsonSearch(ordered=$.age)"`
	Notes   json.RawMessage `stash:"notes,encrypt_into=JsonSearch"`
}

// A needle for Contains: a field left nil is not in the query.
type ProfileNeedle struct {
	Name *string `json:"name,omitempty"`
	Age  *int64  `json:"age,omitempty"`
}

q, err := customers.Fields.Profile.Contains(ctx, cipher, ProfileNeedle{Age: &age})
older, err := customers.Fields.Profile.At.Age.Gt(ctx, cipher, 40)
people, err := customers.Decrypt(ctx, cipher, rows) // each Profile is a Profile again
```

The generated code marshals a struct, map or slice type with `encoding/json` when it seals the field, and unmarshals the opened document into the declared type.
It calls `encoding/json` directly, never through `map[string]any`, so an `int64`, a `uint64` and a finite `float64` come back exactly.
The rest of the document comes back as `encoding/json` reads what it wrote, which is not always the value sealed:

- Invalid UTF-8 in a Go string is written as U+FFFD, with no error: `"a\xffb"` comes back as `"a\uFFFDb"`, the replacement character in place of the byte. `stashgen` cannot refuse it, because it is a property of a value, not of a type, and finding it would need a reflective walk of each value at run time, which the generated code does not do. Check text that may not be UTF-8 with `utf8.ValidString` before you seal it.
- A nil map or slice is stored as JSON `null`, and an empty one as `{}` or `[]`. Each reads back as it was (a field with `null=sql` stores a nil pointer as SQL `NULL` instead), but a query tells them apart: `Contains` with an empty map does not match a stored `null`.
- A `time.Time` field is refused, since it is one value, not a document, but a `time.Time` inside a document is accepted. It is stored as the text its `MarshalJSON` writes: RFC 3339, in the time's own offset, with trailing zero nanoseconds left out. One instant in two zones is two strings, so `EqAt` with a time in another zone matches nothing, and an ordering on that path orders the text, which is not time order: `…T10:00:00+10:00` sorts after `…T01:00:00Z`, an earlier instant, and `…:00.5Z` sorts before `…:00Z`. If you query a time, store it as an integer (`t.UnixNano()`) or as UTC text of a fixed width. Any type with its own `MarshalJSON` or `MarshalText` is stored as the text it writes, and queried as that text.

`stashgen` refuses a type that `encoding/json` cannot carry both ways: an interface such as `any` anywhere in it (it reads numbers back as `float64`); a struct field that `encoding/json` drops (unexported, tagged `json:"-"`, or one of two that write the same member); a `MarshalJSON` or `MarshalText` with no matching unmarshal method; a channel or a function.
It refuses a field tagged `json:",string"` anywhere in a document: `encoding/json` stores its number or bool as a JSON string (`"age":"40"`), so `EqAt`, an ordering or a needle by the number would match nothing, and an ordered path would order the text. A document's numbers cross as their exact digits without it.
An unexported embedded struct is fine: its fields are promoted and stored.
An embedded pointer to an unexported struct is refused: `encoding/json` writes its fields but cannot read them back, since it cannot allocate the struct.
An embedded pointer to an exported struct is accepted, but whether it was nil is not stored: it comes back non-nil when the document holds a member it promotes, and nil when it holds none, so a non-nil pointer whose promoted fields are all left out by `omitempty` comes back nil.
It refuses a string, a number and a bool too: a document is a struct, map or slice.
A `[]byte` is refused, since `encoding/json` writes it as base64: declare JSON text as `json.RawMessage`.
The engine parses the JSON text, so an object that names a member twice and an integer outside the 64-bit range are refused with `encrypt.ErrEncoding`.
A `json.RawMessage` comes back as JSON text that holds the same values; key order and the spelling of numbers are not kept.
A pointer field (`*Profile`, `*json.RawMessage`) is optional and must say `null=sql`: a document has no fixed length to hide a missing one behind.
A nil pointer is SQL `NULL`; a non-nil `*json.RawMessage` holding `null` is a stored JSON `null`.
A `json.RawMessage` sealed any other way (`encrypt`, `index=equality`) is bytes, as any type defined over `[]byte` is.
`JsonSearch` takes `json.RawMessage` itself, or an alias of it (`type Doc = json.RawMessage`), and refuses a type defined over it (`type Doc json.RawMessage`): such a type has no `MarshalJSON`, so `encoding/json` would write it as a base64 string, not as the JSON text it holds, where a scalar type is accepted with any type defined over it.

The type takes options in parentheses: `ordered=` names the paths whose numbers and strings carry an ordering term, separated by `;`, and `sealed_root=false` turns off the sealed root (on by default).
`encrypt_into=JsonSearch(ordered=$.age;$.visits[*].at)` orders two paths.
A path in a tag is plain JSONPath: `$`, then `.key` steps of letters, digits and underscores, and `[n]` or `[*]` steps; an ordered path names no position. The engine checks every path when `stashgen` runs.

The field's `Fields` entry has a method per operation:

| Method | Returns | SQL |
|---|---|---|
| `Contains(ctx, c, needle)`, `ContainedBy(ctx, c, needle)` | `eql.JSONSearchQuery` | `col @> $1::eql_v4.query_json`, `col <@ $1::eql_v4.query_json` |
| `EqAt(ctx, c, path, v)` | `eql.JSONSearchQuery` | `col @> $1::eql_v4.query_json` |
| `At.Age.Lt(ctx, c, v)`, `Lte`, `Gt`, `Gte`, `Between` | `eql.JSONSearchLeafQuery` | `(col -> $sel::text) < $1::eql_v4.query_json_leaf`, `$sel` from `At.Age.Selector(ctx, c)` |
| `Selector(ctx, c, path)` | `encrypt.JSONSelection`: `Selector()` and `Open` | `col -> $1::text` |
| `Subtree(ctx, c, path, opts)` | `encrypt.JSONRead`: `Tokens()`, `Open` and `OpenOne` | `eql_v4.json_tree_subtree(col, $1::text[], 64)` |
| `Children(ctx, c, path)`, `ChildCount(ctx, c, path)` | `encrypt.JSONToken` | `eql_v4.json_tree_children(col, $1::text)`, `eql_v4.json_tree_child_count(col, $1::text)` |

`At` has one accessor per ordered path, named for its keys (`$.visits[*].at` is `At.VisitsAt`, `$.a.1` is `At.A1`); two paths with one name, or one path given twice, stop `stashgen`.
An ordering compares the value `->` extracts at its path, and EQL's `<` compares ordering terms alone, so take the selector from the same accessor (`At.Age.Selector`) rather than spelling the path again.
At a wildcard path (`$.visits[*].at`), `->` returns an unspecified element of each row (the entries are stored in a random order), so write the comparison over every match and order by the least or greatest one:

```sql
-- rows with some visit after $2
SELECT id FROM customers WHERE EXISTS (
  SELECT 1 FROM eql_v4.json_tree_path_query(profile, $1::text) AS e WHERE e > $2::eql_v4.query_json_leaf)
-- rows by their earliest visit
SELECT id FROM customers ORDER BY (
  SELECT eql_v4.ord_term(e) FROM eql_v4.json_tree_path_query(profile, $1::text) AS e ORDER BY 1 LIMIT 1)
```

with `$1` from `At.VisitsAt.Selector(ctx, c)` and `$2` from `At.VisitsAt.Gt(ctx, c, v)`; for the latest visit, order by `ORDER BY 1 DESC NULLS LAST` inside and `DESC` outside.
`OpenOne` reads one value and refuses a read whose path has a wildcard before anything is opened; open a wildcard read with `Open`.
A needle and a value are Go values: a `json.RawMessage` of JSON text crosses as it is, and anything else is marshalled with `encoding/json`.
`EqAt` and the orderings take a scalar: a string, a number, a bool, or `nil` for JSON `null`.
A `[]byte`, a type defined over one, or a pointer to either, is refused rather than written as base64.
A Go string, or a pointer to one, is refused as a `Contains` or `ContainedBy` needle, since it would be one JSON string: pass JSON text as `json.RawMessage`.
So is a needle that writes JSON `null` (`nil`, or a nil pointer, map or slice), which only a null document contains.
For `EqAt` and the orderings a Go string is the string value itself.
A document contains a needle when it holds every member the needle writes, and `encoding/json` writes a struct field that has no `omitempty` even when it is zero.
So a zero field narrows the query to the documents that hold that zero: `Profile{Name: "Alice"}` also asks for `"age": 0`.
Give a needle struct pointer fields with `omitempty`, as `ProfileNeedle` above, or use a map.
`Contains` refuses a needle of the field's own type when that type holds a struct, since that is the likeliest way to make the mistake; a type defined over it (`type wholeProfile Profile`) states that you mean every field.
That includes a slice or map of structs: a `[]Visit` document refuses a `[]Visit` needle, since each `Visit` writes its zero fields; pass a `[]VisitNeedle`, a slice of a needle type with pointer fields and `omitempty`.
`ContainedBy` takes the field's own type: there a zero field widens the query.
Each value a selection or read opens is JSON text; `encrypt.DecodeJSON[T]` reads one into a Go type, with the same rules as a whole document.
A position in a path is refused for `EqAt` and `Selector`, whose selector reads every position as the wildcard; read a position with `Subtree`.

### Optional fields

A sealed field declared over a pointer to one scalar (`*encrypt.Date`, `*int32`, `*string`, a pointer to a type defined over a scalar) is optional: `nil` is a value it may hold, and `Decrypt` gives it back as `nil`.
`null=` says how the field stores `nil`. There are two ways, and they differ in what a reader of the database can see:

| `null=` | Stored for `nil` | What a reader of the column sees |
|---|---|---|
| `sealed` | a sealed null, as long as a sealed value of the field's type, and beside an equality index the one term every null of the field shares | nothing in the ciphertext; in an equality column, that the absent rows are one group, as rows holding one repeated value are |
| `sql` | nothing: the field's columns are `NULL`, and its member in the generated type is `nil` | which rows have no value |

A sealed null hides that the value is absent only where its length matches a value's and no index beside it shows it, so it is the default for a field whose type has a fixed width (a `bool`, a number, `encrypt.Date`, `time.Time`, `encrypt.Decimal`, `encrypt.Int128` and `encrypt.Uint128`) and whose only index, if it has one, is `equality`: sealed with `encrypt`, `encrypt,index=equality`, or into an EQL type with no index or with equality alone (`Date`, `DateEq`, `Integer`, `IntegerEq`, ...).
A null has an equality term, so its rows are one equality group and a query finds them: the generated `EqNull` derives the `eq` query of `nil`, which matches every row whose value is absent.
A `null=sealed` field's entry in the generated `Fields` value also has `EncryptNull`, which seals `nil` for an update of that one column: a sealed null is a value, so set the column to what it returns, not to SQL `NULL`.
A null has no order or match term, so a field with any other index, and a field of text or bytes, has to write `null=sql`: an order or match column would show which values are absent, and text shows its length, and `stashgen` will not choose a visible `NULL` for you.
`null=sealed` on such a field stops `stashgen` with the reason.

A `null=sql` field's member in the generated type is a pointer (`*eql.DateEq`, `*EncryptedUserScore`), `nil` when the value was; a `null=sealed` field's is the same type as a non-optional field's, and its column is never `NULL`.
A stored null read into a field that is not a pointer is an error from `Decrypt`, naming the field, never a zero value.
`-model` does not map a `null=sql` field yet, and `stashgen` stops if it is asked to.

An embedded struct of your own adds its tagged fields to the outer struct.
An embedded struct from another package takes one tag for all of its fields: `stash:",passthrough"` stores them as they are, and `stash:"-"` leaves them out.
Tags for other libraries, such as `gorm`, `db` and `json`, are copied to the same field of the generated type.

An unexported field with no `stash` tag is ignored, with three notices: `stashgen` prints a warning, the generated file names the field in a comment, and the program prints a warning to stderr once for each type.
`stash:"-"` on the field states the choice, and all three stop.

## What stashgen writes

For `-type User`, the file `user_stash.go` holds:

- `EncryptedUser`, with one field for each stored field of `User`, with the same name.
  A passthrough field keeps its Go type.
  A field with `encrypt_into` holds one EQL value.
  A field with `encrypt` or `index=` holds a struct with one field for each output, such as `Email.Ciphertext` and `Email.Equality`.
- `Encrypt` and `Decrypt`, which take a slice and return a slice, and send one ZeroKMS request for each 500 sealed values in it, plus one the first time a keyset is used.
- `Fields`, with one entry for each sealed field.
  An opaque struct, or a struct with no sealed field outside an opaque one, gets no `Fields`: nothing in it is sealed on its own, so nothing can be queried.
  An entry encrypts one value, and has one query method for each operator the engine answers on the field: `Eq`, `Lt`, `Lte`, `Gt`, `Gte`, `Between` or `Matches`.
  stashgen asks the embedded engine which operators each field answers, and which index answers each one, so it holds no copy of those rules: an equality index answers `Eq`, a match index on a string `Matches`, and an ORE or OPE index on an integer of 16 bits or more, a float, a string, an `encrypt.Decimal`, an `encrypt.Date` or a `time.Time` the four orderings and `Between`, through ORE when the field declares both. A float orders as PostgreSQL's `float8` does (`-0.0` ties `0.0`, NaN sorts last), and a string by its folded form: case and accents folded, under Unicode 16.
  `encrypt_into=TextEq` answers `Eq`, which returns the type's query value, `eql.TextEqQuery`.
  `encrypt_into=TextMatch` answers `Matches`, which returns an `encrypt.EQLMatchQuery`: the `eql.TextMatchQuery` operand, with `Verify` and `TargetLimit`.
  The query of `Matches` carries `Verify` and `TargetLimit`, because its answer can hold rows that do not match; an exact operator's query carries neither.
  See the encrypt package's README for each method's result and the query with `database/sql`.
- `String` and `LogValue` on `EncryptedUser`, which print the passthrough fields and hide the sealed ones.
- A copy of the fields of `User`, so a change to them stops the build.

Generated code uses no reflection, and no function in it panics.

## Flags

| Flag | Meaning |
|---|---|
| `-type T` | The struct that carries the `stash` tags. Required. |
| `-name N` | Write `EncryptN`, `DecryptN` and `NFields`. A package holds one `Encrypt`; the second struct in a package needs a name. |
| `-for P.F` | `T` declares the tags for `F`, a type in another package. Each field of `T` names a field of `F` with the same name and type, and every exported field of `F` is named. |
| `-model Name=R` | A model `R` for separate columns: one field for each column, each tagged with the output it holds, `stash:"email"` or `stash:"email,equality"`. Writes `EncryptName` and `DecryptName`. Any number. |
| `-model Name=R:D` | The same, for an `R` that cannot carry tags. The struct `D` in your package declares them. |
| `-redact` | Write `String`, `GoString` and `LogValue` methods on `T`. |
| `-output file` | The file to write. The default is the type's name in lower case, with `_stash.go`. |

`stashgen` loads the package with `golang.org/x/tools/go/packages` and reads types, not text.
It runs none of the package's code.
It ignores its own output file when it loads the package, so a stale file does not stop it.
The same input always gives the same file: fields keep their declared order, and the file carries no version and no time.

`stashgen` checks each declaration with the engine, and holds no copy of the engine's rules: it runs the WASI guest the SDK embeds and asks it, one field at a time, so the error names the field.
It asks the engine for the EQL types it holds: each name, its plaintext type, its indexes, its query form, and whether the engine produces it today.
The command links the build of the engine that holds the EQL types (`encrypt/eql`), so it can answer for every type; a generated file imports `encrypt/eql` only when it names one.
The engine produces these EQL types today, each from one Go field type:

| `encrypt_into` | Go field |
|---|---|
| `TextEq`, `Text`, `TextMatch`, `TextOrd`, `TextOrdOpe`, `TextOrdOre`, `TextSearch`, `TextSearchOre` | `string` |
| `Smallint`, `SmallintEq`, `SmallintOrd`, `SmallintOrdOpe`, `SmallintOrdOre` | `int16`, or any Go integer type |
| `Integer`, `IntegerEq`, `IntegerOrd`, `IntegerOrdOpe`, `IntegerOrdOre` | `int32`, or any Go integer type |
| `Bigint`, `BigintEq`, `BigintOrd`, `BigintOrdOpe`, `BigintOrdOre` | `int64`, or any Go integer type |
| `Boolean` | `bool` |
| `Real`, `RealEq`, `RealOrd`, `RealOrdOpe`, `RealOrdOre` | `float32` |
| `Double`, `DoubleEq`, `DoubleOrd`, `DoubleOrdOpe`, `DoubleOrdOre` | `float64` |
| `Date`, `DateEq` | `encrypt.Date` |
| `DateOrd`, `DateOrdOpe`, `DateOrdOre` | `encrypt.Date` |
| `Timestamp`, `TimestampEq` | `time.Time` |
| `TimestampOrd`, `TimestampOrdOpe`, `TimestampOrdOre` | `time.Time` |
| `Numeric`, `NumericEq` | `encrypt.Decimal` |
| `NumericOrd`, `NumericOrdOpe`, `NumericOrdOre` | `encrypt.Decimal` |
| `JsonSearch` | struct, map, slice, or `json.RawMessage`; see [Encrypted JSON documents](#encrypted-json-documents) |

The `Eq` types answer `Eq`; the `Ord`, `OrdOpe` and `OrdOre` types answer `Lt`, `Lte`, `Gt` and `Gte`, and on text `Eq` too; `TextMatch` answers `Matches`, and `TextSearch` and `TextSearchOre` all of `Eq`, `Lt`, `Lte`, `Gt`, `Gte` and `Matches`, each query carrying only the term its operator reads; `Text`, `Smallint`, `Integer`, `Bigint`, `Boolean`, `Real`, `Double`, `Date`, `Timestamp` and `Numeric` are stored and read only, with no query method.
The ordered date, timestamp and numeric types answer the four comparisons, as do the other ordered EQL types. The generated EQL fields have no `Between` method yet: EQL v4 has range query domains, but `stashgen` does not construct their operands. A JSON document's declared ordered paths have their own `Between` method, which returns two leaf query values; see [Encrypted JSON documents](#encrypted-json-documents).

Any built-in Go integer field takes an integer type (ADR-0002) and seals at the type's width: an `int16` field always fits an `Integer`, and an `int64` field is range checked value by value, `Encrypt` refusing a value that does not fit with `encrypt.ErrEncoding`. `encrypt.Int128` and `encrypt.Uint128` are not converted. A float's width must match: a `float64` field is not a `Real`.
A `TextMatch` field indexes the 3-grams of its text and each two-letter word whole, so a two-letter surname such as "Ng" is stored and found by the query "ng"; a query's two-letter words must be whole words of the row.
A `TextMatch` field refuses text that cuts no token, such as an empty string or one letter; its query refuses such text too.
A `TextSearch` field stores such text with an empty match filter, so its `Eq`, `Lt`, `Lte`, `Gt` and `Gte` queries find it and no `Matches` query does; those queries take such text too, and its `Matches` query refuses it.
Put the column on the left of `@@` (`WHERE name @@ $1::eql_v4.query_text_match`): the other operand order finds nothing until #1171 is fixed.
`encrypt_into` with any other type is refused with the type's name and the reason it is not produced yet.
Separate columns work today for four indexes: `equality`, `match`, `ore` and `ope`.

A field with `encrypt_into` is stored under its table and column, which is what an EQL value records in its `i`.
A cipher extended with a tenant part (`cipher.Extend(...)`) has no column for the extended label, so it refuses a struct with an `encrypt_into` field; use `index=` columns for a tenant-extended struct until that rule is settled.

## When stashgen stops

`stashgen` stops with an error, and writes no file, for each of these.
The error names the type and the field, and never a value.

- an exported field with no `stash` tag;
- a tag that does not parse, or two fields with one name;
- a struct with no `context=` field and no `context_field`;
- a `context_field` beside a `context=` field, a second `context_field`, one that is not a `string`, one with another part such as `encrypt` or `index=`, or one whose name is not a label segment;
- an index or an EQL type that does not apply to the field's Go type, such as `match` on an `int32`;
- a field type that the engine cannot seal;
- an EQL type that the engine cannot produce yet;
- an index the engine does not derive yet (`json`), or an index with options;
- a `passthrough` field that has an index;
- a model with a field that has no tag, or with no field for an output;
- two structs in one package that would both write `Encrypt`;
- an embedded struct from another package with no tag;
- a struct whose every field is left out;
- a struct, slice or map field with `encrypt` or `index=` outside an opaque struct;
- a field of an opaque struct whose type the storage profile or JSON cannot carry both ways.

## Declarations from a policy

A type that a schema generates, such as a protobuf message, cannot carry tags.
For such a type, rules decide how each field is encrypted from what the schema says about it, and `stashgen.Generate` writes the same file from the rules.
The rules live in `github.com/cipherstash/stack/languages/golang/encrypt/policy`; `encrypt/policy/protosource` reads a protobuf message's fields and their options.

```go
var category = policy.Key("classification.data_categories")

var Individuals = policy.ForMessage(&pb.Individual{}, policy.Context("individuals"),
	policy.FirstOf(
		policy.When(policy.Field("id"), policy.Passthrough()),
		policy.When(category.Under("user.government_id"), policy.EncryptInto("TextEq")),
		policy.When(category.Under("user.contact.email"), policy.EncryptIndex(policy.Equality, policy.Match())),
		policy.When(category.Under("user"), policy.Encrypt()),
	),
)

//go:generate go run ../cmd/genencrypt
func main() {
	err := stashgen.Generate(context.Background(), protosource.New(), rules.Individuals,
		"../individuals/individual_stash.go")
	...
}
```

The first rule that matches a field decides it.
Every field needs a decision: a field no rule decides stops the generator with the field's name and its annotations.
`Name` sets the column name, and `Identity` keeps the field's context when its column is renamed.
Only a policy can set `Identity`; no tag spells it yet, because how a declaration changes over time is not decided.
The generated file goes in a package of your own, and the functions take and return pointers to the message.
`stashgen.WithName("Individual")` gives the file's names a prefix, as `-name` does: the second message generated into one package needs one, and `Generate` refuses a file whose names the package already declares.

## Printing

A generated type hides its sealed fields when a program prints or logs it.
The struct you wrote is not protected: `stashgen` warns when it has sealed fields and no `String` and `LogValue` methods, and the program prints the same warning to stderr once for each type.
`-redact` makes `stashgen` write those two methods on the struct, and `GoString` for `%#v`.
No warning, error or log line holds a plaintext value.

## What crosses the binding

Generated code sends the engine every sealed field with its value, under the declaration lowered to data: each field's label (`<context>/<name>`), its outputs and its wire type (`int64`, `string`, `bytes`, ...), which `stashgen` chose from the field's Go type.
A passthrough field stays on the host: the engine does nothing to it a program could observe, and the FFI codec cannot carry every Go type a program stores beside a ciphertext (a `driver.Valuer`, a `sql.NullTime`).
An `opaque` struct crosses as one storage blob and is one column, read back into the exact Go types the struct declares.
The blob is vitaminc's storage profile, version 1 (`vcffi.MarshalStorage`), the format vitaminc keeps readable across releases and languages.
A field may be any type that both the storage profile and `encoding/json` carry both ways: a scalar or a type defined over one, `[]byte`, slices, maps with string or integer keys, pointers, structs whose fields are all exported, and types with both `MarshalText` and `UnmarshalText`, such as `time.Time`.
`encrypt.Decimal` and `encrypt.Date` have no storage form and are refused in an opaque struct: store them as text, or by their parts.
A row an earlier release sealed with one of them in an opaque struct does not decrypt under this release, because no generated file can name the field: decrypt such rows with the earlier release, change the field's type, and encrypt them again before upgrading.
The generated shape struct tags each field `vc:"name,default"`, so a field added to the opaque struct reads as its zero value from a row sealed before it; a field added to a nested struct type needs a pointer type for the same.
`Encrypt` refuses a string that is not UTF-8 and a value nested more than 128 levels deep, as `encrypt.ErrEncoding`.
`encoding/json` still matters because a row an earlier release sealed holds a JSON document, and `Decrypt` reads it as JSON.
A float in an opaque struct may be NaN or an infinity: the blob writes a float by its bits.
A nil slice or map in an opaque struct comes back empty, not nil, from a blob; from an earlier release's JSON document it comes back nil.
A sealed field outside an opaque struct is one scalar, a type defined over one, or a pointer to either (see "Optional fields"); a struct, slice or map field seals only inside an opaque struct.
The scalars are `string`, `[]byte`, `bool`, every integer type (each sealed at its own width, `int` and `uint` as 64-bit), `encrypt.Int128` and `encrypt.Uint128`, `float32`, `float64`, `encrypt.Decimal`, `encrypt.Date` and `time.Time` (a timestamp). The wire type `stashgen` writes for each is the field's own: `int8` is `gensupport.Int8`, `time.Time` is `gensupport.Timestamp`, and so on.
A decimal orders by value, so `1.5` ties `1.50`; a `time.Time` orders by the microsecond, so instants within one microsecond tie.
The zero `encrypt.Date` is not a date: a date field must be set, and `Encrypt` refuses a zero one with `encrypt.ErrEncoding`, naming the field. An optional date is a `*encrypt.Date` field (see "Optional fields").
A nil `[]byte` in a sealed field, or a nil slice of a type defined over `[]byte`, comes back from `Decrypt` as an empty, non-nil slice; inside an opaque struct it comes back empty from a blob too, and nil only from an earlier release's JSON document.
A protobuf message with a `oneof` cannot be generated from a policy: protoc-gen-go puts its members in wrapper types, not in the message struct, and `Generate` refuses it.

## Status

The command runs the WASI guest the SDK embeds, so it needs the guests built: `mise run wasm:guest:build wasm:guest:build:eql`.
The library, `github.com/cipherstash/stack/languages/golang/stashgen`, takes any `Engine`; `stashgen.Generate` takes one with `WithEngine`, and `stashgen/enginetest` has a static one for tests.
