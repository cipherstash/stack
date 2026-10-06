# stashgen

`stashgen` writes the Go code that encrypts a struct with Stack Encrypt.
You declare how each field is encrypted with `stash` tags.
`stashgen` writes the encrypted type and the functions that encrypt, decrypt and search it.
Your program calls those functions, and it never builds or names a plan.

## Use the SDK

1. Add the generator to your module.
   This needs Go 1.24 or later.

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
   people, err := users.Decrypt(ctx, cipher, encrypted)
   query, err := users.Fields.Email.Query(ctx, cipher, "bob@example.com")
   ```

6. Store the encrypted type.
   Each field is one column, so `database/sql`, pgx, sqlx and GORM take it as it is.

7. Run the generator again after each change to the struct or to a tag.
   A change to the fields of the struct stops the build until you do.

8. In CI, run the generator and fail when a generated file changes.

   ```sh
   go generate ./... && git diff --exit-code
   ```

The rest of this file is the reference.

## Struct tags

The first part of a tag is the field's name, which is the column name in a database.

| Tag | Meaning |
|---|---|
| `` _ struct{} `stash:"context=users"` `` | the context of every field in the struct |
| `stash:"email,encrypt_into=TextEq"` | seal the field into one EQL value, with the terms that EQL type has |
| `stash:"notes,encrypt"` | seal the field, with no index |
| `stash:"email,encrypt,index=equality;match"` | seal the field, and derive each index beside it |
| `stash:"attrs,index=json"` | derive the index alone |
| `stash:"id,passthrough"` | store the field as it is |
| `stash:"-"` | leave the field out |
| `` _ struct{} `stash:"context=documents,opaque"` `` | seal the struct as one value |

The index names are `equality`, `match`, `ore`, `ope` and `json`.
A `match` index needs text with at least one token: the engine derives no match term for an empty or separator-only string, or one shorter than the n-gram, because an empty term would match every row.
`Encrypt` then returns an error naming the row, the field and the index; give the field a value, or drop the index.
An index takes its options in parentheses after its name, separated by commas: `index=equality;match(k=3)`.
These words are the same as the Rust API's words for the same behaviour.

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
- `Encrypt` and `Decrypt`, which take a slice and return a slice, and send one ZeroKMS request for all of it.
- `Fields`, with one entry for each sealed field.
  An entry encrypts one value, and it has a query method only for what the field declares: `Query` for `encrypt_into`, and `Equality`, `Match`, `Ore` or `Ope` for `index=`.
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
| `-redact` | Write `String` and `LogValue` methods on `T`. |
| `-output file` | The file to write. The default is the type's name in lower case, with `_stash.go`. |

`stashgen` loads the package with `golang.org/x/tools/go/packages` and reads types, not text.
It runs none of the package's code.
It ignores its own output file when it loads the package, so a stale file does not stop it.
The same input always gives the same file: fields keep their declared order, and the file carries no version and no time.

`stashgen` checks each declaration with the engine, and holds no copy of the engine's rules: it runs the WASI guest the SDK embeds and asks it, one field at a time, so the error names the field.
It asks the engine for the EQL types it holds: each name, its plaintext type, its indexes and its query form.
This build of the engine produces no EQL type, so `encrypt_into` is refused with "EQL types are not available yet"; the next release adds `TextEq` and `encrypt/eql`.
Separate columns work today for four indexes: `equality`, `match`, `ore` and `ope`.

## When stashgen stops

`stashgen` stops with an error, and writes no file, for each of these.
The error names the type and the field, and never a value.

- an exported field with no `stash` tag;
- a tag that does not parse, or two fields with one name;
- a struct with no `context=` field;
- an index or an EQL type that does not apply to the field's Go type, such as `match` on an `int32`;
- a field type that the engine cannot seal;
- an EQL type that the engine cannot produce yet;
- a `passthrough` field that has an index;
- a model with a field that has no tag, or with no field for an output;
- two structs in one package that would both write `Encrypt`;
- an embedded struct from another package with no tag;
- a struct whose every field is left out;
- a struct, slice or map field with `encrypt` or `index=` outside an opaque struct;
- a field of an opaque struct whose type JSON cannot carry both ways.

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
	err := stashgen.Generate(protosource.New(), rules.Individuals,
		stashgen.Output("../individuals/individual_stash.go"))
	...
}
```

The first rule that matches a field decides it.
Every field needs a decision: a field no rule decides stops the generator with the field's name and its annotations.
`Name` sets the column name, and `Identity` keeps the field's context when its column is renamed.
The generated file goes in a package of your own, and the functions take and return pointers to the message.

## Printing

A generated type hides its sealed fields when a program prints or logs it.
The struct you wrote is not protected: `stashgen` warns when it has sealed fields and no `String` and `LogValue` methods, and the program prints the same warning to stderr once for each type.
`-redact` makes `stashgen` write those two methods on the struct.
No warning, error or log line holds a plaintext value.

## What crosses the binding

Generated code sends the engine every sealed field with its value, under the declaration lowered to data: each field's label (`<context>/<name>`), its outputs and its wire type (`int64`, `string`, `bytes`, ...), which `stashgen` chose from the field's Go type.
A passthrough field stays on the host: the engine does nothing to it a program could observe, and the FFI codec cannot carry every Go type a program stores beside a ciphertext.
An `opaque` struct crosses as one JSON document and is one column, decoded back into the exact Go types the struct declares; a field may be any type `encoding/json` carries both ways (a scalar or a type defined over one, `[]byte`, slices, maps with string or integer keys, pointers, structs whose fields are all exported, `time.Time`).
A sealed field outside an opaque struct is one scalar, or a type defined over one; a struct, slice or map field seals only inside an opaque struct.

## Status

The command runs the WASI guest the SDK embeds, so it needs the guest built: `mise run wasm:guest:build`.
The library, `github.com/cipherstash/stack/languages/golang/stashgen`, takes any `Engine`; `stashgen.Generate` takes one with `WithEngine`, and `stashgen/enginetest` has a static one for tests.
