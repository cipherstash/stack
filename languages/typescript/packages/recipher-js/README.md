# @cipherstash/recipher

`@cipherstash/recipher` is the TypeScript SDK for the Stack Encrypt engine.
Stack Encrypt is CipherStash's encryption engine, written in Rust.
The package encrypts each value with a data key of its own.
The data keys come from ZeroKMS, CipherStash's key service.
The package contains no database code.

> **Not released.** This package is private. The package is not published to npm.
> No build of this package promises that a later build can decrypt the values it stored.

## Encrypt and decrypt one value

A `Cipher` uses ZeroKMS to get data keys.
`Cipher.create()` looks for credentials in the `CS_*` environment variables, then in the profile that `stash auth login` writes.
A keyset is a group of keys in ZeroKMS.
Every data key is made under one keyset.
`cipher.defaultKeyset()` returns the keyset that a ZeroKMS administrator set as the default for your client.

```ts
import { Cipher } from '@cipherstash/recipher'

const cipher = (await Cipher.create()).unwrap()
const keyset = cipher.defaultKeyset()

const sealed = await keyset.encrypt('a secret message')
if (sealed.isErr()) {
  return sealed // a RecipherError, as a value
}

const stored = sealed.value.toBytes() // a Uint8Array to keep

const opened = await cipher.decrypt(sealed.value)
```

- Encrypting needs a keyset. Decrypting does not.
- `cipher.decrypt` decrypts a value from any of the cipher's keysets.
  `keyset.decrypt` refuses a value from another keyset.
- `Ciphertext.fromBytes(bytes)` reads stored bytes back as a ciphertext.
  Each ciphertext has its own data key.
- The stored bytes use the engine's format.
  Rust code that calls `keyset.decrypt::<String>` decrypts what this package encrypts.
  This package decrypts what Rust encrypted.
- You cannot make a `Cipher`, a `Keyset`, or a `Ciphertext` with a constructor.
  Get a cipher from `Cipher.create()`, a keyset from `cipher.defaultKeyset()`, and a ciphertext from `encrypt` or `Ciphertext.fromBytes`.

## Values

A value's type decides how it is encrypted.
vitaminc defines the mapping.
vitaminc is the CipherStash Rust library that the engine's plaintext types come from.
The `recipher-value-napi` crate, in `value-napi/`, converts JavaScript values by that mapping, in both directions:

| Value | Encrypted as | Decrypts as |
|---|---|---|
| `string` | text | `string` |
| `boolean` | a boolean | `boolean` |
| `number` | a 64-bit float | `number` |
| `bigint` | an integer, at the narrowest width that holds it | `bigint` |
| `Uint8Array`, `Buffer` | bytes | `Uint8Array` |
| `Date` | a timestamp | `Date` |
| `new VcTimestamp('2026-11-23T01:02:03.000000001Z')` | a timestamp, in nanoseconds | `Date` when it is whole milliseconds, else `VcTimestamp` |
| `new VcDate('2026-11-23')` | a calendar date | `VcDate` |
| `new VcDecimal('1.50')` | a decimal, with its scale | `VcDecimal` |
| `null` | null | `null` |
| `json(value)` | a JSON document, as its JSON text | the document, from the `Ciphertext` that `encrypt` returned or one read with `kinds.json` |

- Integers are a `bigint`.
  A `number` is a float.
  The `number` `5` does not equal the integer `5n`.
- A plain object is refused.
  Wrap it in `json(..)`.
- The package exports `VcUuid`, for a universally unique identifier (UUID).
  The engine has no plaintext type for a UUID yet.
  Encrypting a `VcUuid` is an `Err` with the code `recipher::uuid`.
- vitaminc's rules refuse each of these values, with an error code for each:
  - a `Map` or a `Set`;
  - a class instance;
  - a sparse array;
  - a typed array other than a `Uint8Array`;
  - a string with an unpaired surrogate;
  - a property named `__proto__`, `constructor`, or `prototype`.

If you encrypt an array, you get back an array of ciphertexts in the same order.
The whole array needs one key request to ZeroKMS, however long it is:

```ts
const sealed = await keyset.encrypt(['first secret', 'second secret'])
const opened = await cipher.decrypt(sealed.unwrap())
```

### JSON documents

`json(value)` encrypts a whole document as one ciphertext.
The document is encrypted as its JSON text, as the engine's `JsonPlaintext` type does.

- An integer outside a `number`'s safe range is a `bigint`.
  The `bigint` must be in the 64-bit range that the engine's parser reads: `-(2n ** 63n)` to `2n ** 64n - 1n`.
  A `bigint` outside that range is refused.
- A whole `number` is refused when its absolute value is at least 2^53 but less than 2^64.
  An integer was likely meant.
  The `number` does not keep the digits that were written.
  Use a `bigint` instead.
  Any other finite `number`, such as `1e20`, is a float.
- Bytes, a `Date`, the wrapper classes, and `undefined` have no JSON form.
  The package refuses them.
  The package also refuses a document nested deeper than 127 levels.
- A property named `__proto__`, `constructor`, or `prototype` cannot be encrypted.
  Another SDK can write a document with one of these properties.
  Decrypting that document here gives an `Err` with the code `recipher::reserved_key`.
  The reason is that vitaminc does not build those properties in JavaScript.
- **Read a stored document back with `kinds.json`.**
  The bytes do not record that a value is JSON.
  `Ciphertext.fromBytes(bytes, kinds.json)` decrypts to the document.
  With no kind, the document decrypts to its JSON text.
  `JSON.parse` of that text loses the digits of a large integer.

### Stored bytes

A kind names the type a stored ciphertext decrypts to, such as `kinds.string`.

`Ciphertext.fromBytes(bytes)` decrypts to whatever type was encrypted.
The ciphertext's TypeScript type allows any scalar: any type in the table above except a JSON document.

`Ciphertext.fromBytes(bytes, kinds.string)` has the kind's type.
Decrypting it refuses a value that was encrypted as another type.
An integer kind accepts an integer encrypted at any width, if the value fits the kind.

## Records

A record declares each field of a row once.
A field is encrypted, encrypted with indexes, or passed through unencrypted.

```ts
import { encrypt, kinds, passthrough, record } from '@cipherstash/recipher'

export const user = record('users', {
  id: passthrough<bigint>(),
  email: encrypt(kinds.string, { index: ['equality'] }),
  name: encrypt(kinds.string, { index: ['match'] }),
  age: encrypt(kinds.int32, { index: ['equality'], null: 'sealed' }),
  notes: encrypt(kinds.string, { null: 'sql' }),
})

// One row, or an array of rows in one key request.
const stored = await keyset.encrypt(user, row)
const opened = await cipher.decrypt(user, stored.unwrap())
```

- A declaration is a plain, frozen object: `{ type: 'record', name, fields }`.
  A library can read the record's name, its fields, and each field's declaration from it.
- The package has an ECMAScript module (ESM) build and a CommonJS build.
  A declaration made by either build works with a cipher from the other.
- Each encrypted field names its kind, by the engine's name for it.
  The kinds are `kinds.string`, `kinds.boolean`, `kinds.int8` to `kinds.int128`, `kinds.uint8` to `kinds.uint128`, `kinds.float32`, `kinds.float64`, `kinds.decimal`, `kinds.date`, `kinds.timestamp`, and `kinds.bytes`.
- An integer field takes a `bigint` at every width.
  The field refuses a `bigint` outside its range.
- A context is data that a ciphertext is bound to.
  The ciphertext decrypts only under the same context.
  A field's context is its field path: the record's name, then the field's name.
  The engine's typed Rust API decrypts the stored `email` field's ciphertext under `("users", "email")`.
- An index stores extra bytes, called index terms, beside a field's ciphertext.
  A search can compare index terms without decrypting the field.
  `equality` finds exact matches.
  `match` finds text matches.
  `ore` and `ope` compare order.
- The stored row has one object for each encrypted field.
  The object has a `ciphertext` property.
  The object also has one property for each index the field declares: `equality`, `match`, `ore`, or `ope`.
  Each property is opaque bytes.
- A passthrough field keeps its value in the stored row.
- A field with `null: 'sealed'` encrypts a missing value like any other value.
  A field with `null: 'sql'` is `null` in the stored row when the value is missing.
- `Plaintext<typeof user>` is the type of a row.
  `Stored<typeof user>` is the type of a stored row.
  A row of another shape does not compile.
  `stored.notes.equality` does not compile either, because `notes` declares no index.
- A passthrough field is **not encrypted and not authenticated.**
  Anyone with the stored row can read it, change it, or remove it.
  Use a passthrough field only for values that are not secret.
  Treat the value read back as untrusted.
- The engine checks a declaration the first time a cipher uses it.
  The engine then keeps the plan it built from the declaration.
- `Cipher.create({ records })` checks the declarations before it looks for credentials.
  `checkDeclarations(records)` checks them with no credentials.
  A refusal names the record in `error.record`.
  Where there is a field at fault, the refusal names it in `error.field`.
- Node's `inspect` shows a decrypted row's field names and hides their values.
  `console.log` uses `inspect`, so it hides the values too.
  The values are ordinary properties.
  `JSON.stringify` or a spread still shows them.

To update one field of a stored row, encrypt that field on its own.
An array of values gives an array of stored fields, with one key request:

```ts
const email = await keyset.encryptField(user, 'email', 'ada@example.com')
const value = await cipher.decryptField(user, 'email', email.unwrap())

const emails = await keyset.encryptField(user, 'email', ['a@example.com', 'b@example.com'])
```

The stored field has the same form as that field in a whole stored row.

## Results, not exceptions

No call throws, and no promise rejects.
Every call resolves to a `Result`.
A `Result` has the methods of Rust's `Result`, in camelCase:

- `isOk`, `isErr`, `ok`, and `err`;
- `map`, `mapErr`, and `mapOr`;
- `and`, `andThen`, `or`, and `orElse`;
- `unwrapOr`, `unwrapOrElse`, `unwrap`, and `expect`.

Only `unwrap` and `expect` throw.
The other calls do not throw in these cases either:

- a method passed on its own: `ciphertexts.map(cipher.decrypt)` keeps its cipher;
- an argument of the wrong type;
- a native addon that did not load.

A `RecipherError` is an error report that a call returns as a value.
Most errors come from the engine.
The SDK's own errors have a code that starts with `recipher::`.
Switch on `code`:

```ts
const opened = await cipher.decrypt(damaged)
if (opened.isErr()) {
  opened.error.code // 'stack_encrypt::aead'
  opened.error.message // 'AEAD operation failed (wrong key, AAD mismatch, or malformed ciphertext)'
  opened.error.help // 'Open the value under the context it was sealed with. ...'
}
```

| Property | What it contains |
| --- | --- |
| `code` | The code to switch on. It is stable. It is the engine's code (`stack_encrypt::aead`), vitaminc's code for a value it refused (`ERR_INTEGER_RANGE`), or the SDK's own (`recipher::not_a_ciphertext`). |
| `message` | What went wrong, in one line. |
| `help` | What to do about it, where the error knows. |
| `url` | A documentation page for the error, where it has one. |
| `severity` | `error`, unless the engine's report states `warning` or `advice`. |
| `fields` | The error's structured fields, by `snake_case` name. Examples are a refused declaration's `reason` and a ZeroKMS failure's `request_kind`. |
| `field` | The field at fault, where one is known. |
| `record` | The record at fault, where there is one. |
| `causes` | The errors behind this one, outermost first. Each cause has a `message`, and an engine error also has a `code`. A cause from another library has a fixed message, never that library's own text. |

No error contains a plaintext, a key, a token, or a ciphertext.

## Tests without ZeroKMS

```ts
import { testCipher } from '@cipherstash/recipher/testing'

const cipher = (await testCipher()).unwrap()
```

A test cipher needs no credentials and makes no network requests.
The test cipher derives its keys from a public seed.
Never use a test cipher for data you keep.
Only the debug build of the addon has the test cipher.
The `build:debug` script makes that build.

## How it is built

The native addon is compiled Rust code that Node loads.
The classes are written in Rust, in the `recipher-js` crate in `crate/`.
The crate is a napi-rs 3 addon that calls the engine.
napi-rs is a Rust framework for writing Node addons.

The addon reads and builds JavaScript values only through the value bridge beside it.
The value bridge is the `recipher-value-napi` crate in `value-napi/`.

napi-rs's command-line tool builds the addon.
The tool also writes the addon's TypeScript declarations to `native.d.ts`.
`native.d.ts` is committed.
The package's TypeScript contains what Rust cannot provide: `Result`, `RecipherError`, and typed signatures over the native methods.

The package's `build` and `test` scripts never run cargo.

| Script | What it does |
|---|---|
| `build` | Builds the TypeScript, with tsup. |
| `test` | Runs the suites that need no addon, and the typecheck with the type tests. |
| `build:debug` | Builds the addon, with the test cipher, as `recipher.node`, and writes `native.d.ts`. Needs Rust. |
| `build:native` | Builds the release addon, without the test cipher. Needs Rust. |
| `test:addon` | Runs `build`, then the suites that load the addon. Run `build:debug` first. |
| `test:cargo` | Runs `cargo test`, `cargo fmt --check`, and clippy over the crate. |

The addon is loaded when the package is imported.
The ESM build and the CommonJS build load the same addon, so the two builds share its classes.

## What is not here yet

These features are not built yet:

- `opaque(..)`, for a whole object;
- a `json` record field: this field needs `JsonSearch` from the Encrypt Query Language (EQL) extension for PostgreSQL;
- search terms;
- credentials passed in code;
- named keysets;
- audit metadata;
- cancellation;
- the WebAssembly (wasm) build;
- the platform packages.

The JavaScript engine keeps the plaintext strings it is given in memory.
No test can check what the JavaScript engine does with them.
