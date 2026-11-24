# @cipherstash/recipher

The TypeScript SDK on the Stack Encrypt engine. It encrypts values with
per-value ZeroKMS data keys, and knows nothing about a database.

> **Not released.** This package is private and is not published to npm.
> No build of it promises that a later build opens the values it stored.

## Encrypt and decrypt one value

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

- Encrypting needs a keyset; decrypting does not. `cipher.decrypt` opens a
  value from any of the cipher's keysets, and `keyset.decrypt` refuses a
  value from another keyset.
- `Ciphertext.fromBytes(bytes)` reads stored bytes back. Each ciphertext
  has its own data key.
- The bytes are the engine's: Rust's `keyset.decrypt::<String>` opens what
  this package seals, and this package opens what Rust sealed.

## Values

A value's type picks how it is encrypted. The mapping is vitaminc's, read
and built by its `vitaminc-aead-napi` bridge:

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

- Integers are a `bigint`. A `number` is a float, and `5` does not equal
  the integer `5n`.
- A plain object is refused. Wrap it in `json(..)`.
- `VcUuid` is exported, but the engine's value model does not hold a UUID
  yet, so encrypting one is an `Err` of kind `value`, code
  `recipher::uuid`.
- vitaminc's rules apply: a `Map`, a `Set`, a class instance, a sparse
  array, a typed array other than a `Uint8Array`, a string with an
  unpaired surrogate, and a property named `__proto__`, `constructor` or
  `prototype` are refused, each with a code of its own.

An array in is an array out, in the same order, with one key request
however long it is:

```ts
const sealed = await keyset.encrypt(['first secret', 'second secret'])
const opened = await cipher.decrypt(sealed.unwrap())
```

### JSON documents

`json(value)` encrypts a document as one ciphertext, as the engine's
`JsonPlaintext` does: as its JSON text.

- An integer outside a `number`'s safe range is a `bigint`, in the 64-bit
  range the engine's parser reads (`-(2n ** 63n)` to `2n ** 64n - 1n`); a
  `bigint` outside it is refused.
- A whole `number` between 2^53 and 2^64 from zero is refused: an integer
  was likely meant, and its digits are not the ones written. Use a
  `bigint`. Any other finite `number`, such as `1e20`, is a float.
- Bytes, a `Date`, the wrapper classes and `undefined` have no JSON form
  and are refused. So is a document nested deeper than 127 levels.
- A property named `__proto__`, `constructor` or `prototype` cannot be
  encrypted, and a document another SDK wrote with one opens as an `Err`
  of kind `open`, code `recipher::reserved_key`: vitaminc does not build
  those properties in JavaScript.
- **Read a stored document back with `kinds.json`.** The bytes do not say
  a value is JSON. `Ciphertext.fromBytes(bytes, kinds.json)` opens it as
  the document. With no kind it opens as its JSON text, and `JSON.parse`
  of that text loses the digits of a large integer.

### Stored bytes

`Ciphertext.fromBytes(bytes)` opens as whatever was sealed, typed as any
scalar. `Ciphertext.fromBytes(bytes, kinds.string)` is typed by the kind,
and decrypting refuses a value sealed as another type. An integer kind
takes an integer of any width that fits it.

## Results, not exceptions

No call throws and no promise rejects. Every call resolves to a `Result`,
with Rust's `Result` methods in camelCase: `isOk`, `isErr`, `ok`, `err`,
`map`, `mapErr`, `mapOr`, `and`, `andThen`, `or`, `orElse`, `unwrapOr`,
`unwrapOrElse`, `unwrap` and `expect`. Only `unwrap` and `expect` throw.
This holds for a method passed on its own (`ciphertexts.map(cipher.decrypt)`
keeps its cipher), for an argument of the wrong type, and when the native
build is missing.

A `RecipherError` has a `kind` to switch on (`value`, `credential`,
`zerokms`, `foreign_keyset`, `open`, `internal` and the rest), a stable
`code`, a `message`, and the engine's `reason` and `field` where it gives
them. No error holds a plaintext, a key, a token or a ciphertext.

`Cipher`, `Keyset` and `Ciphertext` have no constructor: get a cipher from
`Cipher.create()`, a keyset from `cipher.defaultKeyset()` and a ciphertext
from `encrypt` or `Ciphertext.fromBytes`.

## Tests without ZeroKMS

```ts
import { testCipher } from '@cipherstash/recipher/testing'

const cipher = (await testCipher()).unwrap()
```

A test cipher needs no credentials and makes no request. Its keys are a
function of a public seed, so never use it for data you keep. Only the
debug build of the addon (`build:debug`) has it.

## How it is built

The classes are written in Rust, in one crate (`crate/`, crate
`recipher-js`): a napi-rs 3 addon over the engine. It reads and builds
JavaScript values only through vitaminc's `vitaminc-aead-napi`. napi-rs's
CLI builds it, and writes its TypeScript declarations to `native.d.ts`,
which is committed. The package's TypeScript holds what Rust cannot:
`Result`, `RecipherError`, and typed signatures over the native methods.

The package's `build` and `test` scripts never run cargo.

| Script | What it does |
|---|---|
| `build` | The TypeScript, with tsup. |
| `test` | The suites that need no addon, and the typecheck with the type tests. |
| `build:debug` | The addon, with the test cipher, as `recipher.node`, and `native.d.ts`. Needs Rust. |
| `build:native` | The release addon, without the test cipher. Needs Rust. |
| `test:addon` | `build`, then the suites that load the addon. Run `build:debug` first. |
| `test:cargo` | `cargo test`, `cargo fmt --check` and clippy over the crate. |

The addon is loaded when the package is imported. The ESM and the CommonJS
builds load the same addon, so they share its classes.

## What is not here yet

`opaque(..)` for a whole object, records, search terms, credentials passed in code, named keysets, audit
metadata, cancellation, the wasm build and the platform packages.

The JavaScript engine holds the plaintext strings it is given, and no test
can check what it does with them.
