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
- This build encrypts a `string` only.

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

Values other than a `string`, arrays, JSON documents, `opaque(..)`,
records, search terms, credentials passed in code, named keysets, audit
metadata, cancellation, the wasm build and the platform packages.

The JavaScript engine holds the plaintext strings it is given, and no test
can check what it does with them.
