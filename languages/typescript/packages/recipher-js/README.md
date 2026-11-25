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
- This build encrypts a `string` only.

## Results, not exceptions

Every call returns, or resolves to, a `Result`.
No promise rejects.
A `Result` has the methods of Rust's `Result`, in camelCase:

- `isOk`, `isErr`, `ok`, and `err`;
- `map`, `mapErr`, and `mapOr`;
- `and`, `andThen`, `or`, and `orElse`;
- `unwrapOr`, `unwrapOrElse`, `unwrap`, and `expect`.

Only `unwrap` and `expect` throw.
The other calls return an `Err` in these cases too:

- an argument of the wrong type, or a missing argument;
- a native addon that did not load.

One call throws: a method called without its object.
`ciphertexts.map(cipher.decrypt)` passes `decrypt` on its own, without its cipher.
The JavaScript engine throws a `TypeError` when it is called, before any of the package's code runs.
Call the method on its object instead:

```ts
const opened = await Promise.all(
  ciphertexts.map((ciphertext) => cipher.decrypt(ciphertext)),
)
```

A static method, such as `Ciphertext.fromBytes`, works on its own.

A `RecipherError` is an error report that a call returns as a value.
Most errors come from the engine.
The SDK's own errors have a code that starts with `recipher_js::`.
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
| `code` | The code to switch on. It is stable. It is the engine's code (`stack_encrypt::aead`), vitaminc's code for a value it refused (`ERR_INTEGER_RANGE`), or the SDK's own (`recipher_js::not_a_ciphertext`). |
| `message` | What went wrong, in one line. |
| `help` | What to do about it, where the error knows. |
| `url` | A documentation page for the error, where it has one. |
| `severity` | `error`, unless the engine's report states `warning` or `advice`. |
| `fields` | The error's structured fields, by `snake_case` name. An example is a ZeroKMS failure's `request_kind`. |
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
Those declarations are the package's public types.
Each method's signature is written in Rust, in the method's `ts_type`, `ts_args_type` or `ts_return_type` attribute.
The documentation comments on the Rust code become the declarations' documentation.
`native-header.d.ts` is the start of `native.d.ts`: it imports the TypeScript types the signatures name, and gives `Ciphertext` its type parameter.
`native.d.ts` is committed.

Each native method returns a `Result` itself.
The package's TypeScript gives the addon the `Ok`, `Err` and `RecipherError` classes when it loads the addon.
The package's TypeScript contains what Rust cannot provide: `Result`, `RecipherError`, the loader, and stand-in classes for when the addon did not load.

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

- values other than a `string`;
- arrays;
- JSON documents;
- `opaque(..)`, for a whole object;
- records;
- search terms;
- credentials passed in code;
- named keysets;
- audit metadata;
- cancellation;
- the WebAssembly (wasm) build;
- the platform packages.

The JavaScript engine keeps the plaintext strings it is given in memory.
No test can check what the JavaScript engine does with them.
