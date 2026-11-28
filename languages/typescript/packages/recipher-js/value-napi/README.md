# recipher-value-napi

This crate is the JavaScript value bridge of `@cipherstash/recipher`. The
value bridge converts values between JavaScript and Rust:

- The bridge reads a Node-API value as a value of the plaintext model of
  `vitaminc-aead`.
- The bridge builds a JavaScript value from a value of that model.

The plaintext model describes a value as scalars, sequences, and maps. The
`recipher-js` addon reads and builds every value through this crate.

This crate is a library that a Node addon links. Node cannot load this crate
itself.

## Where this crate comes from

This crate is a renamed copy of `vitaminc-aead-napi` 0.10.0. The copy comes
from [`cipherstash/vitaminc`](https://github.com/cipherstash/vitaminc) at
commit `b3f69b12c1fde38faff2becec04f9e633dbd4f1c`. This crate is not
published.

The wrapper classes of this crate are `RcDate`, `RcTimestamp`, `RcDecimal`,
and `RcUuid`. vitaminc names the same classes with the prefix `Vc`, such as
`VcDate`.

`tests/testdata/value-conformance.json` is a copy of
`conformance/vitaminc-aead/value-conformance.json`. That file contains the
test vectors that the Rust, Node, and Go bindings all check. The tests of
this crate read the copy, so a test run that covers only this package finds
the file. `scripts/__tests__/recipher-js-value-corpus-parity.test.mjs` fails
when the two files parse to different JSON. So change both files together,
then run `pnpm run code:fix`.

## What this crate provides

[`Encrypt`] and [`Sink`] are traits of `vitaminc-aead`. A JavaScript value
that comes in implements `Encrypt`. A `Sink` builds the JavaScript value
that goes out. This crate provides both sides of that conversion:

- **`JsRef<'e>`** is a live JavaScript value as an `Encrypt`. `JsRef` reads
  the value in a walk. A walk is one pass over a value and every value
  nested in it. The walk runs on the JavaScript thread, and reads each value
  when it reaches that value. The walk builds no tree of values. The walk
  copies a scalar out of the JavaScript engine only to pass it straight to
  the sink.

  `encrypt(JsRef::new(value), &cipher, aad)` encrypts a value in place. To
  encrypt off the JavaScript thread, call `JsRef::to_frame` on the
  JavaScript thread first. `to_frame` copies the value into a frame. A frame
  is a byte buffer that contains one value. A worker thread then encrypts
  the frame, with no access to JavaScript.
- **`JsBuilder<'e>`** is a `Sink` that builds JavaScript values. Pass it to
  `decrypt_into(&cipher, ct, aad, JsBuilder::new(&env))`. For a frame, call
  `JsBuilder::build(&env, frame)`.
- **`JsRef::to_json`** and **`JsBuilder::build_json`** convert a JSON
  document. `to_json` writes a JavaScript value as the text of a document.
  `build_json` builds the JavaScript value of a `serde_json::Value`. See
  [JSON documents](#json-documents).
- **`JsCipherText<Leaf, P>`** converts the generic `CipherText` container to
  plain JavaScript values, and back. The JavaScript form is `{ t, v }` nodes
  with `Buffer` leaves. That form is for the application to use in memory.
  Durable database storage that every language reads is the job of the EQL
  layer, not of this type.

  The passthrough payload `P` converts through `NapiPassthrough`.
  `NapiPassthrough` is implemented for `PassthroughFrame` and for `()`.
  `PassthroughFrame` is the payload of the sink-based tree. The conversion
  applies the tree's nesting limit to the payload too.
- **`Wrappers`** contains the wrapper classes: `RcDate`, `RcTimestamp`,
  `RcDecimal`, and `RcUuid`. The classes are defined once for each
  environment. An addon exports the classes with `Wrappers::exports`. This
  crate keeps the classes in its own registry, keyed by the environment. An
  environment cleanup hook releases them. This crate never reads or changes
  the addon's instance data.

## Run a Node example

This crate provides Rust building blocks for a Node addon. The [test
addon](tests/addon/src/lib.rs) exports `encryptValue` and `decryptValue`.
The two functions use `JsRef`, `JsCipherText`, and `JsBuilder` with
AES-256-GCM. The test addon uses a fixed, public test key, so use it only
with sample data.

You need Rust and Node.js. From `languages/typescript/packages/recipher-js`,
run:

```sh
cargo test -p recipher-value-napi --test node
```

The command builds the addon. The command then runs the example below, and
the other Node tests of this crate. To run the example on its own:

1. Save the example as `example.cjs` in that directory.
2. Run `node example.cjs target/napi-test-addon/addon.node`.

```javascript
const assert = require('node:assert/strict');
const path = require('node:path');
const addon = require(path.resolve(process.argv[2]));

const value = { name: 'Ada', count: 42n, tags: ['example'] };
const aad = 'tenant:example';
const ciphertext = addon.encryptValue(value, aad);
const recovered = addon.decryptValue(ciphertext, aad);

assert.deepEqual(recovered, value);
assert.throws(() => addon.decryptValue(ciphertext, 'tenant:other'));
```

The associated data (`aad`) must be the same for encryption and for
decryption. You can use the associated data to bind a ciphertext to a
tenant, or to another application context. Use a `bigint` for an integer,
such as `42n`. A JavaScript `number` is a float.

## How JavaScript values map to the plaintext model

The walk reads each JavaScript value as the value in this table:

| JavaScript                          | Read as                                  |
| ----------------------------------- | ---------------------------------------- |
| `null`                              | null                                     |
| `undefined`                         | null, logical type `Undefined`           |
| `boolean`                           | bool                                     |
| `number`                            | float (`F64`)                            |
| `bigint`                            | int, at the narrowest fitting width      |
| `string`                            | text                                     |
| `Buffer`, `Uint8Array`              | bytes (any other view is refused)        |
| `Date`                              | `Timestamp(Millis)` over the `i64` count |
| `RcDate("YYYY-MM-DD")`              | `Date` over the day count                |
| `RcTimestamp("RFC 3339, ns")`       | `Timestamp(Nanos)` over the count        |
| `RcDecimal("1.50")`                 | `Decimal { scale }` over the mantissa    |
| `RcUuid("hyphenated hex")`          | `Uuid` over sixteen bytes                |
| `Array`                             | sequence                                 |
| plain object                        | map, over own enumerable string keys     |

A logical type says what a stored scalar means, such as `Timestamp(Millis)`
for an `i64` count.

`JsBuilder` builds each stored value as the JavaScript value in this table:

| Stored value                                   | Built as                                    |
| ---------------------------------------------- | ------------------------------------------- |
| an int of any width                            | `BigInt`                                    |
| a float of either width                        | `number`; an `f32` widens exactly           |
| a timestamp in any unit, in whole milliseconds | `Date`                                      |
| any other timestamp                            | `RcTimestamp`, so no precision is discarded |
| a calendar date                                | `RcDate`                                    |
| a decimal                                      | `RcDecimal`                                 |
| a UUID                                         | `RcUuid`                                    |

A `Date` is stored as its millisecond count. `JsBuilder` reads the same
count back. The count is never converted through seconds and nanoseconds.

A stored value can have a logical type that this build does not define. That
value has no JavaScript value. `JsBuilder` refuses it, and does not build it
with its type dropped.

### Equality across widths and types

An equality term is a value derived from a plaintext. A database compares
equality terms to find equal values without decrypting them. Two terms can
match only when they are in the same domain.

- Every integer width is in one domain. So a `BigInt` written as `int8`
  matches the same number written as `int64` from Go.
- Both float widths are in one domain too.
- Integers and floats are in different domains. So a JavaScript `number` 5
  does not match an `int64` 5. Use a `BigInt` for integer data.

A record field that declares a type is the exception. The engine reads each
value written to that field, or queried against it, as the declared type,
when the conversion is exact. So `5` and `5n` are both the `int64` 5 on an
`int64` field.

### The wrapper classes

JavaScript has no type of its own for a calendar date, a timestamp finer
than a millisecond, a decimal, or a universally unique identifier (UUID). So
each one is an instance of a small class that stores the value's text, such
as `new RcDecimal("1.50")`.

Some rules below mention a polluted prototype. A polluted prototype is a
built-in prototype, such as `Object.prototype`, that other code has added
properties to.

- **The constructor takes a string and nothing else.** This crate checks the
  text, and builds the scalar from it, when the value is encrypted. So one
  rule applies however the instance was made.
- **`value` is an own, read-only, enumerable property.** So
  `JSON.stringify`, `structuredClone`, and a deep equality check all read
  it. `JSON.stringify` gets the bare text through `toJSON`.
- **A clone is not a wrapper.** A clone, or a wrapper posted to a Worker, is
  a plain `{ value }` object, and encrypts as a map. Rebuild the wrapper
  with the constructor on the other side.
- **The classes, their prototypes, and every instance are frozen.**
  Construction uses what the class captured when it was defined. So a
  polluted `Object.prototype`, or a later edit of a class, cannot make
  `value` writable. Neither can break a decrypt, or turn a plain `{ value }`
  object back into a wrapper.
- **An instance is not a plain object.** So no code confuses an instance
  with a plain one-key object that another language wrote. For example, Go's
  `{"date": "2024-01-01"}` decrypts in JavaScript as that object, and
  encrypts again unchanged.

These rules apply to the text:

- Decimal text is exact fixed-point. Decimal text is not a JavaScript
  number, or an instance of a decimal library. A negative zero reads back as
  zero, with its scale kept.
- A leap second has no count since the epoch, so it is refused.
- Dates and timestamps cover the range of the jiff library, years -9999 to
  9999, as in every binding.
- A negative year is a sign and six digits, as JavaScript writes it:
  `-000005-03-01T12:00:00.000000001Z`.

A scalar that cannot be converted throws a `TypeError` with one of these
stable codes:

- `ERR_INTEGER_RANGE`;
- `ERR_INVALID_DATE`;
- `ERR_INVALID_TIMESTAMP`;
- `ERR_INVALID_DECIMAL`;
- `ERR_NON_FINITE_DECIMAL`;
- `ERR_INVALID_UUID`.

## JSON documents

A JSON document is encrypted as its JSON text, so that Rust, Go, and
JavaScript all read the same document. Two functions convert a document:

- `JsRef::to_json(max_depth)` writes the text of a JavaScript value, for
  encrypting.
- `JsBuilder::build_json(&env, &document)` builds the JavaScript value of a
  decrypted document.

### Writing a document

`to_json` uses the same walk as every other value, with every rule in
[Safety notes](#safety-notes). For a document, the walk reads only the
values that a JSON document can contain:

| JavaScript                              | In the document              |
| --------------------------------------- | ---------------------------- |
| `null`, `boolean`, `string`             | the same                     |
| `Array`, plain object                   | an array, an object          |
| whole `number` within 2^53 - 1 of zero  | an integer                   |
| whole `number` from 2^53 up to 2^64     | refused                      |
| any other finite `number`               | a float                      |
| `bigint` within 64 bits                 | an integer, with its digits  |
| anything else                           | refused                      |

- **A whole number is an integer.** `to_json` writes `5000000000` as
  `5000000000`, as `JSON.stringify` does, and never as `5000000000.0`.
  Rust's `serde_json` and Go's `encoding/json` refuse a number with a
  fraction for an integer field. `to_json` writes `-0` as `0`.
- **A whole number from 2^53 up to 2^64 is refused**, either side of zero. A
  `number` that large may not have the digits that were written. An integer
  was probably meant, and a `bigint` stores an integer exactly. A number of
  2^64 or more is not an integer that any reader accepts, so it is a float.
- **A `bigint` is written as its exact digits**, from -2^63 to 2^64 - 1.
  That is the range that a JSON parser in Rust or Go reads. A `bigint`
  outside that range is refused, whatever its size.
- **Everything else is refused.** Each of these values has the code
  `recipher_js::not_json`:
  - `undefined`;
  - `NaN` and the infinities;
  - bytes: a `Buffer`, a typed array, or a `DataView`;
  - a `Date`;
  - a wrapper class instance.

  The message names the kind of value, and contains no part of the value. A
  function and a symbol have the code `recipher_js::not_a_value`, as for any
  value. No code calls a `toJSON` method.
- **`max_depth` is the limit of the code that reads the text.** The limit
  counts levels of arrays and objects, so `[1]` is one level. A document
  nested deeper has the code `recipher_js::too_deep`. The walk's own limit
  of 128 levels applies too.
- **`to_json` writes the text straight into a protected buffer.** The buffer
  wipes each allocation it outgrows, and wipes itself when it is dropped.
  `to_json` builds no tree of the document. `to_json` writes an object's
  members in the order JavaScript lists them.

### Building a document

`build_json` builds each number by these rules:

| In the document                          | JavaScript  |
| ---------------------------------------- | ----------- |
| an integer within 2^53 - 1 of zero       | `number`    |
| any other integer                        | `bigint`    |
| a float                                  | `number`    |

So an integer never loses a digit. The safe range is 2^53 - 1 either side of
zero. A `bigint` in the safe range comes back as a `number`. For example,
`to_json` writes `5n` as `5`. `build_json` reads `5` as the `number` `5`.

napi-rs has its own `serde_json` conversion, and `build_json` uses it for
each scalar. That conversion has the number rules above. This crate builds
each array and object itself, from own data properties. This crate refuses a
member named `__proto__`, `constructor`, or `prototype`.

This crate does not use napi-rs's conversion of a whole document. That
conversion assigns each member (`object[key] = value`), and an assignment
has two unsafe effects:

- An assignment to a member named `__proto__` sets the object's prototype.
- An assignment runs a setter that a polluted prototype defines. The setter
  then receives the decrypted value.

`build_json` copies nothing out of the document. The document belongs to the
caller, and the caller wipes it.

This crate does not use napi-rs's conversion in the other direction either,
from a JavaScript value to a `serde_json::Value`. That conversion:

- writes a whole number above 2^32 as a float;
- writes a `bigint` outside 64 bits as a string;
- drops a member that is `undefined`;
- reads a `Date` as `{}`;
- reads inherited properties;
- replaces an unpaired surrogate.

`tests/json.cjs` pins each of these.

## Errors

Four faults in a value stop the walk:

- a getter that throws;
- a string with an unpaired surrogate;
- a `BigInt` out of range;
- a `Date` outside the range of the wire format. That range is jiff's, about
  years -9999 to 9999.

The walk reports each fault through the sink's `Error::source`, as a
[`JsFault`]. A `JsFault` contains the napi status and the reason. At the
boundary with JavaScript, `JsFault::from_source` turns the fault back into
the napi error. A pending JavaScript exception passes through unchanged, so
the application receives the error that its getter threw.

When the fault is this crate's refusal of a value, `JsFault::refusal()`
returns a `Refusal`. A `Refusal` names the rule that the value broke. A
caller reports the refusal from the `Refusal`, and never reads the text of
the reason.

A `Refusal` is a diagnostic with a stable code and a message. Examples of
the code are `recipher_js::sparse_array` and `ERR_INTEGER_RANGE`. A
`Refusal` also has help, when the caller can do something about the refusal.

`JsFault::refusal()` returns `None` in two cases:

- a failure of Node-API's own;
- an exception that the application threw.

`JsRef::to_frame`, `JsRef::to_json`, `JsBuilder::build`, and
`JsBuilder::build_json` return the `JsFault` itself.

## Safety notes

### Copies of plaintext in memory

- V8 is Node's JavaScript engine. The original of each value to encrypt is
  in the V8 heap. V8 owns those originals, and Rust cannot wipe them.
- When this crate reads a value, every copy that Rust makes of a string is
  wiped on drop. Those copies are the UTF-16 code units and the UTF-8 text
  of each value, each key, and each wrapper class's text. This crate builds
  the UTF-8 text in a buffer of its final size, so no smaller buffer
  remains. This crate parses a wrapper's text in place, and makes no further
  copies.
- An error message names no property of the value, with one exception. The
  exception is one of the three refused property names in the next section.
  An error message contains no other part of the value.
- A frame that `to_frame` makes is `Protected`. The frame is wiped on drop.
- When this crate builds a value, it gives the decrypted text and bytes to
  JavaScript. V8 then owns them. The Rust copies made during the build are
  not wiped. Those copies are:
  - the text of each wrapper class, formatted by this crate or by
    `rust_decimal`;
  - each map key;
  - the bytes copied into a `Buffer`.

### Property names and nesting depth

- Three property names would reach the prototype chain: `__proto__`,
  `constructor`, and `prototype`. This crate rejects them in both
  directions.
- Nesting is limited to 128 levels in both directions. The count is the
  frame's count, and includes the levels inside a ciphertext's passthrough
  payload.
- The walk and the build each check the depth before they recurse. So Node
  does not abort for a tree that is far too deep for the stack. The walk or
  the build returns an error instead. A debug build can also walk a document
  at the limit.

### Objects that the walk accepts

- The walk accepts only plain objects and the wrapper classes for
  encryption. A plain object has the prototype `Object.prototype` or `null`.
- A `Map`, a `Set`, a `RegExp`, a `DataView`, a class instance, and other
  exotic objects keep their state in internal slots. Each one would silently
  encrypt as `{}`, so the walk rejects it with an error.
- The walk gets the prototype through `Object.getPrototypeOf`. That call
  runs a `Proxy`'s trap. So a proxied `Map` or `Date` reports its target's
  prototype, and is refused. The walk reads a proxy over a plain object
  through the proxy's traps.
- A typed array other than a `Uint8Array` is refused. A `DataView` is
  refused too. Neither is encrypted as its raw bytes. A `Buffer` is a
  `Uint8Array`.

### Properties and arrays

- The walk reads only the own, enumerable, string-keyed properties of an
  object. So a polluted `Object.prototype`, or an inherited enumerable
  getter, can never add a key to the encrypted value. Neither can run code
  during encryption.
- An own property explicitly set to `undefined` round-trips. The exception
  is the value of a record field that declares a type. That field refuses
  `undefined`, with the reason `undefined`.
- A sparse array is rejected, such as `[, , "x"]` or `new Array(n)`.
  `[undefined]` is not sparse, and round-trips. The walk detects a hole at
  each index with the semantics of `Object.hasOwn`. So a polluted
  `Array.prototype` cannot fill a hole with an inherited element.
- No code allocates memory in advance for an array length that JavaScript
  reports. `new Array(2**32 - 1)` is one line of code for an attacker, and
  creates no elements. This rule applies in the walk, in the build, and
  where a ciphertext is rebuilt.

### Strings

- A string or an object key with an unpaired UTF-16 surrogate is rejected.
  This crate does not silently normalise it. The conversion to UTF-8 would
  replace a lone surrogate with U+FFFD. This crate would then encrypt a
  plaintext that no longer equals the value the caller passed, or a key that
  no longer names its property.
- The walk reads each property back through its original JavaScript key.

### Values that this crate builds in JavaScript

- This crate writes everything it builds in JavaScript with own-property
  defines, and not with `[[Set]]` assignment. This crate calls
  `napi_define_properties` once for each object. The rule covers decrypted
  object properties and array elements. The rule also covers every
  ciphertext node's `t`, `v`, sequence elements, and map entries. So a
  setter that a polluted `Object.prototype` or `Array.prototype` defines can
  never receive decrypted plaintext or ciphertext. Such a setter can never
  discard a property either.
- A ciphertext node passed back for decryption must be an object. Node-API
  reads the properties of a primitive through its wrapper object. Without
  this check, a bare string would get `t` and `v` from `String.prototype`.
- Errors contain no cryptographic detail. At the trait layer, the error is
  `Unspecified`.

## Cargo features

This crate defines no Cargo feature flags.

## Compatibility

This crate requires the Rust standard library (`std`). This crate targets
native Node.js addons. This crate is not a WebAssembly binding.

<!-- src/lib.rs resolves these for rustdoc. -->
[`Encrypt`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Encrypt.html
[`Sink`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Sink.html
[`JsFault`]: src/error.rs
