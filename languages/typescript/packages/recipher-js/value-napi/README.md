# recipher-value-napi

The JavaScript value bridge of `@cipherstash/recipher`: it reads a Node-API
value as vitaminc's plaintext model, and builds a JavaScript value from it.
The `recipher-js` addon reads and builds every value through it.

This crate is a copy of `vitaminc-aead-napi` 0.10.0, from
[`cipherstash/vitaminc`](https://github.com/cipherstash/vitaminc) at commit
`b3f69b12c1fde38faff2becec04f9e633dbd4f1c`, renamed. It is not published.
Its wrapper classes are `RcDate`, `RcTimestamp`, `RcDecimal` and `RcUuid`.
vitaminc names them `VcDate` and so on.
`tests/testdata/value-conformance.json` is a copy of
`conformance/vitaminc-aead/value-conformance.json`: the vectors the Rust,
Node and Go bindings all check. The bridge's tests read the copy, so a run
scoped to this package finds it.
`scripts/__tests__/recipher-js-value-corpus-parity.test.mjs` fails when the
two parse to different JSON, so change both together, then run
`pnpm run code:fix`.

An incoming JavaScript value implements [`Encrypt`]; a [`Sink`] builds
the outgoing value. This crate supplies both sides of that conversion:

- **`JsRef<'e>`** — a live JavaScript value as an `Encrypt`. The walk runs
  on the JavaScript thread, reading each value as it goes, so no value tree
  is built and a scalar leaves the engine only to go straight to the sink.
  `encrypt(JsRef::new(value), &cipher, aad)` seals a value in place. To
  encrypt off the JavaScript thread, `JsRef::to_frame` snapshots the value
  as a frame there, and a worker seals the frame with no JavaScript access.
- **`JsBuilder<'e>`** — a `Sink` that builds JavaScript values, for
  `decrypt_into(&cipher, ct, aad, JsBuilder::new(&env))`, or
  `JsBuilder::build(&env, frame)` for a frame.
- **`JsRef::to_json`** and **`JsBuilder::build_json`** — a JSON document.
  The first writes a JavaScript value as the text of a document, and the
  second builds the JavaScript value of a `serde_json::Value`. See
  [JSON documents](#json-documents).
- **`JsCipherText<Leaf, P>`** — projects the generic `CipherText` container
  onto plain JS values (`{ t, v }` nodes with `Buffer` leaves) and back, as
  an in-memory/application-side representation. Durable cross-language
  database storage is the EQL layer's job, not this projection's. The
  passthrough payload `P` converts through `NapiPassthrough`, implemented
  for `PassthroughFrame` (the sink-based tree's payload) and `()`, which
  applies the tree's nesting limit to the payload too.
- **`Wrappers`** — the wrapper classes `RcDate`, `RcTimestamp`,
  `RcDecimal` and `RcUuid`, defined once per environment and exported by an
  addon with `Wrappers::exports`. The crate keeps them in its own registry,
  keyed by the environment and released by an environment cleanup hook; the
  addon's instance data is untouched.

## Run a Node example

This crate supplies Rust building blocks for a Node addon. The
[test addon](tests/addon/src/lib.rs)
exports `encryptValue` and `decryptValue` using `JsRef`, `JsCipherText`, and
`JsBuilder` with AES-256-GCM. It uses a fixed, public test key; use it only
with sample data.

From `languages/typescript/packages/recipher-js`, with Rust and Node.js
installed, run:

```sh
cargo test -p recipher-value-napi --test node
```

This builds the addon and runs the following example, along with the binding
tests. To run the example separately, save it as `example.cjs` in that
directory and run `node example.cjs target/napi-test-addon/addon.node`.

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

The associated data (`aad`) must match on encryption and decryption. It can
bind ciphertext to a tenant or another application context. Use `bigint`
for integer values, as shown by `42n`; JavaScript `number` values are floats.

## The mapping

| JavaScript                          | Scalar                                   |
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

And back: every int width is a `BigInt`; both float widths are a `number`
(`f32` widens exactly); a timestamp in any unit is a `Date` when it is
whole milliseconds and an `RcTimestamp` otherwise, so no precision is
discarded; a calendar date, a decimal and a UUID are their wrapper. A
`Date` is stored as its millisecond count and read back as the same
count, never converted through seconds and nanoseconds. A logical type
this build does not know has no JavaScript value and is refused rather
than shown with its type dropped.

Equality terms share one domain across integer widths, so a `BigInt`
written as `int8` matches the same number written as `int64` from Go;
both float widths likewise share one domain. Integers and floats stay
distinct, so a JS `number` 5 does not match an `int64` 5: use `BigInt` for
integer data. A record field that declares a type is the exception: the
engine reads each value written to it, or queried against it, as that
type when the conversion is exact, so `5` and `5n` are both the `int64` 5
on an `int64` field.

### The wrapper classes

JavaScript has no type of its own for a calendar date, a timestamp finer
than a millisecond, a decimal or a UUID, so each is an instance of a small
class holding its text: `new RcDecimal("1.50")`. The constructor takes a
string and nothing else; the text is checked, and the scalar built from
it, when the value is encrypted, so one rule applies however the instance
was made. `value` is an own, read-only, enumerable property, so
`JSON.stringify` (which gives the bare text through `toJSON`),
`structuredClone` and a deep equality all see it. A clone, or a wrapper
posted to a Worker, is a plain `{ value }` object and encrypts as a map;
rebuild it with the constructor on the other side. The classes, their
prototypes and every instance are frozen, and construction uses what the
class captured when it was defined, so a polluted `Object.prototype` or a
later edit of a class cannot make `value` writable, break a decrypt, or
turn a plain `{ value }` object back into a wrapper.

An instance is not a plain object, so it is never confused with data
another language wrote as an ordinary one-key object: Go's
`{"date": "2024-01-01"}` decrypts in JS as that object and encrypts again
unchanged. Decimal text is exact fixed-point, not a JS number or an
arbitrary decimal-library instance; a negative zero reads back as zero
with its scale kept. A leap second has no count since the epoch
and is refused. Dates and timestamps cover jiff's range, years -9999 to
9999, as in every binding, and a negative year is a sign and six digits
(`-000005-03-01T12:00:00.000000001Z`), as JavaScript writes it.

Scalar failures throw a `TypeError` with a stable code: `ERR_INTEGER_RANGE`,
`ERR_INVALID_DATE`, `ERR_INVALID_TIMESTAMP`, `ERR_INVALID_DECIMAL`,
`ERR_NON_FINITE_DECIMAL` and `ERR_INVALID_UUID`.

## JSON documents

A JSON document is encrypted as its JSON text, so that Rust, Go and
JavaScript all read the same document. `JsRef::to_json(max_depth)` writes
the text of a JavaScript value, for encrypting. `JsBuilder::build_json(&env,
&document)` builds the JavaScript value of a decrypted document.

### Writing a document

The walk is the one every value goes through, with every rule in
[Safety notes](#safety-notes). It reads only what a JSON document holds:

| JavaScript                              | In the document              |
| --------------------------------------- | ---------------------------- |
| `null`, `boolean`, `string`             | the same                     |
| `Array`, plain object                   | an array, an object          |
| whole `number` within 2^53 - 1 of zero  | an integer                   |
| whole `number` from 2^53 up to 2^64     | refused                      |
| any other finite `number`               | a float                      |
| `bigint` within 64 bits                 | an integer, with its digits  |
| anything else                           | refused                      |

- **A whole number is an integer.** `5000000000` is written `5000000000`,
  as `JSON.stringify` writes it, and never `5000000000.0`. Rust's
  `serde_json` and Go's `encoding/json` refuse a number with a fraction for
  an integer field. `-0` is written `0`.
- **A whole number from 2^53 up to 2^64 is refused**, either side of zero.
  A `number` that large may not have the digits that were written, and an
  integer was probably meant. A `bigint` holds it exactly. A number of 2^64
  or more is no integer that a reader takes, so it is a float.
- **A `bigint` is its exact digits**, from -2^63 to 2^64 - 1. That is the
  range a JSON parser in Rust or Go reads. A `bigint` outside it is
  refused, whatever its size.
- **Everything else is refused**: `undefined`, `NaN` and the infinities,
  bytes (a `Buffer`, a typed array, a `DataView`), a `Date`, and a wrapper
  class instance. Each has the code `recipher_js::not_json`, and a message
  that names the kind of value and no part of it. A function and a symbol
  are `recipher_js::not_a_value`, as for any value. Nothing calls a
  `toJSON` method.
- **`max_depth` is the reader's limit**, in levels of arrays and objects:
  `[1]` is one level. A document nested deeper is `recipher_js::too_deep`.
  The walk's own limit of 128 applies too.
- **The text is written straight into a protected buffer.** The buffer
  wipes each allocation it outgrows, and wipes itself when it is dropped.
  No tree of the document is built on the way. An object's members are
  written in the order JavaScript lists them.

### Building a document

| In the document                          | JavaScript  |
| ---------------------------------------- | ----------- |
| an integer within 2^53 - 1 of zero       | `number`    |
| any other integer                        | `bigint`    |
| a float                                  | `number`    |

So an integer never loses a digit. A `bigint` that is in the safe range
comes back as a `number`: `5n` is written `5`, and `5` is read as `5`.

Each scalar is converted by napi-rs's own `serde_json` conversion, which
has this number rule. An array and an object are built here, from own data
properties, and a member named `__proto__`, `constructor` or `prototype`
is refused. napi-rs's conversion of a whole document assigns each member
(`object[key] = value`). An assignment gives a member named `__proto__` to
the object as its prototype, and runs a setter that a polluted prototype
defines, which then receives the decrypted value.

`build_json` copies nothing out of the document. The caller owns the
document, and wipes it.

napi-rs's conversion in the other direction, from a JavaScript value to a
`serde_json::Value`, is not used. It writes a whole number above 2^32 as a
float and a wide `bigint` as a string. It drops a member that is
`undefined`, and reads a `Date` as `{}`. It also reads inherited properties,
and replaces an unpaired surrogate. `tests/json.cjs` pins each of these.

## Errors

A getter that throws, a string with an unpaired surrogate, a `BigInt` out
of range or a `Date` outside the wire's range (jiff's, about years -9999
to 9999)
stops the walk through the
sink's `Error::source`, as a [`JsFault`] carrying the napi status and
reason. At the boundary, `JsFault::from_source` turns it back into the
napi error, and a pending JavaScript exception surfaces unchanged: the
application sees the error its getter threw.

When the fault is this crate's refusal of a value, `JsFault::refusal()` says
which rule the value broke, as a `Refusal`: a diagnostic with a stable code
(`recipher_js::sparse_array`, `ERR_INTEGER_RANGE`), a message and, where there
is something to do, help. A caller reports the refusal from that, and never
reads the reason's text. It is `None` for a failure of Node-API's own and
for an exception the application threw. `JsRef::to_frame`,
`JsRef::to_json`, `JsBuilder::build` and `JsBuilder::build_json` return the
`JsFault` itself.

This crate is a library consumed by the Node addon (cdylib/npm package);
it is not itself loadable from Node.

## Safety notes

- The original copies of encrypted values in the V8 heap are owned by the
  JS engine and cannot be wiped from Rust. On the way in, every copy Rust
  makes of a string is wiped on drop: the UTF-16 code units and the UTF-8
  text of each value, key and wrapper class's text. The UTF-8 text is built
  in a buffer of its final size, so no smaller buffer is left behind, and
  the wrapper text is parsed in place without further copies. An error
  message names no property of the value, except one of the three refused
  names below, and holds no other part of it. A frame snapshot is `Protected` and
  wiped on drop.
- On the way out, the build hands decrypted text and bytes to JavaScript,
  where the engine owns them. The Rust copies made along the way are not
  wiped: the text of each wrapper class (formatted by the binding or
  `rust_decimal`), each map key, and the bytes copied into a
  `Buffer`.
- Property names that would touch the prototype chain (`__proto__`,
  `constructor`, `prototype`) are rejected in both directions. Nesting is
  limited to 128 levels in both directions too, counted as the frame counts
  it, including inside a ciphertext's passthrough payload. The walk and the
  build each check the depth before recursing, so a tree far too deep for
  the stack fails cleanly instead of aborting Node, and a document at the
  limit walks in a debug build.
- Only **plain objects** (prototype `Object.prototype` or `null`) and the
  wrapper classes are accepted for encryption. `Map`, `Set`, `RegExp`,
  `DataView`, class instances and other exotic objects keep their state in
  internal slots and would silently encrypt as `{}` — they are rejected with
  an error instead. The prototype is asked through `Object.getPrototypeOf`,
  which runs a `Proxy`'s trap, so a proxied `Map` or `Date` reports its
  target's prototype and is refused; a proxy over a plain object walks
  through its traps. Typed arrays other than `Uint8Array` (and `Buffer`),
  and `DataView`, are refused rather than sealed as their raw bytes.
- Object enumeration reads **own, enumerable, string-keyed** properties
  only, so a polluted `Object.prototype` (or inherited enumerable getters)
  can never leak keys into — or run code during — encryption. An own
  property explicitly set to `undefined` round-trips, except as the value
  of a record field that declares a type, which refuses it with the reason
  `undefined`.
- Sparse arrays (`[, , "x"]`, `new Array(n)`) are rejected; `[undefined]`
  is not sparse and round-trips. A hole is detected per index via
  `Object.hasOwn` semantics, so a polluted `Array.prototype` cannot fill
  holes with inherited elements.
- JS-reported array lengths are never trusted for up-front allocation
  (a `new Array(2**32 - 1)` costs the attacker one line and materialises
  nothing), in the walk, the build and the ciphertext rebuilder.
- Strings and object keys containing unpaired UTF-16 surrogates are
  **rejected** rather than silently normalized: the UTF-8 fetch would
  replace a lone surrogate with U+FFFD, sealing a plaintext that no longer
  equals what the caller passed, or a key that no longer names its
  property. Each property is read back through its original JS key.
- Everything this crate builds in JS is written with **own-property
  defines** (`napi_define_properties`, one call per object), not `[[Set]]`
  assignment: decrypted object properties and array elements, and every
  ciphertext node's `t`, `v`, sequence elements and map entries. A polluted
  setter on `Object.prototype` or `Array.prototype` can never observe
  decrypted plaintext or ciphertext, or swallow a property.
- A ciphertext node handed back for decryption must be an object. N-API
  reads properties of a primitive through its wrapper, so a bare string
  would otherwise take `t` and `v` from `String.prototype`.
- Errors carry no cryptographic detail (`Unspecified` at the trait layer).


## Cargo features

This crate defines no Cargo feature flags.

## Compatibility

Requires the Rust standard library (`std`). This crate targets native
Node.js addons; it is not a WebAssembly binding.

<!-- src/lib.rs resolves these for rustdoc. -->
[`Encrypt`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Encrypt.html
[`Sink`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Sink.html
[`JsFault`]: src/error.rs
