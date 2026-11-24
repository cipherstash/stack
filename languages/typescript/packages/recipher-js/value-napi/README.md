# recipher-value-napi

The JavaScript value bridge of `@cipherstash/recipher`: it reads a Node-API
value as vitaminc's plaintext model, and builds a JavaScript value from it.
The `recipher-js` addon reads and builds every value through it.

This crate is a copy of `vitaminc-aead-napi` 0.10.0, from
[`cipherstash/vitaminc`](https://github.com/cipherstash/vitaminc) at commit
`b3f69b12c1fde38faff2becec04f9e633dbd4f1c`, renamed. It is not published.
`tests/testdata/value-conformance.json` is vitaminc's `testdata/value-conformance.json`
at the same commit: the vectors the Rust, Node and Go bindings all check.

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
- **`JsCipherText<Leaf, P>`** — projects the generic `CipherText` container
  onto plain JS values (`{ t, v }` nodes with `Buffer` leaves) and back, as
  an in-memory/application-side representation. Durable cross-language
  database storage is the EQL layer's job, not this projection's. The
  passthrough payload `P` converts through `NapiPassthrough`, implemented
  for `PassthroughFrame` (the sink-based tree's payload) and `()`, which
  applies the tree's nesting limit to the payload too.
- **`Wrappers`** — the wrapper classes `VcDate`, `VcTimestamp`,
  `VcDecimal` and `VcUuid`, defined once per environment and exported by an
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
| `VcDate("YYYY-MM-DD")`              | `Date` over the day count                |
| `VcTimestamp("RFC 3339, ns")`       | `Timestamp(Nanos)` over the count        |
| `VcDecimal("1.50")`                 | `Decimal { scale }` over the mantissa    |
| `VcUuid("hyphenated hex")`          | `Uuid` over sixteen bytes                |
| `Array`                             | sequence                                 |
| plain object                        | map, over own enumerable string keys     |

And back: every int width is a `BigInt`; both float widths are a `number`
(`f32` widens exactly); a timestamp in any unit is a `Date` when it is
whole milliseconds and a `VcTimestamp` otherwise, so no precision is
discarded; a calendar date, a decimal and a UUID are their wrapper. A
`Date` is stored as its millisecond count and read back as the same
count, never converted through seconds and nanoseconds. A logical type
this build does not know has no JavaScript value and is refused rather
than shown with its type dropped.

Equality terms share one domain across integer widths, so a `BigInt`
written as `int8` matches the same number written as `int64` from Go;
both float widths likewise share one domain. Integers and floats stay
distinct, so a JS `number` 5 does not match an `int64` 5: use `BigInt` for
integer data.

### The wrapper classes

JavaScript has no type of its own for a calendar date, a timestamp finer
than a millisecond, a decimal or a UUID, so each is an instance of a small
class holding its text: `new VcDecimal("1.50")`. The constructor takes a
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
(`recipher::sparse_array`, `ERR_INTEGER_RANGE`), a message and, where there
is something to do, help. A caller reports the refusal from that, and never
reads the reason's text. It is `None` for a failure of Node-API's own and
for an exception the application threw. `JsRef::to_frame` and
`JsBuilder::build` return the `JsFault` itself.

This crate is a library consumed by the Node addon (cdylib/npm package);
it is not itself loadable from Node.

## Safety notes

- The original copies of encrypted values in the V8 heap are owned by the
  JS engine and cannot be wiped from Rust. On the way in, every copy Rust
  makes of a string is wiped on drop: the UTF-16 code units and the UTF-8
  text of each value, key and wrapper class's text. The UTF-8 text is built
  in a buffer of its final size, so no smaller buffer is left behind, and
  the wrapper text is parsed in place without further copies. The one
  exception is an error message, which names a property a getter removed
  while the walk was reading it. A frame snapshot is `Protected` and wiped
  on drop.
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
  property explicitly set to `undefined` round-trips.
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
