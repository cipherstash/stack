// JSON documents at the N-API boundary: a JavaScript value written as the
// text of a document (`JsRef::to_json`), and a document built as a
// JavaScript value (`JsBuilder::build_json`). The last section pins what
// napi-rs's own `serde_json` conversion does, which is why the bridge reads
// a value itself and writes arrays and objects itself. Run by tests/node.rs
// with the test addon's path.
const assert = require('node:assert/strict')
const path = require('node:path')
const addon = require(path.resolve(process.argv[2]))

// The depth the engine's JSON parser reads.
const DEPTH = 127

const NOT_JSON = 'recipher_js::not_json'

/** The JSON text of `value`. */
const text = (value, depth = DEPTH) => {
  const out = addon.jsonText(value, depth)
  assert.equal(out.code, undefined, out.message)
  return out.text
}

/** The refusal of `value`: its code and its message. */
const refusal = (value, depth = DEPTH) => {
  const out = addon.jsonText(value, depth)
  assert.equal(out.text, undefined, 'the value was written')
  return out
}

/** The JavaScript value of the document `json`. */
const built = (json) => {
  const out = addon.jsonValue(json)
  assert.equal(out.code, undefined, out.message)
  return out.value
}

// --- Writing a value as JSON text ---

// An object, an array, a string, a boolean and null stay as they are. The
// members keep the order JavaScript lists them in.
assert.equal(
  text({ b: 'text', a: [true, false, null], nested: { deep: [] } }),
  '{"b":"text","a":[true,false,null],"nested":{"deep":[]}}',
)
assert.equal(text(null), 'null')
assert.equal(text('alone'), '"alone"')
assert.equal(text([]), '[]')
assert.equal(text({}), '{}')
assert.equal(text(Object.create(null)), '{}')

// A whole number in the safe range is an integer, as JSON.stringify writes
// it, at every size. napi-rs writes one above 2^32 as a float.
for (const whole of [
  0,
  5,
  -5,
  4294967296,
  5000000000,
  -5000000000,
  // A millisecond timestamp, as Date.now() gives one.
  1764288000000,
  Number.MAX_SAFE_INTEGER,
  Number.MIN_SAFE_INTEGER,
]) {
  assert.equal(text(whole), JSON.stringify(whole), String(whole))
  assert.equal(text({ n: whole }), `{"n":${whole}}`)
}
assert.equal(text(5000000000), '5000000000')
const now = Date.now()
assert.equal(text({ t: now }), `{"t":${now}}`)
// JSON.stringify(-0) is "0".
assert.equal(text(-0), '0')

// Any other finite number is a float that reads back as the same number.
for (const float of [
  1.5,
  -0.25,
  0.1,
  5e-324,
  // 2^64 and above.
  2 ** 64,
  1e20,
  -6.02e23,
  Number.MAX_VALUE,
  -Number.MAX_VALUE,
]) {
  const written = text(float)
  assert.equal(JSON.parse(written), float, written)
  // A fraction or an exponent, so no reader takes it as an integer.
  assert.match(written, /[.e]/, written)
}

// A whole number from 2^53 up to 2^64 is refused: its digits may not be
// the ones written.
for (const unsafe of [
  2 ** 53,
  2 ** 53 + 2,
  2 ** 60,
  // The largest number below 2^64.
  2 ** 64 - 2048,
  -(2 ** 53),
  -(2 ** 63),
]) {
  const refused = refusal({ n: unsafe })
  assert.equal(refused.code, NOT_JSON, String(unsafe))
  assert.match(refused.message, /bigint/)
  // No message holds any part of the value.
  assert.ok(!/\d{6}/.test(refused.message), refused.message)
}

// NaN and the infinities have no JSON form. JSON.stringify writes them as
// null, which would decrypt as another value.
for (const number of [
  Number.NaN,
  Number.POSITIVE_INFINITY,
  Number.NEGATIVE_INFINITY,
]) {
  const refused = refusal([number])
  assert.equal(refused.code, NOT_JSON, String(number))
  assert.match(refused.message, /not finite/)
}

// A bigint is its exact digits, within 64 bits, signed or unsigned.
assert.equal(text(0n), '0')
assert.equal(text(-0n), '0')
assert.equal(text(5n), '5')
assert.equal(text(-5n), '-5')
assert.equal(text(2n ** 53n), '9007199254740992')
assert.equal(text(2n ** 63n - 1n), '9223372036854775807')
assert.equal(text(2n ** 63n), '9223372036854775808')
assert.equal(text(2n ** 64n - 1n), '18446744073709551615')
assert.equal(text(-(2n ** 63n)), '-9223372036854775808')
// Outside 64 bits a bigint is refused, with one refusal at every size.
for (const wide of [
  2n ** 64n,
  -(2n ** 63n) - 1n,
  2n ** 127n,
  -(2n ** 127n),
  2n ** 128n,
  2n ** 200n,
  -(2n ** 200n),
]) {
  const refused = refusal({ id: wide })
  assert.equal(refused.code, NOT_JSON, String(wide))
  assert.match(refused.message, /64-bit/)
  assert.ok(!/\d{6}/.test(refused.message), refused.message)
}

// A value with no JSON form is refused, at the top, in an array and as a
// member. JSON.stringify would drop it, or write something else.
const RcDate = addon.RcDate
const noJsonForm = [
  [undefined, /undefined/],
  [new Date(0), /a date/],
  [new Date(Number.NaN), /a date/],
  [Buffer.from('bytes'), /bytes/],
  [new Uint8Array(2), /bytes/],
  [new Uint16Array(2), /bytes/],
  [new Float64Array(2), /bytes/],
  [new DataView(new ArrayBuffer(2)), /bytes/],
  [new RcDate('2026-11-23'), /a date/],
  [new addon.RcTimestamp('2026-11-23T01:02:03.000000001Z'), /a date/],
  [new addon.RcDecimal('1.50'), /a decimal/],
  [new addon.RcUuid('123e4567-e89b-12d3-a456-426614174000'), /a UUID/],
  // A wrapper is refused before its text is read, so a malformed one is
  // refused the same way.
  [new RcDate('not a date'), /a date/],
]
for (const [value, message] of noJsonForm) {
  for (const document of [
    value,
    [value],
    { member: value },
    [[{ deep: value }]],
  ]) {
    const refused = refusal(document)
    assert.equal(refused.code, NOT_JSON)
    assert.match(refused.message, message)
  }
}

// A function and a symbol are no value at all.
for (const value of [() => 1, function named() {}, Symbol('s'), class {}]) {
  assert.equal(refusal(value).code, 'recipher_js::not_a_value')
  assert.equal(refusal({ member: value }).code, 'recipher_js::not_a_value')
}
// So an object with a toJSON method is refused: nothing calls the method.
assert.equal(
  refusal({ toJSON: () => 'replaced' }).code,
  'recipher_js::not_a_value',
)

// The walk's safety rules apply to a document as to any value.
assert.equal(refusal(new Map([['k', 1]])).code, 'recipher_js::not_plain')
assert.equal(refusal(new Set([1])).code, 'recipher_js::not_plain')
assert.equal(refusal(new (class Thing {})()).code, 'recipher_js::not_plain')
assert.equal(refusal(new ArrayBuffer(2)).code, 'recipher_js::not_plain')
assert.equal(
  refusal(Object.create({ inherited: 1 })).code,
  'recipher_js::not_plain',
)
// biome-ignore lint/suspicious/noSparseArray: a hole is the case.
assert.equal(refusal([1, , 3]).code, 'recipher_js::sparse_array')
assert.equal(refusal(new Array(3)).code, 'recipher_js::sparse_array')
assert.equal(refusal('\uD800').code, 'recipher_js::unpaired_surrogate')
assert.equal(refusal({ '\uDC00': 1 }).code, 'recipher_js::unpaired_surrogate')
for (const reserved of ['__proto__', 'constructor', 'prototype']) {
  assert.equal(
    refusal(JSON.parse(`{"${reserved}":1}`)).code,
    'recipher_js::reserved_key',
  )
}
// Only own, enumerable, string keys are members.
const mixed = { own: 1 }
Object.defineProperty(mixed, 'hidden', { value: 2, enumerable: false })
mixed[Symbol('s')] = 3
assert.equal(text(mixed), '{"own":1}')
Object.prototype.polluted = 'x'
try {
  assert.equal(text({ a: 1 }), '{"a":1}')
} finally {
  delete Object.prototype.polluted
}
// A hole is not read through a polluted Array.prototype.
Array.prototype[1] = 'injected'
try {
  // biome-ignore lint/suspicious/noSparseArray: a hole is the case.
  assert.equal(refusal(['a', , 'b']).code, 'recipher_js::sparse_array')
} finally {
  delete Array.prototype[1]
}
// A getter that throws surfaces as the error it threw, and is no refusal.
const thrown = new Error('the getter threw')
assert.throws(
  () =>
    addon.jsonText(
      {
        get member() {
          throw thrown
        },
      },
      DEPTH,
    ),
  (error) => error === thrown,
)

// Text is written with JSON's escapes, and reads back as itself.
for (const plain of [
  '',
  'quote " and backslash \\',
  'line\nfeed, tab\t, nul\0 and \u001f',
  'José, 日本, 😀,   and \u{10FFFF}',
]) {
  assert.equal(JSON.parse(text(plain)), plain)
  assert.deepEqual(JSON.parse(text({ [plain]: [plain] })), { [plain]: [plain] })
}
assert.equal(text('a"b\n'), '"a\\"b\\n"')

// The text of a document is the document.
const document = {
  number: '4111 1111 1111 1111',
  expiry: { month: 4, year: 2031 },
  tags: ['a', 'b'],
  active: true,
  note: null,
  ratio: 0.75,
  big: 1e21,
}
assert.deepEqual(JSON.parse(text(document)), document)

// A document nests as deep as the limit it is given, and no deeper. The
// innermost array is empty, so `nested(n)` is n levels.
const nested = (levels) => {
  let value = []
  for (let level = 1; level < levels; level++) value = [value]
  return value
}
const nestedObject = (levels) => {
  let value = {}
  for (let level = 1; level < levels; level++) value = { k: value }
  return value
}
for (const limit of [1, 2, DEPTH]) {
  assert.equal(
    text(nested(limit), limit),
    '['.repeat(limit) + ']'.repeat(limit),
  )
  assert.ok(text(nestedObject(limit), limit).startsWith('{'))
  for (const tooDeep of [nested(limit + 1), nestedObject(limit + 1)]) {
    const refused = refusal(tooDeep, limit)
    assert.equal(refused.code, 'recipher_js::too_deep')
    assert.equal(
      refused.message,
      `the value is nested deeper than ${limit} levels`,
    )
  }
}
// A scalar is no level.
assert.equal(text(5, 0), '5')
assert.equal(refusal([], 0).code, 'recipher_js::too_deep')
// A cycle is refused as too deep, at the limit given or at the walk's own.
const cycle = []
cycle.push(cycle)
assert.equal(refusal(cycle).code, 'recipher_js::too_deep')
assert.equal(refusal(cycle, 100000).code, 'recipher_js::too_deep')
const loop = {}
loop.self = loop
assert.equal(refusal(loop).code, 'recipher_js::too_deep')

// A long array is written whole.
const long = Array.from({ length: 5000 }, (_, index) => index)
assert.deepEqual(JSON.parse(text(long)), long)

// --- Building a document as a JavaScript value ---

// An integer in the safe range is a number, at both ends of the range.
assert.strictEqual(built('5'), 5)
assert.strictEqual(built('-5'), -5)
assert.strictEqual(built('5000000000'), 5000000000)
assert.strictEqual(built('9007199254740991'), Number.MAX_SAFE_INTEGER)
assert.strictEqual(built('-9007199254740991'), Number.MIN_SAFE_INTEGER)
// Any other integer is a bigint, so no digit is lost.
assert.strictEqual(built('9007199254740992'), 2n ** 53n)
assert.strictEqual(built('-9007199254740992'), -(2n ** 53n))
assert.strictEqual(built('9223372036854775807'), 2n ** 63n - 1n)
assert.strictEqual(built('9223372036854775808'), 2n ** 63n)
assert.strictEqual(built('-9223372036854775808'), -(2n ** 63n))
assert.strictEqual(built('18446744073709551615'), 2n ** 64n - 1n)
// A float is a number, whole or not.
assert.strictEqual(built('1.5'), 1.5)
assert.strictEqual(built('5.0'), 5)
assert.strictEqual(built('1e20'), 1e20)
assert.strictEqual(built('1.7976931348623157e308'), Number.MAX_VALUE)
assert.ok(Object.is(built('-0.0'), -0))
// The rest stay as they are.
assert.strictEqual(built('null'), null)
assert.strictEqual(built('true'), true)
assert.strictEqual(built('"text 😀"'), 'text 😀')
assert.deepEqual(
  built('{"a":[1,{"b":null,"big":18446744073709551615}],"c":"d","e":{}}'),
  { a: [1, { b: null, big: 18446744073709551615n }], c: 'd', e: {} },
)

// What is written reads back, with a safe bigint as a number.
assert.deepEqual(built(text(document)), document)
assert.deepEqual(
  built(text({ small: 5n, big: 2n ** 64n - 1n, t: 1764288000000 })),
  {
    small: 5,
    big: 2n ** 64n - 1n,
    t: 1764288000000,
  },
)

// An array and an object are ordinary ones, of own data properties that
// are writable, enumerable and configurable.
const made = built('{"k":[7]}')
assert.equal(Object.getPrototypeOf(made), Object.prototype)
assert.ok(Array.isArray(made.k))
assert.ok(Object.hasOwn(made, 'k'))
assert.deepEqual(Object.getOwnPropertyDescriptor(made.k, '0'), {
  value: 7,
  writable: true,
  enumerable: true,
  configurable: true,
})
assert.deepEqual(built('[]'), [])
assert.equal(built('[1,2,3]').length, 3)
// A key keeps its exact text.
assert.deepEqual(Object.keys(built('{"a\\u0000b":1,"7":2,"":3}')).sort(), [
  '',
  '7',
  'a\0b',
])

// A setter on a polluted prototype never receives a decrypted value, from
// an object or from an array.
let captured = 'untouched'
Object.defineProperty(Object.prototype, 'leak', {
  set(value) {
    captured = value
  },
  configurable: true,
})
Object.defineProperty(Array.prototype, '0', {
  set(value) {
    captured = value
  },
  configurable: true,
})
try {
  const out = built('{"leak":"secret","list":["secret"]}')
  assert.equal(captured, 'untouched')
  assert.ok(Object.hasOwn(out, 'leak'))
  assert.equal(out.leak, 'secret')
  assert.ok(Object.hasOwn(out.list, '0'))
  assert.equal(out.list[0], 'secret')
} finally {
  delete Object.prototype.leak
  delete Array.prototype[0]
}

// A member with a reserved name is refused, at any depth: it is never
// assigned, so it never becomes the object's prototype.
for (const reserved of ['__proto__', 'constructor', 'prototype']) {
  for (const json of [
    `{"${reserved}":{"polluted":true}}`,
    `[{"deep":{"${reserved}":1}}]`,
  ]) {
    const out = addon.jsonValue(json)
    assert.equal(out.value, undefined, json)
    assert.equal(out.code, 'recipher_js::reserved_key', json)
  }
}
assert.equal({}.polluted, undefined)

// A document nested as deep as the engine reads is built.
assert.ok(Array.isArray(built('['.repeat(DEPTH) + ']'.repeat(DEPTH))))
// The build has a limit of its own, 128 levels as for any value, for a
// document that no parser has bounded. Arrays and objects both count.
for (const wrap of ['array', 'object']) {
  let deepest = addon.jsonNestedValue(128, wrap).value
  assert.notEqual(deepest, undefined, wrap)
  for (let level = 0; level < 128; level++) {
    deepest = wrap === 'array' ? deepest[0] : deepest.k
  }
  assert.strictEqual(deepest, true)
  const tooDeep = addon.jsonNestedValue(129, wrap)
  assert.equal(tooDeep.value, undefined, wrap)
  assert.equal(tooDeep.code, 'recipher_js::too_deep', wrap)
  assert.equal(tooDeep.message, 'the value is nested deeper than 128 levels')
}

// --- What napi-rs's own conversion does ---
//
// The bridge uses napi-rs's conversion for a document's scalars only. These
// cases pin why. If one of them fails after a napi-rs update, read the
// change and decide again.

// Reading a value. A whole number above 2^32, or below -2^31, becomes a
// float. Rust's serde_json and Go's encoding/json refuse `5000000000.0` for
// an integer field.
assert.equal(addon.napiJsonText(4294967295), '4294967295')
assert.equal(addon.napiJsonText(5000000000), '5000000000.0')
assert.equal(addon.napiJsonText(-5000000000), '-5000000000.0')
assert.equal(addon.napiJsonText(2 ** 53), '9007199254740992.0')
// A bigint outside 64 bits becomes a string of its digits.
assert.equal(addon.napiJsonText(2n ** 64n), '"18446744073709551616"')
// A member that is undefined is dropped, and a Date, a Map and a wrapper
// class instance are read as objects.
assert.equal(addon.napiJsonText({ a: undefined, b: 1 }), '{"b":1}')
assert.equal(addon.napiJsonText(new Date(0)), '{}')
assert.equal(addon.napiJsonText(new Map([[1, 2]])), '{}')
assert.equal(
  addon.napiJsonText(new RcDate('2026-11-23')),
  '{"value":"2026-11-23"}',
)
// An inherited property is read, and an unpaired surrogate is replaced.
assert.equal(
  addon.napiJsonText(Object.create({ inherited: 1 })),
  '{"inherited":1}',
)
assert.equal(addon.napiJsonText('\uD800'), '"�"')

// Building a value. The number rule is the one the bridge documents, and
// uses.
assert.deepEqual(
  addon.napiJsonValue(
    '[5,9007199254740991,9007199254740992,-9223372036854775808,18446744073709551615,1.5,1e20,5.0]',
  ),
  [
    5,
    Number.MAX_SAFE_INTEGER,
    2n ** 53n,
    -(2n ** 63n),
    2n ** 64n - 1n,
    1.5,
    1e20,
    5,
  ],
)
// A member named `__proto__` becomes the object's prototype.
const assigned = addon.napiJsonValue('{"__proto__":{"inherited":1},"own":2}')
assert.deepEqual(Object.keys(assigned), ['own'])
assert.equal(assigned.inherited, 1)
// Members and elements are assigned, so a setter on a polluted prototype
// receives the value, and the result has no such property of its own.
captured = 'untouched'
Object.defineProperty(Object.prototype, 'leak', {
  set(value) {
    captured = value
  },
  configurable: true,
})
try {
  const out = addon.napiJsonValue('{"leak":"secret"}')
  assert.equal(captured, 'secret')
  assert.ok(!Object.hasOwn(out, 'leak'))
} finally {
  delete Object.prototype.leak
}
captured = 'untouched'
Object.defineProperty(Array.prototype, '0', {
  set(value) {
    captured = value
  },
  configurable: true,
})
try {
  const out = addon.napiJsonValue('["secret"]')
  assert.equal(captured, 'secret')
  assert.ok(!Object.hasOwn(out, '0'))
} finally {
  delete Array.prototype[0]
}
