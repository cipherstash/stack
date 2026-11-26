// The transport frame this bridge writes for every kind of JavaScript value
// it accepts, held to testdata/js-frames.json byte for byte. Where a value
// is one the engine's conformance corpus also spells, the file records
// whether the bridge's frame is the corpus's frozen frame, and the check
// fails if that changes either way: a JavaScript `Date` (milliseconds in the
// 0xF3 envelope) and a `bigint` (the narrowest width that holds it) are
// written differently from the corpus's typed hosts, and that difference is
// pinned here, not hidden. Run by tests/node.rs with the test addon's path.
//
// Regenerate with RECIPHER_UPDATE_FIXTURES=1; never edit the file by hand.
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const addon = require(path.resolve(process.argv[2]))
const { VcDate, VcTimestamp, VcDecimal, VcUuid } = addon

const golden = path.join(__dirname, 'testdata/js-frames.json')
const corpusDir = path.join(__dirname, '../../../../../../conformance/stack-encrypt/v1')

// Every frame the corpus froze, by case id: the value-kinds profile's
// `frame`, and the scalar profile's frames from its Rust artifacts.
const corpus = new Map()
const values = JSON.parse(fs.readFileSync(path.join(corpusDir, 'record-values-v1.cases.json')))
for (const c of values.cases) if (c.frame) corpus.set(`record-values-v1/${c.id}`, c.frame)
const scalars = JSON.parse(
  fs.readFileSync(path.join(corpusDir, 'record-scalars-v1.expected.rust-native.json')),
)
for (const [id, artifact] of Object.entries(scalars.cases)) corpus.set(`record-scalars-v1/${id}`, artifact.frame)

// [name, the value, the corpus case that spells the same value, if any].
const inputs = [
  ['null', () => null],
  ['undefined', () => undefined],
  ['true', () => true, 'record-values-v1/bool-true'],
  ['false', () => false, 'record-values-v1/bool-false'],
  ['number 0', () => 0],
  ['number 34', () => 34],
  ['number -0', () => -0, 'record-values-v1/f64-negative-zero'],
  ['number 1.5', () => 1.5, 'record-values-v1/float32-given-float64'],
  ['number float32 max', () => 3.4028234663852886e38, 'record-values-v1/f32-max'],
  ['number MAX_VALUE', () => Number.MAX_VALUE, 'record-values-v1/f64-max'],
  ['number 5e-324', () => 5e-324, 'record-values-v1/f64-min-positive'],
  ['number Infinity', () => Infinity, 'record-values-v1/f64-inf'],
  ['number -Infinity', () => -Infinity, 'record-values-v1/f64-neg-inf'],
  ['number NaN', () => NaN],
  ['number 2^53 + 2', () => 2 ** 53 + 2],
  ['bigint 0 as uint8', () => 0n, 'record-values-v1/u8-zero'],
  ['bigint 0 as uint16', () => 0n, 'record-values-v1/u16-zero'],
  ['bigint 0 as uint32', () => 0n, 'record-values-v1/u32-zero'],
  ['bigint 0 as uint128', () => 0n, 'record-values-v1/u128-zero'],
  ['bigint 1 as int64', () => 1n, 'record-values-v1/int128-given-int64'],
  ['bigint 34', () => 34n],
  ['bigint -128', () => -128n, 'record-values-v1/i8-min'],
  ['bigint 127', () => 127n, 'record-values-v1/i8-max'],
  ['bigint 128', () => 128n],
  ['bigint 255', () => 255n, 'record-values-v1/u8-max'],
  ['bigint -129', () => -129n],
  ['bigint 256', () => 256n],
  ['bigint -32768', () => -32768n, 'record-values-v1/i16-min'],
  ['bigint 32767', () => 32767n, 'record-values-v1/i16-max'],
  ['bigint 32768', () => 32768n],
  ['bigint 65535', () => 65535n, 'record-values-v1/u16-max'],
  ['bigint -32769', () => -32769n],
  ['bigint 65536', () => 65536n],
  ['bigint -2^31', () => -(2n ** 31n), 'record-scalars-v1/i32-min'],
  ['bigint 2^31 - 1', () => 2n ** 31n - 1n, 'record-scalars-v1/i32-max'],
  ['bigint 2^32 - 1', () => 2n ** 32n - 1n, 'record-values-v1/u32-max'],
  ['bigint 2^32', () => 2n ** 32n],
  ['bigint -2^31 - 1', () => -(2n ** 31n) - 1n],
  ['bigint -2^63', () => -(2n ** 63n), 'record-scalars-v1/i64-min'],
  ['bigint 2^63 - 1', () => 2n ** 63n - 1n, 'record-scalars-v1/i64-max'],
  ['bigint 2^53 + 1', () => 2n ** 53n + 1n, 'record-scalars-v1/above-js-safe-integer'],
  ['bigint 2^63', () => 2n ** 63n, 'record-values-v1/i128-above-i64'],
  ['bigint 2^64 - 1', () => 2n ** 64n - 1n, 'record-scalars-v1/u64-max'],
  ['bigint -2^63 - 1', () => -(2n ** 63n) - 1n, 'record-values-v1/i128-below-i64'],
  ['bigint 2^64', () => 2n ** 64n, 'record-values-v1/u128-above-u64'],
  ['bigint 2^127 - 1', () => 2n ** 127n - 1n, 'record-values-v1/i128-max'],
  ['bigint -2^127', () => -(2n ** 127n), 'record-values-v1/i128-min'],
  ['bigint 2^128 - 1', () => 2n ** 128n - 1n, 'record-values-v1/u128-max'],
  ['string empty', () => '', 'record-scalars-v1/text-empty'],
  ['string unicode', () => 'café 東京 🔐', 'record-scalars-v1/text-unicode'],
  ['string with NUL', () => 'a\0b', 'record-values-v1/string-nul'],
  ['Buffer empty', () => Buffer.alloc(0), 'record-values-v1/bytes-empty'],
  ['Buffer 00ff10', () => Buffer.from('00ff10', 'hex'), 'record-values-v1/bytes-binary'],
  ['Uint8Array 00ff10', () => new Uint8Array([0, 255, 16]), 'record-values-v1/bytes-binary'],
  ['Date 0', () => new Date(0), 'record-values-v1/timestamp-epoch'],
  ['Date 123', () => new Date(123)],
  ['Date -1', () => new Date(-1)],
  ['VcDate 1970-01-01', () => new VcDate('1970-01-01'), 'record-values-v1/date-epoch'],
  ['VcDate 1969-12-31', () => new VcDate('1969-12-31'), 'record-values-v1/date-before-epoch'],
  ['VcDate 0001-01-01', () => new VcDate('0001-01-01'), 'record-values-v1/date-year-one'],
  ['VcDate 9999-12-31', () => new VcDate('9999-12-31'), 'record-values-v1/date-year-9999'],
  ['VcTimestamp epoch', () => new VcTimestamp('1970-01-01T00:00:00Z'), 'record-values-v1/timestamp-epoch'],
  [
    'VcTimestamp one nanosecond',
    () => new VcTimestamp('2026-10-17T01:02:03.000000001Z'),
    'record-values-v1/timestamp-nanosecond',
  ],
  [
    'VcTimestamp before epoch',
    () => new VcTimestamp('1969-12-31T23:59:59.999999999Z'),
    'record-values-v1/timestamp-before-epoch',
  ],
  [
    'VcTimestamp nanoseconds',
    () => new VcTimestamp('2026-10-17T01:02:03.123456789Z'),
    'record-values-v1/timestamp-microsecond-query',
  ],
  [
    'VcTimestamp year 9999',
    () => new VcTimestamp('9999-12-30T22:00:00.999999999Z'),
    'record-values-v1/timestamp-year-9999',
  ],
  ['VcDecimal 42', () => new VcDecimal('42'), 'record-values-v1/decimal-scale-0'],
  [
    'VcDecimal scale 28',
    () => new VcDecimal('0.0000000000000000000000000001'),
    'record-values-v1/decimal-scale-28',
  ],
  ['VcDecimal -1234.5600', () => new VcDecimal('-1234.5600'), 'record-values-v1/decimal-trailing-zeros'],
  [
    'VcDecimal max mantissa',
    () => new VcDecimal('79228162514264337593543950335'),
    'record-values-v1/decimal-max-mantissa',
  ],
  ['VcDecimal -0.00', () => new VcDecimal('-0.00')],
  ['VcUuid', () => new VcUuid('123e4567-e89b-12d3-a456-426614174000')],
  ['array empty', () => []],
  ['array of bigint and string', () => [1n, 'x']],
  ['array of null', () => [null]],
  ['array of undefined', () => [undefined]],
  ['object empty', () => ({})],
  ['object of two keys', () => ({ b: 1n, a: 'x' })],
  ['object nested', () => ({ list: [1n], map: {}, at: new Date(0) })],
]

const actual = {}
for (const [name, make, corpusCase] of inputs) {
  assert.ok(!(name in actual), `${name}: named twice`)
  const frame = addon.encode(make()).toString('hex')
  const entry = { frame }
  if (corpusCase) {
    assert.ok(corpus.has(corpusCase), `${name}: no corpus case ${corpusCase}`)
    entry.corpus_case = corpusCase
    entry.same_as_corpus = frame === corpus.get(corpusCase)
  }
  actual[name] = entry
}

if (process.env.RECIPHER_UPDATE_FIXTURES) {
  const document = {
    _comment:
      'The transport frame recipher-value-napi writes for each JavaScript value, read by tests/frames.cjs. Where a corpus case spells the same value, same_as_corpus records whether the frames are equal. Regenerate with RECIPHER_UPDATE_FIXTURES=1; never edit by hand.',
    frames: actual,
  }
  fs.writeFileSync(golden, `${JSON.stringify(document, null, 2)}\n`)
} else {
  const pinned = JSON.parse(fs.readFileSync(golden)).frames
  assert.deepStrictEqual(Object.keys(actual).sort(), Object.keys(pinned).sort(), 'the same inputs')
  for (const [name, entry] of Object.entries(actual)) {
    assert.deepStrictEqual(entry, pinned[name], name)
  }
}
const differing = Object.values(actual).filter((entry) => entry.same_as_corpus === false).length
console.log(`Bridge frames: ${inputs.length} values pinned, ${differing} differ from the corpus`)
