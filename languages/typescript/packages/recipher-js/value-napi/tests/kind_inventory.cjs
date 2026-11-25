// Every scalar kind the build can produce, from one Sink::scalar call each,
// converts to its expected JavaScript value, and containers and passthrough
// build through the whole walk. Run by tests/node.rs with the test addon's
// path.
const assert = require('node:assert/strict');
const path = require('node:path');
const addon = require(path.resolve(process.argv[2]));
const { VcDate, VcTimestamp, VcDecimal, VcUuid } = addon;
assert.deepStrictEqual(addon.kindInventory(), {
  null: null,
  undefined: undefined,
  bool: true,
  int8: -128n,
  uint8: 255n,
  int16: -32768n,
  uint16: 65535n,
  int32: -32n,
  uint32: 0xffffffffn,
  int64: -(1n << 63n),
  uint64: (1n << 64n) - 1n,
  int128: -(1n << 127n),
  uint128: (1n << 128n) - 1n,
  float32: 1.5,
  float64: 2.5,
  string: 'hello',
  bytes: Buffer.from([0, 255]),
  date: new VcDate('2024-02-29'),
  timestamp: new Date(0),
  timestampMillis: new Date(-1),
  timestampMicros: new VcTimestamp('1970-01-01T00:00:00.000001000Z'),
  timestampNanos: new VcTimestamp('1969-12-31T23:59:59.999999999Z'),
  decimal: new VcDecimal('1.50'),
  uuid: new VcUuid('123e4567-e89b-12d3-a456-426614174000'),
  array: [true],
  object: { k: true },
  passthrough: true,
});
// A logical type this binding does not know has no JavaScript value and is
// refused, rather than shown as its physical value with the type dropped.
assert.throws(() => addon.decode(addon.unknownLogicalFrame()), /not known to this binding/);
// A known logical type over a value it does not admit is refused too.
for (const c of ['date-over-text', 'date-out-of-range', 'timestamp-out-of-range', 'uuid-short', 'decimal-scale']) {
  assert.throws(() => addon.buildMismatched(c), /not a value this binding can build/, c);
}
console.log('Every scalar kind converts to its expected JavaScript value');
