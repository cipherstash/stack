// Every row of the ADR 0001 section 6 mapping, encrypted and decrypted
// through real AES-256-GCM by the sink-based cipher, with the value walked
// in place on the way in and built by the sink on the way out. Run by
// tests/node.rs with the test addon's path.
const assert = require('node:assert/strict');
const path = require('node:path');
const addon = require(path.resolve(process.argv[2]));
const { VcDate, VcTimestamp, VcDecimal, VcUuid } = addon;
const aad = 'section-6';

const rows = {
  null: null,
  undefined: undefined,
  boolean: true,
  number: 1.5,
  'number (integral)': 42,
  bigint: 42n,
  'bigint (wide)': -(1n << 100n),
  string: 'Ada Lovelace',
  Buffer: Buffer.from([0xde, 0xad, 0xbe, 0xef]),
  Uint8Array: new Uint8Array([1, 2, 3]),
  Date: new Date(1_700_000_000_123),
  'Date (before the epoch)': new Date(-1),
  Array: [1n, 'two', [3.0], { four: null }],
  'plain object': { name: 'Ada', tags: ['math'], born: new VcDate('1815-12-10'), x: undefined },
  'null prototype': Object.assign(Object.create(null), { k: 'v' }),
  VcDate: new VcDate('2024-02-29'),
  VcTimestamp: new VcTimestamp('1969-12-31T23:59:59.999999999Z'),
  VcDecimal: new VcDecimal('-1.50'),
  VcUuid: new VcUuid('123e4567-e89b-12d3-a456-426614174000'),
  'empty array': [],
  'empty object': {},
};
for (const [name, value] of Object.entries(rows)) {
  const ct = addon.encryptValue(value, aad);
  const got = addon.decryptValue(ct, aad);
  const want = name === 'Uint8Array' ? Buffer.from(value) : name === 'null prototype' ? { k: 'v' } : value;
  assert.deepEqual(got, want, name);
  if (name !== 'null' && name !== 'undefined') {
    assert.throws(() => addon.decryptValue(ct, 'other'), /decrypt: cipher failed/, name);
  }
}
// A Date keeps its exact millisecond count: no trip through seconds and
// nanoseconds, and no rounding.
// The last two are the ends of the wire's range, which is jiff's.
for (const ms of [0, -1, 1, 1_700_000_000_123, -62_135_596_800_000, -377_705_023_201_000, 253_402_207_200_999]) {
  const got = addon.decryptValue(addon.encryptValue(new Date(ms), aad), aad);
  assert.ok(got instanceof Date, `${ms}`);
  assert.equal(got.getTime(), ms);
}
// A Date just past either end is refused.
for (const ms of [-377_705_023_201_001, 253_402_207_201_000]) {
  assert.throws(() => addon.encryptValue(new Date(ms), aad), {code: 'ERR_INVALID_TIMESTAMP'}, `${ms}`);
}

// A getter that throws stops the walk and rejects with that same error.
const boom = new RangeError('the getter threw');
assert.throws(() => addon.encryptValue({ get a() { throw boom; } }, aad), (e) => e === boom);
assert.throws(() => addon.encryptValue([{ get a() { throw boom; } }], aad), (e) => e === boom);
// A string with an unpaired surrogate is refused, not sealed mutated.
assert.throws(() => addon.encryptValue('\ud800', aad), /unpaired surrogate/);
assert.throws(() => addon.encryptValue({ s: 'a\udc00b' }, aad), /unpaired surrogate/);
assert.throws(() => addon.encryptValue({ '\ud800': 1 }, aad), /unpaired surrogate/);
// A valid surrogate pair is one character and is kept; only an unpaired
// half is refused. The empty string is the smallest read.
for (const s of ['', '😀', 'a😀', '😀b', '\u{10FFFF}', 'José']) {
  assert.equal(addon.decryptValue(addon.encryptValue(s, aad), aad), s, JSON.stringify(s));
  assert.deepEqual(addon.decryptValue(addon.encryptValue({ [s]: s }, aad), aad), { [s]: s });
}
// A Proxy trap that throws is like a getter that throws: the walk stops and
// encryption rejects with that same error.
const trapError = new RangeError('the trap threw');
for (const handler of [
  { getPrototypeOf() { throw trapError; } },
  { ownKeys() { throw trapError; } },
  { get() { throw trapError; } },
]) {
  const trap = Object.keys(handler)[0];
  assert.throws(() => addon.encryptValue(new Proxy({ a: 1 }, handler), aad), (e) => e === trapError, trap);
}
// A value with no place in the mapping is refused, wherever it sits.
for (const value of [Symbol('s'), () => 1, { f() {} }, [Symbol.iterator]]) {
  assert.throws(() => addon.encryptValue(value, aad), /JS type cannot be encrypted/, String(typeof value));
}

// Nesting past the limit and the forbidden keys are refused on the way in.
const MAX_DEPTH = 128;
const nest = (levels, wrap, leaf) => { let v = leaf; for (let i = 0; i < levels; i++) v = wrap(v); return v; };
for (const wrap of [(v) => [v], (v) => ({ k: v })]) {
  addon.decryptValue(addon.encryptValue(nest(MAX_DEPTH, wrap, 1n), aad), aad);
  assert.throws(() => addon.encryptValue(nest(MAX_DEPTH + 1, wrap, 1n), aad), /nested too deeply/);
}
assert.throws(() => addon.encryptValue(JSON.parse('{"__proto__": 1}'), aad), /not allowed/);
assert.throws(() => addon.encryptValue({ constructor: 1 }, aad), /not allowed/);
assert.throws(() => addon.encryptValue({ prototype: 1 }, aad), /not allowed/);
// And on the way out: a ciphertext map key is attacker-writable. This is
// the ciphertext reader's refusal; the build's own, from a frame, is pinned
// in object-safety.cjs.
{
  const ct = addon.encryptValue({ a: 1n }, aad);
  const v = JSON.parse('{"__proto__": null}');
  v.__proto__ = ct.v.a;
  assert.throws(() => addon.decryptValue({ t: 'map', v }, aad), /not allowed/);
}

// Async encryption snapshots the value on the JavaScript thread and seals
// the frame on a worker: the getter runs before the promise exists, and the
// result decrypts like a synchronous one.
(async () => {
  let reads = 0;
  const value = { get secret() { reads++; return 'hush'; }, n: 7n };
  const promise = addon.encryptValueAsync(value, aad);
  assert.equal(reads, 1, 'the value is walked before encryptValueAsync returns');
  const ct = await promise;
  assert.equal(reads, 1, 'nothing is read on the worker');
  assert.deepEqual(addon.decryptValue(ct, aad), { secret: 'hush', n: 7n });
  // The walk is synchronous, so a getter that throws does so before there
  // is a promise to reject.
  assert.throws(() => addon.encryptValueAsync({ get a() { throw boom; } }, aad), (e) => e === boom);

  // A JavaScript null sealed by the binding decrypts into a Rust Option as
  // None, and so does undefined, which is null under its logical type.
  assert.equal(addon.decryptsAsNone(addon.encryptValue(null, aad), aad), true);
  assert.equal(addon.decryptsAsNone(addon.encryptValue(undefined, aad), aad), true);
  assert.equal(addon.decryptsAsNone(addon.encryptValue('present', aad), aad), false);
  assert.throws(() => addon.decryptsAsNone(addon.encryptValue(7n, aad), aad), /decrypt/);

  console.log(`Encrypt/decrypt: ${Object.keys(rows).length} mapping rows round-tripped`);
})().catch((e) => { console.error(e); process.exit(1); });
