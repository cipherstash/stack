// Object handling at the N-API boundary: which keys are read, how output
// properties are written, and the ciphertext node projection. Run by
// tests/node.rs with the test addon's path.
const assert = require('node:assert/strict');
const path = require('node:path');
const addon = require(path.resolve(process.argv[2]));

const roundTrip = (value) => addon.decode(addon.encode(value));

// Only own, enumerable, string keys are read.
const mixed = { own: 2 };
Object.defineProperty(mixed, 'hidden', { value: 3, enumerable: false });
mixed[Symbol('s')] = 4;
assert.deepEqual(Object.keys(roundTrip(mixed)), ['own']);
const bare = Object.create(null);
bare.own = 1;
assert.deepEqual(Object.keys(roundTrip(bare)), ['own']);
// An object with any other prototype is refused rather than read.
assert.throws(() => addon.encode(Object.create({ inherited: 1 })));

// A polluted Object.prototype contributes no keys.
Object.prototype.polluted = 'x';
try {
  assert.deepEqual(Object.keys(roundTrip({ a: 1 })), ['a']);
} finally {
  delete Object.prototype.polluted;
}

// An own property explicitly set to undefined round-trips.
const explicit = roundTrip({ x: undefined });
assert.ok(Object.hasOwn(explicit, 'x'));
assert.equal(explicit.x, undefined);

// Keys holding NUL, and numeric keys, keep their exact text.
assert.deepEqual(Object.keys(roundTrip({ 'a\0b': 1, 7: 2 })), ['7', 'a\0b']);

// Output properties are own data properties, defined without running a
// polluted inherited setter.
let captured = 'untouched';
Object.defineProperty(Object.prototype, 'leak', {
  set(v) { captured = v; },
  configurable: true,
});
try {
  const out = roundTrip({ leak: 'secret' });
  assert.equal(captured, 'untouched');
  assert.ok(Object.hasOwn(out, 'leak'));
  assert.equal(out.leak, 'secret');
} finally {
  delete Object.prototype.leak;
}

// Output properties are writable, enumerable and configurable, like ones
// created by assignment.
assert.deepEqual(Object.getOwnPropertyDescriptor(roundTrip({ k: 1 }), 'k'), {
  value: 1, writable: true, enumerable: true, configurable: true,
});

// Prototype-touching keys are refused, walking a value and building one.
assert.throws(() => addon.encode(JSON.parse('{"__proto__": 1}')));
assert.throws(() => addon.encode({ constructor: 1 }));
for (const key of ['__proto__', 'constructor', 'prototype']) {
  // The frame of `{ [key]: 1n }`: a one-entry map whose key is attacker-written.
  const len = Buffer.alloc(4);
  len.writeUInt32LE(key.length);
  const frame = Buffer.concat([Buffer.from('f101000000', 'hex'), len, Buffer.from(key), Buffer.from('0c01', 'hex')]);
  assert.throws(() => addon.decode(frame), /not allowed/, key);
}

// A Proxy reports its target's prototype, so a proxied Map, Date, array or
// class instance is refused like the target would be, rather than read
// through `napi_get_prototype` (which says `null` for every proxy) as a
// null-prototype object.
assert.throws(() => addon.encode(new Proxy(new Map([['k', 'secret']]), {})));
assert.throws(() => addon.encode(new Proxy(new Date(5), {})));
assert.throws(() => addon.encode(new Proxy([1, 2], {})));
assert.throws(() => addon.encode(new Proxy(new (class { #x = 1 })(), {})));
assert.deepEqual(roundTrip(new Proxy({ a: 1 }, {})), { a: 1 });

// Only a Buffer or a Uint8Array is bytes. Every other view would seal as
// its raw bytes and come back as a Buffer, so it is refused.
assert.deepEqual(roundTrip(new Uint8Array([1, 2, 3])), Buffer.from([1, 2, 3]));
assert.deepEqual(roundTrip(new Uint8Array(new Uint8Array([9, 1, 2]).buffer, 1)), Buffer.from([1, 2]));
for (const view of [
  new Float64Array([1.5]), new Int16Array([-1]), new BigInt64Array([1n]),
  new Uint8ClampedArray([1]), new DataView(new ArrayBuffer(2)),
]) {
  assert.throws(() => addon.encode(view), /only a Buffer or a Uint8Array/, view.constructor.name);
}

// The binding keeps the wrapper classes in its own registry, so an addon
// that uses the environment's instance data for itself loses nothing.
addon.claimInstanceData();
assert.equal(roundTrip(new addon.VcDecimal('2.50')).value, '2.50');
assert.deepEqual(roundTrip({ k: 'v' }), { k: 'v' });

// A wrapper instance is built by its constructor, so it is a real instance.
const date = roundTrip(new addon.VcDate('2026-10-09'));
assert.ok(date instanceof addon.VcDate);
assert.equal(date.value, '2026-10-09');
// The classes, their prototypes and their instances are frozen, and the
// constructor uses what it captured when the classes were defined, so
// neither prototype pollution nor a later edit of a class can make
// `value` writable, break construction, hide extra state in an instance,
// or turn a plain `{ value }` object back into a wrapper.
assert.ok(Object.isFrozen(addon.VcUuid) && Object.isFrozen(addon.VcUuid.prototype) && Object.isFrozen(date));
Object.prototype.writable = true;
Object.prototype.get = () => 'polluted';
try {
  const decimal = new addon.VcDecimal('1.50');
  assert.throws(() => { 'use strict'; decimal.value = '999.99'; }, TypeError);
  assert.equal(decimal.value, '1.50');
  assert.equal(roundTrip(decimal).value, '1.50');
} finally {
  delete Object.prototype.writable;
  delete Object.prototype.get;
}
assert.throws(() => Object.defineProperty(addon.VcUuid, Symbol.hasInstance, { value: () => true }), TypeError);
assert.deepEqual(roundTrip({ value: '123e4567-e89b-12d3-a456-426614174000' }), { value: '123e4567-e89b-12d3-a456-426614174000' });
assert.throws(() => { 'use strict'; date.extra = 'secret'; }, TypeError);
assert.equal('extra' in date, false);

// The ciphertext node projection survives a trip through Rust.
const leaf = Buffer.from('a1b2', 'hex');
const ct = {
  t: 'map',
  v: {
    a: { t: 'ct', v: leaf },
    'k\0': { t: 'seq', v: [{ t: 'eseq', v: leaf }, { t: 'pt', v: 5n }, { t: 'pt', v: { a: [new addon.VcDecimal('1.50')] } }] },
    e: { t: 'eseq', v: leaf },
    m: { t: 'emap', v: leaf },
    u: { t: 'pt', v: undefined },
  },
};
assert.deepEqual(addon.ciphertextRoundTrip(ct), ct);
// The retired absent marker is no node kind: a `None` is a sealed null leaf.
assert.throws(() => addon.ciphertextRoundTrip({ t: 'none', v: leaf }), /malformed ciphertext/);

// A ciphertext map reads own keys only and writes own properties.
const map = Object.create({ inherited: { t: 'ct', v: leaf } });
map.own = { t: 'ct', v: leaf };
map[Symbol('s')] = { t: 'ct', v: leaf };
Object.defineProperty(Object.prototype, 'own', {
  set(v) { captured = v; },
  configurable: true,
});
try {
  const out = addon.ciphertextRoundTrip({ t: 'map', v: map });
  assert.equal(captured, 'untouched');
  assert.deepEqual(Object.keys(out.v), ['own']);
} finally {
  delete Object.prototype.own;
}
{
  const v = JSON.parse('{"__proto__": {"t": "ct"}}');
  v.__proto__.v = leaf;
  assert.throws(() => addon.ciphertextRoundTrip({ t: 'map', v }), /not allowed/);
}

// Nesting is limited to 128 levels below the root, converting JS to Rust
// and reading a ciphertext tree.
const MAX_DEPTH = 128;
const nest = (levels, wrap, leaf) => {
  let v = leaf;
  for (let i = 0; i < levels; i++) v = wrap(v);
  return v;
};
for (const wrap of [(v) => [v], (v) => ({ k: v })]) {
  addon.convert(nest(MAX_DEPTH, wrap, 1));
  assert.throws(() => addon.convert(nest(MAX_DEPTH + 1, wrap, 1)), /nested too deeply/);
}
for (const wrap of [(v) => ({ t: 'seq', v: [v] }), (v) => ({ t: 'map', v: { k: v } })]) {
  const deepest = nest(MAX_DEPTH, wrap, { t: 'ct', v: leaf });
  assert.deepEqual(addon.ciphertextRoundTrip(deepest), deepest);
  // Reading alone, so the output limit cannot be what refuses it.
  assert.throws(
    () => addon.readCiphertext(nest(MAX_DEPTH + 1, wrap, { t: 'ct', v: leaf })),
    /nested too deeply/,
  );
}

// A leap second has no count since the epoch, so it is refused rather than
// shown as a Date (ADR 0001 section 3).
assert.throws(() => addon.encode(new addon.VcTimestamp('2016-12-31T23:59:60Z')), { code: 'ERR_INVALID_TIMESTAMP' });

// A passthrough value decodes to its plain JS value, at the root and nested.
assert.equal(addon.decode(Buffer.from('f203', 'hex')), true);
assert.deepEqual(addon.decode(Buffer.from('f0010000' + '00f20a0100000061', 'hex')), ['a']);

// Building JS from Rust is limited to the same depth. A frame cannot nest
// past it, so a tree that deep fails when it is framed, before any JS is built.
for (const wrap of ['array', 'object', 'passthrough']) {
  addon.nestedValue(MAX_DEPTH, wrap);
  assert.throws(() => addon.nestedValue(MAX_DEPTH + 1, wrap), /nests deeper than 128 levels/, wrap);
}
assert.equal(nest(MAX_DEPTH, (v) => v[0], addon.nestedValue(MAX_DEPTH, 'array')), true);
for (const wrap of ['seq', 'map']) {
  addon.nestedCiphertext(MAX_DEPTH, wrap);
  assert.throws(() => addon.nestedCiphertext(MAX_DEPTH + 1, wrap), /nested too deeply/, wrap);
}

// Array elements are own properties too: a polluted index setter on
// Array.prototype sees nothing, and the result has no hole.
for (const make of [
  () => addon.decode(addon.encode(['secret'])),
  () => addon.ciphertextRoundTrip({ t: 'seq', v: [{ t: 'ct', v: leaf }] }).v,
]) {
  let stolen = 'untouched';
  Object.defineProperty(Array.prototype, '0', {
    set(v) { stolen = v; },
    configurable: true,
  });
  try {
    const out = make();
    assert.equal(stolen, 'untouched');
    assert.ok(Object.hasOwn(out, 0));
  } finally {
    delete Array.prototype[0];
  }
}

// So are a ciphertext node's `t` and `v`.
for (const key of ['t', 'v']) {
  let stolen = 'untouched';
  Object.defineProperty(Object.prototype, key, {
    set(v) { stolen = v; },
    configurable: true,
  });
  try {
    const out = addon.ciphertextRoundTrip({ t: 'ct', v: leaf });
    assert.equal(stolen, 'untouched');
    assert.deepEqual(Object.keys(out), ['t', 'v']);
  } finally {
    delete Object.prototype[key];
  }
}

// A key holding an unpaired surrogate is refused, not sealed under U+FFFD
// with its value lost.
assert.throws(() => addon.encode({ '\uD800': 'secret' }), /unpaired surrogate/);
assert.throws(
  () => addon.ciphertextRoundTrip({ t: 'map', v: { '\uDC00': { t: 'ct', v: leaf } } }),
  /unpaired surrogate/,
);

// A ciphertext node must be an object. N-API would otherwise read `t` and
// `v` of a primitive from its (here polluted) prototype.
String.prototype.t = 'pt';
Number.prototype.t = 'pt';
try {
  assert.throws(() => addon.ciphertextRoundTrip('abc'), /malformed ciphertext/);
  assert.throws(() => addon.ciphertextRoundTrip({ t: 'map', v: { k: 5 } }), /malformed ciphertext/);
  assert.throws(() => addon.ciphertextRoundTrip({ t: 'map', v: 'abc' }), /malformed ciphertext/);
} finally {
  delete String.prototype.t;
  delete Number.prototype.t;
}

// A node's `t` and `v` must be its own: a polluted prototype cannot supply
// either. An own `v: undefined` is still accepted (see `u` above).
for (const [key, value] of [['t', 'pt'], ['v', leaf]]) {
  Object.prototype[key] = value;
  try {
    assert.throws(() => addon.readCiphertext(key === 't' ? { v: leaf } : { t: 'ct' }), /malformed ciphertext/);
  } finally {
    delete Object.prototype[key];
  }
}

// A passthrough of undefined loses its `v` key through JSON, so a missing
// `v` reads as undefined there, and never from the prototype.
Object.prototype.v = 'injected';
try {
  const out = addon.ciphertextRoundTrip(JSON.parse(JSON.stringify({ t: 'pt', v: undefined })));
  assert.ok(Object.hasOwn(out, 'v'));
  assert.equal(out.v, undefined);
} finally {
  delete Object.prototype.v;
}

// Ownership is checked right before each read, so a getter that deletes a
// later property cannot make that read fall through to the prototype.
Object.prototype.b = 'injected';
Object.prototype.v = leaf;
try {
  assert.throws(
    () => addon.encode({ get a() { delete this.b; return 1; }, b: 2 }),
    /removed while it was being read/,
  );
  assert.throws(
    () => addon.readCiphertext({ get t() { delete this.v; return 'ct'; }, v: leaf }),
    /malformed ciphertext/,
  );
  assert.throws(
    () => addon.readCiphertext({
      t: 'map',
      v: { get a() { delete this.b; return { t: 'ct', v: leaf }; }, b: { t: 'ct', v: leaf } },
    }),
    /removed while it was being read/,
  );
} finally {
  delete Object.prototype.b;
  delete Object.prototype.v;
}
Object.prototype.t = 'pt';
Object.prototype.v = 'injected';
try {
  assert.throws(() => addon.readCiphertext({}), /malformed ciphertext/);
} finally {
  delete Object.prototype.t;
  delete Object.prototype.v;
}

// Sequence elements must be own: a hole cannot be filled by a node on a
// polluted Array.prototype.
Array.prototype[0] = { t: 'ct', v: leaf };
try {
  assert.throws(() => addon.readCiphertext({ t: 'seq', v: new Array(1) }), /malformed ciphertext/);
} finally {
  delete Array.prototype[0];
}

// A passthrough payload continues the tree's depth count, in both
// directions, as it does in the transport encoding: 60 sequences, the
// passthrough node, then 67 arrays reach exactly 128.
addon.ciphertextWithPayload(60, 67);
assert.throws(() => addon.ciphertextWithPayload(60, 68), /nested too deeply/);
const payloadTree = (arrays) =>
  nest(60, (v) => ({ t: 'seq', v: [v] }), { t: 'pt', v: nest(arrays, (v) => [v], true) });
addon.readCiphertext(payloadTree(67));
assert.throws(() => addon.readCiphertext(payloadTree(68)), /nested too deeply/);

// With no passthrough payload type, a passthrough node must carry undefined.
addon.readUnitCiphertext({ t: 'pt', v: undefined });
assert.throws(() => addon.readUnitCiphertext({ t: 'pt', v: 1 }), /malformed ciphertext/);

// A `()` payload counts like any other: it sits one level below its
// passthrough node, so 127 sequences are the most it allows.
addon.unitCiphertext(127);
assert.throws(() => addon.unitCiphertext(128), /nested too deeply/);
addon.readUnitCiphertext(nest(127, (v) => ({ t: 'seq', v: [v] }), { t: 'pt' }));
assert.throws(
  () => addon.readUnitCiphertext(nest(128, (v) => ({ t: 'seq', v: [v] }), { t: 'pt' })),
  /nested too deeply/,
);

// A Rust-built tree far too deep for the stack is refused cleanly: it is
// measured and then dropped without recursing once per level, so neither
// step can overflow the stack and abort Node.
const HUGE = 1_000_000;
for (const wrap of ['array', 'object', 'passthrough']) {
  assert.throws(() => addon.nestedValue(HUGE, wrap), /nests deeper than 128 levels/, wrap);
}
for (const wrap of ['seq', 'map']) {
  assert.throws(() => addon.nestedCiphertext(HUGE, wrap), /nested too deeply/, wrap);
}
assert.throws(() => addon.ciphertextWithPayload(60, HUGE), /nested too deeply/);

// A Worker that loads the addon and uses the wrapper classes tears its
// environment down through the registry's cleanup hook; the process must
// outlive it, and the main environment's classes are untouched.
(async () => {
  const { Worker } = require('node:worker_threads');
  const script = `
    const addon = require(${JSON.stringify(path.resolve(process.argv[2]))});
    const date = addon.decode(addon.encode(new addon.VcDate('2024-02-29')));
    require('node:worker_threads').parentPort.postMessage(date instanceof addon.VcDate ? date.value : 'not a wrapper');
  `;
  const reply = await new Promise((resolve, reject) => {
    const worker = new Worker(script, { eval: true });
    worker.on('message', resolve);
    worker.on('error', reject);
    worker.on('exit', (code) => code === 0 || reject(new Error(`worker exited with ${code}`)));
  });
  assert.equal(reply, '2024-02-29');
  assert.equal(roundTrip(new addon.VcDate('2024-02-29')).value, '2024-02-29');

  // A value the binding refuses is not kept alive by the refusal: once
  // nothing in JavaScript holds it, a collection frees it.
  require('node:v8').setFlagsFromString('--expose-gc');
  const gc = require('node:vm').runInNewContext('gc');
  const refused = (() => {
    const views = [new Float64Array([1.5]), new Int16Array([-1]), new Uint8ClampedArray([1])];
    for (const view of views) {
      assert.throws(() => addon.encode(view), /only a Buffer or a Uint8Array/, view.constructor.name);
    }
    const leaf = { not: 'bytes' };
    assert.throws(() => addon.ciphertextRoundTrip({ t: 'ct', v: leaf }));
    return [...views, leaf].map((value) => new WeakRef(value));
  })();
  // A WeakRef keeps its target alive until the current job ends.
  await new Promise(setImmediate);
  gc();
  for (const [i, ref] of refused.entries()) {
    assert.equal(ref.deref(), undefined, `refused value ${i} is still alive`);
  }
})().catch((e) => { console.error(e); process.exit(1); });
