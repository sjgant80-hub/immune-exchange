import { test } from 'node:test';
import assert from 'node:assert/strict';
// Hostile-input (never-throw) battery over the vendored break-it kernels + the exchange kernels. A guard like
// `x && typeof x === 'object' ? x : {}` mutated to `||` stops being total; this is what kills those mutants.
import * as wire from '../src/wire.mjs';
import { decide, isAdmitted } from '../src/gate.mjs';
import * as immune from '../src/immune.mjs';
import * as ab from '../src/antibody.mjs';
import { verifyBundle, bundleMaterial, toHex, fromHex } from '../src/exchange.mjs';

const circular = {}; circular.self = circular;
const toxic = { get stage() { throw new Error('toxic'); }, get length() { throw new Error('toxic'); } };
const HOSTILE = [null, undefined, NaN, Infinity, -1, 0, 1, '', '  ', 'str', true, false, 10n, [], {}, circular, toxic,
  new Uint8Array(0), new Uint8Array(5), new Uint8Array(400), { stage: 'x' }, { reason: 1 }, () => {}];
const neverThrows = (name, fn) => test('total: ' + name + ' never throws on hostile input', () => {
  for (const x of HOSTILE) assert.doesNotThrow(() => fn(x), name + ' threw on ' + String(x));
});

neverThrows('rawCheck', wire.rawCheck);
neverThrows('parse', wire.parse);
neverThrows('encodeUnsigned', wire.encodeUnsigned);
neverThrows('withSignature', (x) => wire.withSignature(x, new Uint8Array(wire.SIG)));
test('total: withSignature returns null (not a throw) on junk, and on a wrong-length signature', () => {
  for (const x of HOSTILE) assert.equal(wire.withSignature(x, new Uint8Array(wire.SIG)), null);
  const u = wire.encodeUnsigned({ sender: 1, counter: 1n, op: wire.OPS.SET, key: 'k', value: 'v' });
  assert.equal(wire.withSignature(u, new Uint8Array(wire.SIG - 1)), null);
});
test('total: decide never throws and never admits junk', () => {
  const ctx = { keyFor: () => new Uint8Array(32), verify: () => true, lastCounter: () => 0n };
  for (const x of HOSTILE) { let r; assert.doesNotThrow(() => { r = decide(x, ctx); }); assert.equal(r.admit, false); }
  assert.equal(isAdmitted(null), false);
});
neverThrows('classify', (x) => immune.classify(x, {}));
neverThrows('classify(facts)', (x) => immune.classify({ stage: 'size' }, x));
neverThrows('fingerprint', (x) => immune.fingerprint('forgery', { bytes: x }));
neverThrows('learn', (x) => immune.learn(x, { family: 'forgery', print: 'p', source: 's' }));
neverThrows('standing', (x) => immune.standing(x, 's'));
neverThrows('immuneStage', ab.immuneStage);
neverThrows('features', (x) => ab.features(x, 'signature'));
neverThrows('distance', (x) => ab.distance(x, x));
neverThrows('mint', (x) => ab.mint(x, { hash: 'a'.repeat(64), stage: 'signature', keyset: 'b'.repeat(64) }));
neverThrows('mint(facts)', (x) => ab.mint(new Uint8Array(83), x));
neverThrows('adopt', (x) => ab.adopt(ab.emptyLibrary(), x));
neverThrows('recognise', (x) => ab.recognise(x, 'a'.repeat(64), null, 'b'.repeat(64)));
neverThrows('verifyBundle', (x) => verifyBundle(x, () => true, () => true));
neverThrows('verifyBundle(isPinned junk)', (x) => verifyBundle({ v: 1, from: 'a'.repeat(64), antigens: ['ab'], sig: '0'.repeat(128) }, x, () => true));
neverThrows('bundleMaterial', (x) => bundleMaterial(x, x));
neverThrows('fromHex', fromHex);
neverThrows('toHex', (x) => toHex(x instanceof Uint8Array ? x : new Uint8Array(0)));
