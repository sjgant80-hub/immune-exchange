import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verify as edVerify } from 'node:crypto';
import { makeBundle, verifyBundle, bundleMaterial, toHex, fromHex, EXCHANGE_DOMAIN, MAX_ANTIGENS, MAX_ANTIGEN_HEX } from '../src/exchange.mjs';
import { keyFromSeed, rawPublic, signWith, publicFromRaw } from '../src/keys.mjs';

const K = keyFromSeed(new Uint8Array(32).fill(5)), K2 = keyFromSeed(new Uint8Array(32).fill(6));
const pub = toHex(rawPublic(K)), pub2 = toHex(rawPublic(K2));
const verify = (msg, sig, fromHex) => { try { return edVerify(null, Buffer.from(msg), publicFromRaw(Buffer.from(fromHex, 'hex')), Buffer.from(sig)) === true; } catch { return false; } };
const pinned = (f) => f === pub;
const A = ['42524b31aa', 'deadbeef'];

test('toHex/fromHex round-trip (Buffer-free, browser-safe)', () => {
  const u = new Uint8Array([0, 1, 255, 16, 171]);
  assert.equal(toHex(u), '0001ff10ab');
  assert.deepEqual(Array.from(fromHex('0001ff10ab')), [0, 1, 255, 16, 171]);
});

test('a well-formed bundle verifies under its pinned key', () => {
  const b = makeBundle(pub, A, signWith(K));
  assert.equal(b.v, 1); assert.equal(b.from, pub); assert.equal(b.sig.length, 128);
  const r = verifyBundle(b, pinned, verify);
  assert.equal(r.ok, true); assert.deepEqual(r.antigens, A);
});

test('makeBundle drops malformed/oversized antigens before signing, and caps the count', () => {
  const b = makeBundle(pub, ['ab', 'nothex!', 'x'.repeat(MAX_ANTIGEN_HEX + 2), 'cd'], signWith(K));
  assert.deepEqual(b.antigens, ['ab', 'cd']);                       // odd-length / non-hex / oversized dropped
  const many = makeBundle(pub, Array.from({ length: MAX_ANTIGENS + 10 }, () => 'ab'), signWith(K));
  assert.equal(many.antigens.length, MAX_ANTIGENS);
});

test('an unpinned sender is refused before any crypto work', () => {
  const b = makeBundle(pub2, A, signWith(K2));
  assert.equal(verifyBundle(b, pinned, verify).ok, false);
});

test('a tampered signature, swapped antigen list, or lifted from-id all fail', () => {
  const b = makeBundle(pub, A, signWith(K));
  assert.equal(verifyBundle({ ...b, sig: b.sig.slice(0, -2) + (b.sig.endsWith('00') ? '11' : '00') }, pinned, verify).ok, false);
  assert.equal(verifyBundle({ ...b, antigens: ['ab'] }, pinned, verify).ok, false);
  assert.equal(verifyBundle({ ...b, from: pub2 }, (f) => f === pub || f === pub2, verify).ok, false);  // sig binds from
});

test('bundleMaterial binds the domain, the from-id and the exact list', () => {
  assert.ok(bundleMaterial(pub, A).startsWith(EXCHANGE_DOMAIN));
  assert.notEqual(bundleMaterial(pub, A), bundleMaterial(pub2, A));
  assert.notEqual(bundleMaterial(pub, A), bundleMaterial(pub, ['ab']));
});

test('verifyBundle is total: any hostile bundle is a clean refusal, never a throw', () => {
  for (const x of [null, undefined, 42, 'str', [], {}, { v: 2 }, { v: 1, from: 'zz' }, { v: 1, from: pub, antigens: [], sig: 'x' },
    { v: 1, from: pub, antigens: ['nothex'], sig: '00'.repeat(64) }, { v: 1, from: pub, antigens: ['ab'], sig: 'short' }]) {
    assert.doesNotThrow(() => verifyBundle(x, pinned, verify));
    assert.equal(verifyBundle(x, pinned, verify).ok, false);
  }
});

test('verifyBundle refuses an empty or over-long antigen list, and a wrong-length signature', () => {
  const b = makeBundle(pub, A, signWith(K));
  assert.equal(verifyBundle({ ...b, antigens: [] }, pinned, verify).ok, false);
  assert.equal(verifyBundle({ ...b, antigens: Array.from({ length: MAX_ANTIGENS + 1 }, () => 'ab') }, pinned, verify).ok, false);
  assert.equal(verifyBundle({ ...b, sig: 'ab' }, pinned, verify).ok, false);
});

test('verifyBundle fails CLOSED if the injected verify throws', () => {
  const b = makeBundle(pub, A, signWith(K));
  assert.equal(verifyBundle(b, pinned, () => { throw new Error('boom'); }).ok, false);
});

test('each verifyBundle check is reachable on its own (one broken field at a time)', () => {
  const good = makeBundle(pub, A, signWith(K));
  const sig128 = '0'.repeat(128);
  const broken = [
    [{ ...good, v: 2 }, /v1/],
    [{ ...good, from: 123 }, /from is not a string/],
    [{ ...good, from: 'z'.repeat(64) }, /32-byte key/],
    [{ ...good, antigens: 'x' }, /not a list/],
    [{ ...good, antigens: [] }, /empty/],
    [{ ...good, antigens: Array.from({ length: MAX_ANTIGENS + 1 }, () => 'ab') }, /too long/],
    [{ ...good, antigens: [123] }, /not a string/],
    [{ ...good, antigens: ['xy'] }, /not hex/],
    [{ ...good, antigens: ['ab'.repeat(MAX_ANTIGEN_HEX)] }, /too long/],
    [{ ...good, sig: 123 }, /signature is not a string/],
    [{ ...good, sig: 'zz' }, /not hex/],
    [{ ...good, sig: 'ab' }, /not 64 bytes/],
  ];
  for (const [b, re] of broken) { const r = verifyBundle(b, (f) => f === pub, verify); assert.equal(r.ok, false); assert.match(r.reason, re); }
  // and a pinned peer whose key is not 64-hex is still rejected at the HEX64 check, before the pin check
  assert.match(verifyBundle({ ...good, from: 'z'.repeat(64) }, () => true, verify).reason, /32-byte key/);
});

test('verifyBundle accepts the MAX edges and names a null bundle as not-v1 (no deref)', () => {
  const maxCount = makeBundle(pub, Array.from({ length: MAX_ANTIGENS }, () => 'ab'), signWith(K));
  assert.equal(maxCount.antigens.length, MAX_ANTIGENS);
  assert.equal(verifyBundle(maxCount, pinned, verify).ok, true);                 // exactly MAX_ANTIGENS passes
  const maxLen = makeBundle(pub, ['ab'.repeat(MAX_ANTIGEN_HEX / 2)], signWith(K));
  assert.equal(maxLen.antigens[0].length, MAX_ANTIGEN_HEX);
  assert.equal(verifyBundle(maxLen, pinned, verify).ok, true);                   // an antigen of exactly MAX_ANTIGEN_HEX passes
  assert.match(verifyBundle(null, pinned, verify).reason, /v1/);                 // null → {} → 'not a v1 bundle', never deref'd
});
