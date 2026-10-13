import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { adoptAntigens } from '../src/subscribe.mjs';
import { toHex } from '../src/exchange.mjs';
import { decide } from '../src/gate.mjs';
import { immuneStage, mint, adopt, recognise, emptyLibrary, PERMANENT } from '../src/antibody.mjs';
import { classify } from '../src/immune.mjs';
import { keyFromSeed, rawPublic, keyTable, signWith } from '../src/keys.mjs';
import { encodeUnsigned, signedBytes, withSignature, SIG, OPS } from '../src/wire.mjs';

const sha = (u8) => createHash('sha256').update(u8).digest('hex');
const S1 = keyFromSeed(new Uint8Array(32).fill(1)), ATT = keyFromSeed(new Uint8Array(32).fill(0xee));
const t = keyTable({ 1: toHex(rawPublic(S1)) });
const packet = ({ counter = 1n, value = 'x', signer = S1 } = {}) => {
  const u = encodeUnsigned({ sender: 1, counter, op: OPS.SET, key: 'name', value });
  const n = (u[14] << 8) | u[15];
  return withSignature(u, signWith(signer)(signedBytes(new Uint8Array([...u, ...new Uint8Array(SIG)]), n)));
};
const deps = (library) => ({ ctx: { keyFor: t.keyFor, verify: t.verify, lastCounter: () => 0n },
  decide, immuneStage, classify, mint, adopt, PERMANENT, keyset: t.keyset, hash: sha, library });

test('a forgery (permanent refusal here) is adopted as an exact antibody', () => {
  const f = packet({ counter: 7n, signer: ATT });
  const r = adoptAntigens([toHex(f)], deps(emptyLibrary()));
  assert.equal(r.adopted, 1);
  assert.equal(recognise(r.library, sha(f), null, t.keyset).drop, true);
});

test('a packet that ADMITS here is never adopted — negative selection blocks autoimmunity', () => {
  const legit = packet({ counter: 1n });
  const r = adoptAntigens([toHex(legit)], deps(emptyLibrary()));
  assert.equal(r.adopted, 0);
  assert.equal(r.autoimmuneBlocked, 1);
  assert.equal(decide(legit, deps().ctx).admit, true);             // still admits — the gate was not poisoned
});

test('an out-of-order packet (could become valid) earns recognition only, not a permanent antibody', () => {
  const ooo = packet({ counter: 5n });
  const r = adoptAntigens([toHex(ooo)], deps(emptyLibrary()));
  assert.equal(r.adopted, 0);
  assert.equal(r.recognitionOnly, 1);
});

test('adopting the same forgery twice adds the antibody once', () => {
  const f = packet({ counter: 9n, signer: ATT });
  let r = adoptAntigens([toHex(f)], deps(emptyLibrary()));
  assert.equal(r.adopted, 1);
  r = adoptAntigens([toHex(f)], deps(r.library));
  assert.equal(r.adopted, 0);                                       // already covered — minted once
});

test('a mixed bundle tallies each outcome independently', () => {
  const r = adoptAntigens([toHex(packet({ counter: 7n, signer: ATT })), toHex(packet({ counter: 1n })), toHex(packet({ counter: 5n }))], deps(emptyLibrary()));
  assert.equal(r.adopted, 1);            // the forgery
  assert.equal(r.autoimmuneBlocked, 1);  // the valid counter-1 packet
  assert.equal(r.recognitionOnly, 1);    // the out-of-order packet
});

test('adoptAntigens is total on junk antigens (bad hex, wrong type) — no throw, nothing adopted', () => {
  assert.doesNotThrow(() => adoptAntigens(['nothex', '', 'zz', 42, null], deps(emptyLibrary())));
  assert.equal(adoptAntigens(['', 'zzz'], deps(emptyLibrary())).adopted, 0);
  assert.doesNotThrow(() => adoptAntigens(null, deps(emptyLibrary())));
});

test('adoptAntigens is total on bad deps (no throw, nothing adopted)', () => {
  assert.doesNotThrow(() => adoptAntigens([], null));
  assert.doesNotThrow(() => adoptAntigens([], 'nonsense'));
  assert.equal(adoptAntigens([], null).adopted, 0);
});
