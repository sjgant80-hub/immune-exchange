#!/usr/bin/env node
// run.mjs — stand up a mesh of gates on the immune exchange and watch a zero-day immunise all of them.
//
//   node run.mjs [--nodes 3]
//
// Each node has its OWN break-it gate (the same verify-before-parse kernel), its own antibody library, and pins
// the other nodes' bundle keys. Node 0 is hit by a forgery its gate refuses; it bundles the attack, signs it, and
// publishes. Every other node VERIFIES the bundle (pinned peer + signature) then RE-RUNS the attack on its own
// gate before adopting — so it goes immune to an attack it never saw, and a valid packet or a tampered bundle is
// never adopted. In-process (one relay, no network) so the whole story prints in one run. Sovereign: no cloud.
import { makeBundle, verifyBundle, toHex } from './src/exchange.mjs';
import { adoptAntigens } from './src/subscribe.mjs';
import { decide } from './src/gate.mjs';
import { immuneStage, mint, adopt, recognise, emptyLibrary, PERMANENT } from './src/antibody.mjs';
import { classify } from './src/immune.mjs';
import { keyFromSeed, rawPublic, keyTable, signWith, publicFromRaw } from './src/keys.mjs';
import { encodeUnsigned, signedBytes, withSignature, SIG, OPS } from './src/wire.mjs';
import { createHash, verify as edVerify } from 'node:crypto';

const arg = (k, d) => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : d; };
const N = Math.max(2, Math.min(9, Number(arg('--nodes', '3')) || 3));
const sha = (u8) => createHash('sha256').update(u8).digest('hex');

// one pinned sender key for every node's gate (the legit client), plus a bundle key per node for the exchange
const S1 = keyFromSeed(new Uint8Array(32).fill(1)), ATTACKER = keyFromSeed(new Uint8Array(32).fill(0xee));
const t = keyTable({ 1: toHex(rawPublic(S1)) });
const nodeKeys = Array.from({ length: N }, (_, i) => keyFromSeed(new Uint8Array(32).fill(40 + i)));
const nodePub = nodeKeys.map((k) => toHex(rawPublic(k)));
const verify = (msg, sig, fromHex) => { try { return edVerify(null, Buffer.from(msg), publicFromRaw(Buffer.from(fromHex, 'hex')), Buffer.from(sig)) === true; } catch { return false; } };

const nodes = nodeKeys.map((k, i) => ({
  i, sign: signWith(k),
  ctx: { keyFor: t.keyFor, verify: t.verify, lastCounter: () => 0n },
  library: emptyLibrary(),
  pins: new Set(nodePub.filter((_, j) => j !== i)),        // pin every OTHER node's bundle key
}));
const packet = ({ counter = 1n, value = 'x', signer = S1 }) => {
  const u = encodeUnsigned({ sender: 1, counter, op: OPS.SET, key: 'name', value });
  const n = (u[14] << 8) | u[15];
  return withSignature(u, signWith(signer)(signedBytes(new Uint8Array([...u, ...new Uint8Array(SIG)]), n)));
};
const receive = (node, bundle) => {
  const v = verifyBundle(bundle, (f) => node.pins.has(f), verify);
  if (!v.ok) return { verified: false, reason: v.reason };
  const r = adoptAntigens(v.antigens, { ctx: node.ctx, decide, immuneStage, classify, mint, adopt, PERMANENT, keyset: t.keyset, hash: sha, library: node.library });
  node.library = r.library; return { verified: true, ...r };
};
const knows = (node, bytes) => recognise(node.library, sha(bytes), null, t.keyset).drop;

console.log(`\nIMMUNE EXCHANGE — ${N} gates on one bus\n`);
const forgery = packet({ counter: 7n, value: 'mallory', signer: ATTACKER });   // a zero-day: forged, no node has seen it
console.log('A zero-day forgery arrives at node 0. Who already knows it?');
for (const n of nodes) console.log(`  node ${n.i}: ${knows(n, forgery) ? 'immune' : 'never seen it'}`);

const refused = decide(forgery, nodes[0].ctx);
console.log(`\nnode 0's gate refuses it at "${refused.stage}". node 0 bundles + signs the attack and publishes it.`);
const bundle = makeBundle(nodePub[0], [toHex(forgery)], nodes[0].sign);

console.log('\nthe relay fans the signed bundle to every peer; each re-runs it on its OWN gate:');
for (const n of nodes.slice(1)) { const r = receive(n, bundle); console.log(`  node ${n.i}: verified ${r.verified}, adopted ${r.adopted || 0}`); }

console.log('\nnow who knows the zero-day?');
for (const n of nodes) console.log(`  node ${n.i}: ${knows(n, forgery) ? 'IMMUNE — recognises it on sight' : 'never seen it'}`);

// and the two things the bus must never do
const legit = packet({ counter: 1n, value: 'alice' });
const autoB = receive(nodes[1], makeBundle(nodePub[0], [toHex(legit)], nodes[0].sign));
console.log(`\na peer tries to share a packet that is VALID on node 1: adopted ${autoB.adopted} (autoimmunity blocked ${autoB.autoimmuneBlocked}) — the gate is not poisoned.`);
const tampered = { ...makeBundle(nodePub[0], [toHex(forgery)], nodes[0].sign), from: nodePub[1] };
console.log(`a signature lifted onto another sender id: verified ${receive(nodes[2], tampered).verified} — rejected.`);
console.log('\nproof: node attack-kit/redteam.mjs --check\n');
