#!/usr/bin/env node
// attack-kit/redteam.mjs — prove the exchange is safe to subscribe to. Two nodes, each with its OWN break-it gate;
// node 0 publishes signed bundles, node 1 subscribes (pins node 0's key) and re-runs every antigen on its own gate.
//   node attack-kit/redteam.mjs           write receipts/redteam.json
//   node attack-kit/redteam.mjs --check   regenerate and demand it is byte-identical
// The win condition is inverted from break-it: here a case HOLDS when a genuine zero-day propagates AND nothing
// valid-here / unsigned / unpinned / tampered / sig-lifted is ever adopted. Deterministic keys → reproducible.
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { createHash, verify as edVerify } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeBundle, verifyBundle, toHex, fromHex } from '../src/exchange.mjs';
import { adoptAntigens } from '../src/subscribe.mjs';
import { decide } from '../src/gate.mjs';
import { immuneStage, mint, adopt, recognise, emptyLibrary, PERMANENT } from '../src/antibody.mjs';
import { classify } from '../src/immune.mjs';
import { keyFromSeed, rawPublic, keyTable, signWith, publicFromRaw } from '../src/keys.mjs';
import { encodeUnsigned, signedBytes, withSignature, SIG, OPS } from '../src/wire.mjs';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'receipts', 'redteam.json');
const sha = (u8) => createHash('sha256').update(u8).digest('hex');
const seed = (b) => keyFromSeed(new Uint8Array(32).fill(b));
const hex = (k) => toHex(rawPublic(k));

// sender keys the GATE pins, and the node (bundle) keys the EXCHANGE pins
const S1 = seed(1), ATTACKER = seed(0xee);
const NODE0 = seed(10), NODE1 = seed(11), STRANGER = seed(0x99);
const pubkeys = { 1: hex(S1) };
const t = keyTable(pubkeys);

// build a real signed packet for sender 1 (optionally with the wrong signer / counter)
function packet({ counter = 1n, op = OPS.SET, key = 'name', value = 'alice', signer = S1 } = {}) {
  const u = encodeUnsigned({ sender: 1, counter, op, key, value });
  const n = (u[14] << 8) | u[15];
  return withSignature(u, signWith(signer)(signedBytes(new Uint8Array([...u, ...new Uint8Array(SIG)]), n)));
}
// a subscriber node: its own gate ctx (pins sender 1) + an antibody library + the exchange peers it pins
function node(pinnedBundleKeysHex) {
  const pinned = new Set(pinnedBundleKeysHex);
  return {
    ctx: { keyFor: t.keyFor, verify: t.verify, lastCounter: () => 0n },   // nothing admitted yet → counter 0
    keyset: t.keyset, library: emptyLibrary(),
    isPinned: (fromHex) => pinned.has(fromHex),
    verify: (msg, sig, fromHex) => { try { return edVerify(null, Buffer.from(msg), publicFromRaw(fromHex_(fromHex)), Buffer.from(sig)) === true; } catch { return false; } },
  };
}
const fromHex_ = (h) => Buffer.from(h, 'hex');

const cases = [];
const add = (name, tried, outcome, ok) => cases.push({ name, tried, outcome, held: ok === true });

// node 1 subscribes to node 0
const n1 = node([hex(NODE0)]);
const publish = (antigensHex, signerKey) => makeBundle(hex(signerKey), antigensHex, signWith(signerKey));
function receive(n, bundle) {
  const v = verifyBundle(bundle, n.isPinned, n.verify);
  if (!v.ok) return { verified: false, reason: v.reason, adopted: 0 };
  const r = adoptAntigens(v.antigens, { ctx: n.ctx, decide, immuneStage, classify, mint, adopt, PERMANENT, keyset: n.keyset, hash: sha, library: n.library });
  n.library = r.library;
  return { verified: true, ...r };
}

// ── 1 · a genuine zero-day propagates ───────────────────────────────────────────────────────────────────────
const forgery = packet({ counter: 7n, value: 'mallory', signer: ATTACKER });   // signature forgery — permanent on n1's gate
const zero = receive(n1, publish([toHex(forgery)], NODE0));
add('a zero-day forgery, published by a pinned peer, is adopted after re-run', 'node 0 refused it, bundles + signs it, node 1 re-runs it on its own gate',
  zero.verified ? 'adopted ' + zero.adopted : 'bundle rejected: ' + zero.reason, zero.verified && zero.adopted === 1);
const seen = recognise(n1.library, sha(forgery), null, n1.keyset);
add('…and node 1 now recognises that attack ON SIGHT', 'the same bytes it had never seen before node 0 shared them',
  seen.drop ? 'recognised (' + seen.family + ')' : 'not recognised', seen.drop === true);

// ── 2 · no false immunity: a packet that is VALID here is never adopted ──────────────────────────────────────
const legit = packet({ counter: 1n, value: 'bob' });                            // valid on n1's gate (sender 1, counter 1)
const auto = receive(n1, publish([toHex(legit)], NODE0));
add('a packet that is VALID on node 1 is NOT adopted (autoimmunity blocked)', 'a pinned peer bundles a packet node 1 would admit',
  auto.verified ? 'adopted ' + auto.adopted + ', blocked ' + auto.autoimmuneBlocked : 'rejected', auto.verified && auto.adopted === 0 && auto.autoimmuneBlocked === 1);
const stillAdmits = decide(legit, n1.ctx).admit;
add('…and that valid packet still ADMITS on node 1 (the library did not poison the gate)', 'decide() the same packet after the bundle',
  stillAdmits ? 'ADMITS' : 'refused', stillAdmits === true);

// ── 3 · the bus itself cannot be abused ──────────────────────────────────────────────────────────────────────
const unpinned = receive(n1, publish([toHex(forgery)], STRANGER));              // signed by a key n1 does not pin
add('a bundle from an UNPINNED peer is refused', 'a stranger key signs a perfectly-formed bundle',
  !unpinned.verified ? 'rejected: ' + unpinned.reason : 'accepted', !unpinned.verified);
const good = publish([toHex(forgery)], NODE0);
const badSig = { ...good, sig: good.sig.slice(0, -2) + (good.sig.endsWith('00') ? '11' : '00') };
add('a bundle with a tampered signature is refused', 'flip the last byte of a valid bundle signature',
  !receive(n1, badSig).verified ? 'rejected' : 'accepted', !receive(n1, badSig).verified);
const otherForgery = packet({ counter: 8n, value: 'evil2', signer: ATTACKER });
const swapped = { ...good, antigens: [toHex(otherForgery)] };                   // sign one list, ship another
add('a bundle whose antigen list was swapped after signing is refused', 'node 0 signs [A], the relay ships [B]',
  !receive(n1, swapped).verified ? 'rejected (sig binds the list)' : 'accepted', !receive(n1, swapped).verified);
const lifted = { ...good, from: hex(NODE1) };                                   // lift node 0's sig onto another pinned id
add('a signature cannot be lifted onto another sender id', 'keep node 0 sig, change from to node 1 (also pinned)',
  !receive(n1, lifted).verified ? 'rejected (sig binds from)' : 'accepted', !receive(n1, lifted).verified);

// ── 4 · an antigen that could later be valid earns recognition, never a permanent antibody ───────────────────
const n2 = node([hex(NODE0)]);
const ooo = packet({ counter: 5n, value: 'future' });                           // out-of-order on a fresh gate (counter 0)
const rec = receive(n2, publish([toHex(ooo)], NODE0));
add('an out-of-order packet earns recognition only, not a permanent antibody', 'a legit-key packet that skips ahead',
  rec.verified ? 'adopted ' + rec.adopted + ', recognition ' + rec.recognitionOnly : 'rejected', rec.verified && rec.adopted === 0 && rec.recognitionOnly === 1);

const held = cases.every((c) => c.held);
const result = { kind: 'immune-exchange-redteam', v: 1, rule: 'a zero-day propagates; nothing valid/unsigned/unpinned/tampered/lifted is ever adopted', cases: cases.length, held, results: cases };
const canonical = (v) => v === null || typeof v !== 'object' ? JSON.stringify(v) : Array.isArray(v) ? '[' + v.map(canonical).join(',') + ']' : '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
const text = canonical(result) + '\n';
if (process.argv.includes('--check')) {
  const committed = existsSync(OUT) ? readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n') : '';
  if (committed !== text) { console.error('the receipt does NOT reproduce'); process.exit(1); }
  console.log('REPRODUCED — ' + result.cases + ' cases, all held: ' + result.held); process.exit(result.held ? 0 : 1);
}
mkdirSync(dirname(OUT), { recursive: true }); writeFileSync(OUT, text);
for (const c of cases) console.log((c.held ? 'HELD  ' : 'BROKE ') + c.name.slice(0, 74).padEnd(76) + ' → ' + c.outcome);
console.log('\n' + (held ? 'the exchange is safe to subscribe to' : 'A PROPERTY BROKE') + ' — ' + cases.length + ' cases → receipts/redteam.json');
process.exit(held ? 0 : 1);
