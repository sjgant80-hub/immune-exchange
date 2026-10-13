#!/usr/bin/env node
// attack-kit/first-publisher.mjs — PROOF: break-it is the exchange's first publisher. Reads a REAL break-it journal
// (test/fixtures/break-it-journal.jsonl, captured from a live break-it node under attack), turns it into a signed
// exchange bundle, and shows a FRESH subscriber gate verify it, re-run every antigen on its own gate, and go immune.
//   node attack-kit/first-publisher.mjs           write receipts/first-publisher.json
//   node attack-kit/first-publisher.mjs --check    regenerate and demand it is byte-identical
// Deterministic (fixed keys + committed fixture) → reproducible. CI runs --check with no break-it checkout needed.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { createHash, verify as edVerify } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { antigensFromJournal } from '../src/publisher.mjs';
import { makeBundle, verifyBundle, toHex, fromHex } from '../src/exchange.mjs';
import { adoptAntigens } from '../src/subscribe.mjs';
import { decide } from '../src/gate.mjs';
import { immuneStage, mint, adopt, recognise, emptyLibrary, PERMANENT } from '../src/antibody.mjs';
import { classify } from '../src/immune.mjs';
import { keyFromSeed, rawPublic, keyTable, signWith, publicFromRaw } from '../src/keys.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'receipts', 'first-publisher.json');
const sha = (u8) => createHash('sha256').update(u8).digest('hex');
const hx = (k) => toHex(rawPublic(k));

// the subscriber's gate pins the SAME legit sender key break-it's node pinned (so a forgery stays a forgery here)
const S1 = keyFromSeed(new Uint8Array(32).fill(1));
const t = keyTable({ 1: hx(S1) });
const BREAKIT_NODE = keyFromSeed(new Uint8Array(32).fill(21));   // break-it's bundle/publisher key
const verify = (msg, sig, fromHex) => { try { return edVerify(null, Buffer.from(msg), publicFromRaw(Buffer.from(fromHex, 'hex')), Buffer.from(sig)) === true; } catch { return false; } };

// 1 · read break-it's real journal and select what to publish
const journal = readFileSync(join(ROOT, 'test', 'fixtures', 'break-it-journal.jsonl'), 'utf8');
const sel = antigensFromJournal(journal);

// 2 · break-it signs and publishes an exchange bundle of those antigens
const bundle = makeBundle(hx(BREAKIT_NODE), sel.antigens, signWith(BREAKIT_NODE));

// 3 · a FRESH subscriber gate verifies the bundle, then re-runs every antigen on its OWN gate
const ctx = { keyFor: t.keyFor, verify: t.verify, lastCounter: () => 0n };
const v = verifyBundle(bundle, (f) => f === hx(BREAKIT_NODE), verify);
let library = emptyLibrary(), adopted = 0, recognisedOnSight = 0;
if (v.ok) {
  const r = adoptAntigens(v.antigens, { ctx, decide, immuneStage, classify, mint, adopt, PERMANENT, keyset: t.keyset, hash: sha, library });
  library = r.library; adopted = r.adopted;
  for (const hex of v.antigens) if (recognise(library, sha(fromHex(hex)), null, t.keyset).drop) recognisedOnSight++;
}

const result = {
  kind: 'immune-exchange-first-publisher', v: 1,
  source: 'a real break-it node journal (test/fixtures/break-it-journal.jsonl)',
  journalRecords: journal.split('\n').filter(Boolean).length,
  selected: sel.selected, skipped: sel.skipped,
  bundleVerified: v.ok, bundleFrom: bundle.from.slice(0, 16),
  adopted, recognisedOnSight,
  held: v.ok && sel.selected > 0 && adopted === sel.selected && recognisedOnSight === sel.selected,
};
const canonical = (x) => x === null || typeof x !== 'object' ? JSON.stringify(x) : Array.isArray(x) ? '[' + x.map(canonical).join(',') + ']' : '{' + Object.keys(x).sort().map((k) => JSON.stringify(k) + ':' + canonical(x[k])).join(',') + '}';
const text = canonical(result) + '\n';
if (process.argv.includes('--check')) {
  const committed = existsSync(OUT) ? readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n') : '';
  if (committed !== text) { console.error('the first-publisher receipt does NOT reproduce'); process.exit(1); }
  console.log('REPRODUCED — break-it published ' + result.selected + ' antigens, the subscriber adopted ' + result.adopted + ', all recognised on sight: ' + result.held);
  process.exit(result.held ? 0 : 1);
}
mkdirSync(dirname(OUT), { recursive: true }); writeFileSync(OUT, text);
console.log('break-it journal → ' + result.journalRecords + ' records, ' + result.selected + ' published');
console.log('subscriber: bundle verified ' + result.bundleVerified + ', adopted ' + result.adopted + '/' + result.selected + ', recognised on sight ' + result.recognisedOnSight);
console.log('\n' + (result.held ? 'break-it is a working publisher — its attacks immunise a gate that never saw them' : 'FAILED') + ' → receipts/first-publisher.json');
process.exit(result.held ? 0 : 1);
