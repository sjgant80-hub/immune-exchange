#!/usr/bin/env node
// tools/publish.mjs — the live publisher: read a break-it node's journal, bundle the publishable antigens, sign
// with this node's key, and POST them to an exchange hub.
//
//   node tools/publish.mjs <break-it-journal.jsonl> <hub-url> [--secret secrets/node.pem]
//
// break-it needs no change — its journal is the feed. This is the adapter that puts break-it on the bus. The key
// lives in secrets/ (git-ignored); it is created on first run. Sovereign: the only network call is to the hub URL
// you pass. Nothing is verified here — the hub stores, subscribers re-run on their own gate.
import { readFileSync } from 'node:fs';
import { antigensFromJournal } from '../src/publisher.mjs';
import { makeBundle, toHex } from '../src/exchange.mjs';
import { loadOrCreate, rawPublic, signWith } from '../src/keys.mjs';

const [journalPath, hubUrl] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
if (!journalPath || !hubUrl) { console.error('usage: node tools/publish.mjs <break-it-journal.jsonl> <hub-url>'); process.exit(2); }

const key = loadOrCreate('secrets', 'publisher');
const from = toHex(rawPublic(key));
const sel = antigensFromJournal(readFileSync(journalPath, 'utf8'));
if (sel.selected === 0) { console.log('nothing to publish — the journal holds no novel, full, permanent-stage attacks'); process.exit(0); }
const bundle = makeBundle(from, sel.antigens, signWith(key));

const r = await fetch(new URL('/publish', hubUrl), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(bundle) });
const body = await r.json().catch(() => ({}));
console.log('published ' + sel.selected + ' antigen(s) from ' + journalPath.split(/[\\/]/).pop() + ' to ' + hubUrl + ' → ' + (body.ok ? 'stored at seq ' + body.seq : 'refused: ' + (body.why || r.status)));
process.exit(body.ok ? 0 : 1);
