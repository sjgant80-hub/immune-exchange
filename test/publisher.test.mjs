import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { antigensFromJournal, PUBLISHABLE } from '../src/publisher.mjs';
import { MAX_ANTIGENS, MAX_ANTIGEN_HEX } from '../src/exchange.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const rec = (o) => JSON.stringify({ seq: 0, at: 't', stage: 'signature', novel: true, detail: 'full', bytes: '42524b31aa', ...o });

test('the real break-it fixture yields exactly its 3 novel permanent-stage antigens', () => {
  const j = readFileSync(join(HERE, 'fixtures', 'break-it-journal.jsonl'), 'utf8');
  const r = antigensFromJournal(j);
  assert.equal(r.selected, 3);
  assert.equal(r.antigens.length, 3);
  assert.ok(r.antigens.every((a) => /^(?:[0-9a-f]{2})+$/.test(a)));
});

test('only NOVEL records are published', () => {
  assert.equal(antigensFromJournal(rec({ novel: false })).selected, 0);
  assert.equal(antigensFromJournal(rec({ novel: true })).selected, 1);
});

test('only FULL records with bytes are published (a count-only record is skipped)', () => {
  assert.equal(antigensFromJournal(rec({ detail: 'count', bytes: '' })).selected, 0);
  assert.equal(antigensFromJournal(rec({ bytes: '' })).selected, 0);
  assert.equal(antigensFromJournal(rec({ bytes: 'nothex' })).selected, 0);
});

test('only PERMANENT-on-any-gate stages are published (counter/http/flood/behavior are not)', () => {
  for (const s of PUBLISHABLE) assert.equal(antigensFromJournal(rec({ stage: s })).selected, 1, s);
  for (const s of ['counter', 'http', 'flood', 'behavior', 'recognised', 'breach']) assert.equal(antigensFromJournal(rec({ stage: s })).selected, 0, s);
});

test('duplicate bytes publish once; an oversized antigen is skipped', () => {
  const two = rec({ bytes: 'aabb' }) + '\n' + rec({ bytes: 'aabb' });
  const r = antigensFromJournal(two);
  assert.equal(r.selected, 1); assert.equal(r.skipped.duplicate, 1);
  assert.equal(antigensFromJournal(rec({ bytes: 'ab'.repeat(MAX_ANTIGEN_HEX) })).skipped.oversized, 1);
});

test('the antigen count is capped at MAX_ANTIGENS', () => {
  const many = Array.from({ length: MAX_ANTIGENS + 20 }, (_, i) => rec({ bytes: '42' + i.toString(16).padStart(6, '0') })).join('\n');
  assert.equal(antigensFromJournal(many).selected, MAX_ANTIGENS);
});

test('a malformed line is counted, never thrown', () => {
  assert.doesNotThrow(() => antigensFromJournal('not json\n{bad\n' + rec({})));
  const r = antigensFromJournal('not json\n{bad\n' + rec({}));
  assert.equal(r.skipped.malformed, 2); assert.equal(r.selected, 1);
});

test('antigensFromJournal is total on junk input', () => {
  for (const x of [null, undefined, 42, {}, [], '']) { assert.doesNotThrow(() => antigensFromJournal(x)); assert.equal(antigensFromJournal(x).selected, 0); }
});

test('an antigen of exactly MAX_ANTIGEN_HEX is published (the > edge), one over is oversized', () => {
  assert.equal(antigensFromJournal(rec({ bytes: 'ab'.repeat(MAX_ANTIGEN_HEX / 2) })).selected, 1);   // exactly MAX
  assert.equal(antigensFromJournal(rec({ bytes: 'ab'.repeat(MAX_ANTIGEN_HEX / 2 + 1) })).skipped.oversized, 1);
});

test('a line that parses to a non-object (null, number, string) is malformed — counted, never thrown', () => {
  assert.doesNotThrow(() => antigensFromJournal('null\n42\n"str"\n' + rec({})));
  const r = antigensFromJournal('null\n42\n"str"\n' + rec({}));
  assert.equal(r.skipped.malformed, 3); assert.equal(r.selected, 1);
});

test('a count-record carrying bytes is still skipped as not-full (detail must be full)', () => {
  assert.equal(antigensFromJournal(rec({ detail: 'count', bytes: 'aabb' })).selected, 0);
  assert.equal(antigensFromJournal(rec({ detail: 'count', bytes: 'aabb' })).skipped.notFull, 1);
});
