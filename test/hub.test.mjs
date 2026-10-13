import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startHub } from '../src/hub.mjs';
import { makeBundle, toHex } from '../src/exchange.mjs';
import { keyFromSeed, rawPublic, signWith } from '../src/keys.mjs';

let hub;
const K = keyFromSeed(new Uint8Array(32).fill(7));
const good = () => makeBundle(toHex(rawPublic(K)), ['42524b31aa', 'deadbeef'], signWith(K));
const post = (b) => fetch(hub.url + '/publish', { method: 'POST', headers: { 'content-type': 'application/json' }, body: typeof b === 'string' ? b : JSON.stringify(b) }).then((r) => r.json().then((j) => ({ status: r.status, j })));

before(async () => { hub = await startHub({ port: 0 }); });
after(async () => { await hub.close(); });

test('the hub stores a well-formed bundle and serves it on the feed', async () => {
  const r = await post(good());
  assert.equal(r.j.ok, true); assert.equal(r.j.seq, 0);
  const feed = await (await fetch(hub.url + '/feed')).json();
  assert.equal(feed.bundles.length, 1);
  assert.equal(feed.bundles[0].bundle.from, toHex(rawPublic(K)));
});

test('the hub refuses a bundle that is not the exchange shape (but never vouches for a signature)', async () => {
  assert.equal((await post({ v: 2, from: 'x' })).j.ok, false);
  assert.equal((await post('not json')).j.ok, false);
  assert.equal((await post({ ...good(), antigens: [] })).j.ok, false);
  assert.equal((await post({ ...good(), sig: 'short' })).j.ok, false);
  // a VALID-shape bundle with a nonsense signature is still STORED — the hub does not verify; subscribers do
  const r = await post({ ...good(), sig: '0'.repeat(128) });
  assert.equal(r.j.ok, true);
});

test('the feed cursor returns only bundles at or after ?since', async () => {
  const head = (await (await fetch(hub.url + '/health')).json()).head;
  await post(good());
  const feed = await (await fetch(hub.url + '/feed?since=' + head)).json();
  assert.ok(feed.bundles.length >= 1);
  assert.ok(feed.bundles.every((e) => e.seq >= head));
});
