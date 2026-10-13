// ════════════════════════════════════════════════════════════════
// hub.mjs — the UNTRUSTED relay. Bound to 127.0.0.1. It carries signed bundles between gates and nothing more:
//   POST /publish   a bundle (JSON) — shape-checked and stored; the hub does NOT and CANNOT vouch for it
//   GET  /feed      the recent bundles, newest first (?since= a monotonic cursor)
//   GET  /health
// The hub never verifies a signature or re-runs an antigen — that is every subscriber's job (verifyBundle +
// subscribe.adoptAntigens on its own gate). So a compromised hub can drop or reorder bundles, but it cannot forge
// one, swap a bundle's antigens, or make any gate adopt anything. Bounded: a capped ring, a body-size limit.
// ════════════════════════════════════════════════════════════════
import http from 'node:http';

export const LIMITS = Object.freeze({ bodyBytes: 256 * 1024, keep: 4096, rate: 200, burst: 400 });
const HEX = /^(?:[0-9a-f]{2})+$/, HEX64 = /^[0-9a-f]{64}$/;

// a bundle is STORABLE only if it has the exchange shape (the hub still does not trust it — subscribers verify)
function storable(b) {
  return b && typeof b === 'object' && b.v === 1 && typeof b.from === 'string' && HEX64.test(b.from)
    && Array.isArray(b.antigens) && b.antigens.length > 0 && b.antigens.length <= 64
    && b.antigens.every((a) => typeof a === 'string' && HEX.test(a) && a.length <= 4096)
    && typeof b.sig === 'string' && HEX.test(b.sig) && b.sig.length === 128;
}

export async function startHub(opts = {}) {
  const host = opts.host || '127.0.0.1';
  const now = opts.now || (() => Date.now());
  const feed = [];                 // { seq, at, bundle }
  let seq = 0;
  const buckets = new Map();
  const allow = (ip) => { const t = now(); let b = buckets.get(ip); if (!b) { if (buckets.size >= 10000) buckets.delete(buckets.keys().next().value); b = { tok: LIMITS.burst, at: t }; buckets.set(ip, b); } b.tok = Math.min(LIMITS.burst, b.tok + ((t - b.at) * LIMITS.rate) / 1000); b.at = t; if (b.tok < 1) return false; b.tok -= 1; return true; };
  const json = (res, code, body) => { const s = JSON.stringify(body); res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'access-control-allow-origin': '*' }); res.end(s); };
  const readBody = (req) => new Promise((resolve) => { const cl = req.headers['content-length']; if (req.headers['transfer-encoding'] !== undefined || typeof cl !== 'string' || !/^[0-9]{1,7}$/.test(cl)) return resolve(null); const n = Number(cl); if (n < 1 || n > LIMITS.bodyBytes) return resolve(null); const parts = []; let got = 0, done = false; const fin = (v) => { if (!done) { done = true; resolve(v); } }; req.on('data', (c) => { got += c.length; if (got > n) { fin(null); req.destroy(); } else parts.push(c); }); req.on('end', () => fin(got === n ? Buffer.concat(parts).toString('utf8') : null)); req.on('error', () => fin(null)); });

  const server = http.createServer({ requestTimeout: 3000, headersTimeout: 2000, maxHeaderSize: 8192 }, async (req, res) => {
    const ip = String(req.socket.remoteAddress || '?');
    try {
      const url = new URL(req.url, 'http://local');
      if (req.method === 'POST' && url.pathname === '/publish') {
        if (!allow(ip)) return json(res, 429, { ok: false, why: 'rate limited' });
        const body = await readBody(req); let b = null; try { b = JSON.parse(body); } catch { /* null */ }
        if (!storable(b)) return json(res, 400, { ok: false, why: 'not a storable bundle' });
        const entry = { seq: seq++, at: new Date(now()).toISOString(), bundle: { v: 1, from: b.from, antigens: b.antigens, sig: b.sig } };
        feed.push(entry); if (feed.length > LIMITS.keep) feed.shift();
        return json(res, 200, { ok: true, seq: entry.seq });
      }
      if (req.method !== 'GET') return json(res, 405, { ok: false });
      if (url.pathname === '/health') return json(res, 200, { ok: true, bundles: feed.length, head: seq });
      if (url.pathname === '/feed') { const since = Math.max(0, Number(url.searchParams.get('since')) || 0); const limit = Math.min(256, Math.max(1, Number(url.searchParams.get('limit')) || 64)); return json(res, 200, { head: seq, bundles: feed.filter((e) => e.seq >= since).slice(-limit) }); }
      return json(res, 404, { ok: false });
    } catch { return json(res, 500, { ok: false }); }
  });
  server.maxConnections = 256;
  await new Promise((r) => server.listen(opts.port || 0, host, r));
  const port = server.address().port;
  return { port, url: 'http://' + host + ':' + port, get bundles() { return feed.length; }, close: () => new Promise((r) => { server.close(r); server.closeAllConnections?.(); }) };
}
