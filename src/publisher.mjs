// ════════════════════════════════════════════════════════════════
// publisher.mjs — break-it is the exchange's first publisher. Pure, total, gated.
//
// break-it already writes every refused attack to its hash-chained journal, with the raw bytes. This reads that
// journal and selects the antigens worth publishing to the bus: a NOVEL refusal, kept in FULL (bytes on file), at a
// stage that is permanent on ANY gate regardless of that gate's state — bad size/magic/schema, an unknown sender,
// a forged signature. It deliberately does NOT publish a 'counter' refusal (a replay is fresh on a gate that has
// not seen it) or http/flood/behaviour (not universal packet bytes). The subscriber re-runs everything on its own
// gate anyway (subscribe.mjs), so this only chooses WHAT to offer; it can never cause a false adoption.
//
// So break-it needs no change to become a publisher — its journal IS the feed. This turns that journal into the
// exchange's antigen list, ready for makeBundle (exchange.mjs).
// ════════════════════════════════════════════════════════════════
import { MAX_ANTIGENS, MAX_ANTIGEN_HEX } from './exchange.mjs';

// stages that are permanent on any gate (pure bytes, or a key the gate pins) — safe to offer estate-wide
export const PUBLISHABLE = Object.freeze(['size', 'magic', 'schema', 'sender', 'signature']);
const HEX = /^(?:[0-9a-f]{2})+$/;

/**
 * The antigens worth publishing from a break-it journal (one JSON record per line).
 * → { antigens: hex[], scanned, selected, skipped: {notNovel, notFull, nonPermanent, malformed, duplicate, oversized} }.
 * Total: a bad line is counted as malformed, never a throw.
 */
export function antigensFromJournal(text) {
  const lines = (typeof text === 'string' ? text : '').split(/\r?\n/).filter((l) => l.length);
  const seen = new Set(), antigens = [];
  const skip = { notNovel: 0, notFull: 0, nonPermanent: 0, malformed: 0, duplicate: 0, oversized: 0 };
  let scanned = 0;
  for (const line of lines) {
    scanned++;
    let r;
    try { r = JSON.parse(line); } catch { skip.malformed++; continue; }
    if (!r || typeof r !== 'object') { skip.malformed++; continue; }
    if (r.novel !== true) { skip.notNovel++; continue; }
    if (r.detail !== 'full' || typeof r.bytes !== 'string' || !HEX.test(r.bytes) || r.bytes.length === 0) { skip.notFull++; continue; }
    if (!PUBLISHABLE.includes(r.stage)) { skip.nonPermanent++; continue; }
    if (r.bytes.length > MAX_ANTIGEN_HEX) { skip.oversized++; continue; }
    if (seen.has(r.bytes)) { skip.duplicate++; continue; }
    if (antigens.length >= MAX_ANTIGENS) break;
    seen.add(r.bytes); antigens.push(r.bytes);
  }
  return { antigens, scanned, selected: antigens.length, skipped: skip };
}
