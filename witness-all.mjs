#!/usr/bin/env node
// witness-all.mjs — the re-runnable mutation + fuzz gate over every decision kernel. Local and CI run the SAME
// thing: `node witness-all.mjs`. Exit 0 only if every kernel is clean (no unreviewed survivors).
//
// Gated here:
//   exchange  — the signed-bundle protocol (the antibody bus): who may publish, what binds a signature
//   subscribe — NEGATIVE SELECTION: re-run every antigen on THIS node's own gate before adopting (no false immunity)
//   wire · gate · antibody · immune — vendored from sjgant80-hub/break-it (witness-CLEAN there); re-gated here so
//     this repo proves its OWN copies rather than pointing at another repo ("never trust, re-run").
//
// NOT gated: keys.mjs (node:crypto glue — exercised by every test that signs). Reviewed-equivalent survivors, with
// a written reason each, live in witness.baseline.json.
import { runMutations } from './.witness/witness.mjs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
export const PAIRS = [
  ['src/exchange.mjs', ['test/exchange.test.mjs', 'test/fuzz.test.mjs']],
  ['src/subscribe.mjs', ['test/subscribe.test.mjs', 'test/fuzz.test.mjs']],
  ['src/wire.mjs', ['test/wire.test.mjs', 'test/fuzz.test.mjs']],
  ['src/gate.mjs', ['test/gate.test.mjs', 'test/fuzz.test.mjs']],
  ['src/antibody.mjs', ['test/antibody.test.mjs', 'test/fuzz.test.mjs']],
  ['src/immune.mjs', ['test/immune.test.mjs', 'test/fuzz.test.mjs']],
];

const only = process.argv.slice(2);
let allClean = true;
const rows = [];
for (const [src, tests] of PAIRS) {
  if (only.length && !only.includes(src)) continue;
  const testFiles = Array.isArray(tests) ? tests : [tests];
  const t0 = Date.now();
  const r = runMutations(join(HERE, src), { cwd: HERE, cap: 5000, timeout: 60000, testCmd: ['node', '--test', ...testFiles] });
  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  rows.push({ src, killed: r.killed, total: r.total, survived: r.survived.length, ignored: r.ignored.length, capped: r.capped });
  console.log(`${r.clean && !r.capped ? '✓' : '✗'} ${src.padEnd(18)} ${String(r.killed).padStart(4)}/${String(r.total).padEnd(4)} killed` +
    `${r.ignored.length ? ` · ${r.ignored.length} reviewed-equivalent` : ''}${r.capped ? ` · CAPPED` : ''} · ${secs}s`);
  for (const s of r.survived) console.log(`    SURVIVED line ${s.line}: ${s.mutation} :: ${s.snippet}`);
  if (!r.clean || r.capped) allClean = false;
}
const k = rows.reduce((a, r) => a + r.killed, 0), n = rows.reduce((a, r) => a + r.total, 0);
console.log(`\n${allClean ? 'WITNESS CLEAN' : 'WITNESS NOT CLEAN'} — ${k}/${n} mutants killed across ${rows.length} kernel(s)`);
process.exit(allClean ? 0 : 1);
