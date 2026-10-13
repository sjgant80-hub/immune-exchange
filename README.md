# IMMUNE EXCHANGE

### ▶ Live: **https://sjgant80-hub.github.io/immune-exchange/**

A centerless, signed **antibody bus** for gates. A gate that refuses an attack bundles the raw bytes,
signs the bundle with its own key, and publishes it. Every subscriber **verifies the bundle came from a
pinned peer, then re-runs the attack through its OWN gate** before trusting a single byte. So a zero-day
caught anywhere immunises everyone — and **no bundle, however it arrives, can turn a gate against a packet
it would admit.**

```
gate A refuses an attack ─ bundles + signs it ─▶ (untrusted relay) ─▶ gate B, C, D …
                                                                      each VERIFIES the signature,
                                                                      then RE-RUNS it on its own gate,
                                                                      adopts only a permanent refusal
```

## Why it's safe to subscribe to

- **Negative selection — no false immunity.** A subscriber adopts an antibody only when *its own* gate
  refuses the bytes at a **permanent** stage (bad size/magic/schema, an unknown sender, a forged signature,
  a replay). An antigen that this gate would **admit** is never adopted (that would be autoimmunity — the
  body turning on itself). So the gate stays the sole authority; the exchange only ever makes it wiser.
- **The relay is untrusted.** Bundles are signed over `DOMAIN ‖ from ‖ the exact antigen list`, so the
  relay (or anyone) cannot forge a bundle, swap its antigens, or lift a signature onto another sender id.
  And even a perfectly-delivered bundle only gets a subscriber to *re-run* an attack — never to adopt on
  anyone's say-so.
- **Recognition, not over-commitment.** An attack refused at a stage that could *later* become valid
  (out-of-order) earns recognition, never a permanent antibody.

## First publisher: break-it

[break-it](https://github.com/sjgant80-hub/break-it) already writes every refused attack to a hash-chained
journal with the raw bytes — so it needs **no change** to publish: its journal *is* the feed. `src/publisher.mjs`
selects the novel, permanent-on-any-gate antigens (bad size/magic/schema, unknown sender, forged signature — never
a node-specific replay), and `tools/publish.mjs` bundles + signs + POSTs them to a hub. Proven on a **real break-it
journal** (`test/fixtures/break-it-journal.jsonl`, captured from a live node under attack): its three attacks
immunise a fresh gate that never saw them — `node attack-kit/first-publisher.mjs --check` (byte-identical receipt,
run in CI).

```bash
node tools/publish.mjs <break-it-node>/data/node-1/journal.jsonl http://127.0.0.1:8899   # break-it → the bus
```

## Run it

```bash
node run.mjs --nodes 3    # 3 gates on one bus: a zero-day hits node 0, the others go immune after re-running it
```

The hub (`src/hub.mjs`) is an untrusted relay — `POST /publish`, `GET /feed`. It never verifies a signature or
re-runs an antigen; it can drop or reorder bundles but cannot forge one or make any gate adopt anything.

## Subscribe your gate (the whole contract)

The bus is gate-agnostic — any gate can subscribe. Publish and adopt are two small, pure kernels:

```js
import { makeBundle, verifyBundle } from './src/exchange.mjs';   // the signed-bundle protocol
import { adoptAntigens } from './src/subscribe.mjs';             // re-run-then-adopt (negative selection)

// publish the attacks your gate just refused
const bundle = makeBundle(myPubKeyHex, refusedBytesHex, signWithMyKey);

// on a subscriber: verify it's from a pinned peer + signed, THEN re-run each antigen on YOUR gate
const v = verifyBundle(bundle, isPinnedPeer, verifyEd25519);
if (v.ok) adoptAntigens(v.antigens, { ctx, decide, immuneStage, classify, mint, adopt, PERMANENT, keyset, hash, library });
```

`decide`, `mint`, `adopt` and the stage map are injected, so you plug in your own gate. The demo wires the
[break-it](https://github.com/sjgant80-hub/break-it) gate (vendored in `src/`).

## Proof it holds (all re-runnable; CI runs them)

- **`node attack-kit/redteam.mjs --check`** — 9 cases across two gates, byte-identical receipt: a genuine
  zero-day propagates **and** nothing valid-here / unsigned / unpinned / tampered / sig-lifted is ever adopted.
- **`node witness-all.mjs`** — the mutation + fuzz gate over every decision kernel (`exchange`, `subscribe`,
  and the vendored `wire · gate · antibody · immune`). Reviewed-equivalent survivors, with a reason each, live
  in `witness.baseline.json`.
- **`node --test test/*.test.mjs`** — the unit + hostile-input (never-throw) suites.

MIT licensed; see [`NOTICE`](NOTICE) for credits (Gary W. Floyd's GEP ladder; the break-it gate it vendors;
Konomi / Thomas Frumkin). Keys live in `secrets/` (git-ignored, never served).
