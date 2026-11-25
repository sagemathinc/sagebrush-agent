// fleet-relay-core.test.mjs's other process: the pure core alone, with the WebCrypto backend (what the fleet Worker
// installs), verifying the corpus it reads on stdin; prints each case's code (and the admitted fields) as JSON. It
// never loads lib/fleet's Node entry.
import { readFileSync } from "node:fs";
import * as core from "../lib/fleet/core/index.mjs";

const read = (f) => JSON.parse(readFileSync(new URL(f, import.meta.url), "utf8"));
core.useCrypto(core.webCrypto());
core.useSchemas((name) => read(`../schema/fleet/${name}`));

const corpus = JSON.parse(readFileSync(0, "utf8"));
const { AUD, NOW, fleet, host, agent } = corpus;
const hostRaw = core.unb64(corpus.hostRaw);
const chain = (await core.applyChainEntry(null, core.unb64(corpus.genesis), { aud: AUD, fleet })).state;

const ctxOf = (c = {}) => ({
  aud: AUD, now: c.now ?? NOW,
  hostKey: (h) => { if (h !== host) core.refuse("unknown_host"); return hostRaw; },
  currentGen: () => c.gen ?? 3,
  agentHasBrowser: (h, a) => a === agent && c.granted !== false,
  consumeAppToken: (key) => corpus.tokens[key] ?? null,
  sessionLive: (account, session) => account === corpus.account && session === corpus.account_session && !c.sessionDead,
  chainOf: () => chain,
});

const out = [];
for (const k of corpus.cases) {
  try {
    let r;
    if (k.kind === "host") r = await core.verifyHostOpen({ target: k.target, headers: k.headers }, ctxOf(k.ctx));
    else if (k.kind === "app") r = await core.verifyAppOpen({ target: k.target, headers: k.headers }, ctxOf(k.ctx));
    else r = await core.verifyCommit({ header: k.header, body: core.unb64(k.body) }, ctxOf(k.ctx));
    out.push({ code: "ok", value: r });
  } catch (e) {
    if (!(e instanceof core.FleetError)) throw e;
    out.push({ code: e.code });
  }
}
// (stateful sequences: each its own copy of the token rows, which a consume takes; in order, or all at once)
const sequences = [];
for (const q of corpus.sequences ?? []) {
  const rows = new Map(Object.entries(q.tokens));
  const ctx = { ...ctxOf(), consumeAppToken: async (key) => { const r = rows.get(key) ?? null; rows.delete(key); return r; } };
  const one = async (k) => { try { await core.verifyAppOpen({ target: k.target, headers: k.headers }, ctx); return "ok"; } catch (e) { if (!(e instanceof core.FleetError)) throw e; return e.code; } };
  const codes = [];
  if (q.concurrent) codes.push(...(await Promise.all(q.cases.map(one))));
  else for (const k of q.cases) codes.push(await one(k));
  sequences.push({ codes, left: rows.size });
}
// (the control plane's MACs on this backend: the request header, and an answer verified back)
const c = corpus.control;
const key = core.controlKey(c.key);
const header = await core.signControlRequest({ key, method: c.method, target: c.target, body: core.unb64(c.body), ts: c.ts, id: c.id });
const call = await core.verifyControlRequest({ header, method: c.method, target: c.target, body: core.unb64(c.body) }, { key, now: c.ts });
const answer = await core.signControlAnswer({ key, call, answer: "admit", fields: { result: "refused", code: "not_granted" } });
const back = await core.verifyControlAnswer(answer, { key, call, answer: "admit" });
process.stdout.write(JSON.stringify({ out, sequences, control: { header, answer: { header: answer.header, body: core.b64(answer.body) }, back } }));
