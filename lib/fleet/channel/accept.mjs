// The browser channel's handshake, host side (design agent-autonomous-browser-channel.md r4 §3; O11 §7.2): the
// responder's checks on message 1, in the design's order, then ONE atomic durable compare-and-set per agent on the
// host's store, before message 2 can be written.
//
//   1. the relay-claimed host and aud are this host's own (a misrouted stream is refused before any Noise);
//   2. the key the broker holds is its current certificate's enc_key, exactly;
//   3. Noise reads message 1 (es, s, ss, the payload);
//   4. the payload is the signed sb.browser-session.v1 record, verified through the core (the device signer counting
//      at chain_seq and at the pinned head); its fields equal the prologue's; s equals its app_session_pub; its time
//      window holds;
//   5. the live checks (the caller's: the certificate not revoked, host_gen current and the grant giving this agent the
//      browser, the host and agent not revoked, horizon_s);
//   6. the compare-and-set (H1, H2): a fresh session (resume_n 0) needs an unseen session and a browser_gen strictly
//      above the agent's highest; a resume needs the agent's live session, its browser_gen, app key and record hash, and
//      resume_n = stored + 1. It rechecks (5) inside the commit, retires the replaced session, and is durable (fsync)
//      before it returns. Only then can message 2 be written. A lost message 2 never rolls it back: the app's next
//      attempt is the next resume_n.

import { b64, canonText, enc, isId, refuse, sha256b64 } from "../index.mjs";
import { openByDevice } from "../core/verify.mjs";
import { DurableState, exactKeys } from "../host/store.mjs";
import { responder } from "./noise.mjs";

export const RECORD_MAX = 65439;
export const STORE_NAME = "browser-channels.json";
const TWELVE_HOURS = 12 * 3600_000;
const RETIRED_KEPT = 256;
const PROLOGUE_KEYS = ["fleet", "aud", "session", "host", "agent", "browser_gen", "host_gen", "resume_n"];

/** The prologue's bytes (O11 §7.2): canon({ proto, fleet, aud, session, host, agent, browser_gen, host_gen, resume_n }). */
export function prologueBytes(p) {
  if (!exactKeys(p, PROLOGUE_KEYS)) refuse("bad_form", "the prologue's fields");
  return enc(canonText({ proto: "sagebrush-browser/1", ...p }));
}

// ---- the store: one durable file per host, under the host's lock

const count = (v) => Number.isSafeInteger(v) && v >= 0;
const B64_32 = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
function checkStore(st) {
  if (!exactKeys(st, ["v", "agents"]) || st.v !== 1 || !st.agents || typeof st.agents !== "object" || Array.isArray(st.agents)) refuse("bad_form", "the channel store's shape");
  for (const [agent, a] of Object.entries(st.agents)) {
    if (!isId(agent) || !exactKeys(a, ["high", "live", "retired"]) || !count(a.high)) refuse("bad_form", "a channel store entry");
    if (!Array.isArray(a.retired) || a.retired.length > RETIRED_KEPT || !a.retired.every(isId)) refuse("bad_form", "a channel store entry's retired sessions");
    if (a.live !== null && (!exactKeys(a.live, ["session", "browser_gen", "app_static", "record_sha256", "resume_n"]) || !isId(a.live.session)
      || !count(a.live.browser_gen) || a.live.browser_gen > a.high || !count(a.live.resume_n) || !B64_32.test(a.live.app_static) || !B64_32.test(a.live.record_sha256))) refuse("bad_form", "a channel store's live session");
  }
}

/** The host's channel store, a DurableState under the lock the host store owner holds (lib/fleet/host/store.mjs). */
export const openChannelStore = (dir, lock, io) => DurableState.attach(dir, STORE_NAME, { check: checkStore, initial: () => ({ v: 1, agents: {} }), lock, io });

// ---- message 1

/**
 * Check message 1 and commit its acceptance. ctx:
 *   self: { host, aud, fleet }; prologue: the fields of the relay's admitted host open (§5.2), built by this host;
 *   encKey: { raw, dh } (the X25519 key it holds); cert: its own verified certificate (verifyHostCert: { encRaw, ... });
 *   chain: the pinned chain state; store: openChannelStore(...); now: ms;
 *   live(record): throws the refusal if a live check fails (it runs again inside the commit);
 *   ephemeral: the fixtures only.
 * Returns { record, accepted: { host_gen, browser_gen, resume_n }, reply() } where reply() writes message 2 (once) and
 * returns { message, send, receive }. Every refusal is a FleetError, and nothing is committed.
 */
export async function acceptMessage1(message1, ctx) {
  const p = ctx.prologue;
  const pro = prologueBytes(p);
  // (1) a stream the relay routed here must be this host's own
  if (p.host !== ctx.self.host || p.fleet !== ctx.self.fleet) refuse("not_granted", "a stream for another host");
  if (p.aud !== ctx.self.aud) refuse("bad_audience");
  // (2) the held key is the certified one, checked here and not left to the handshake
  if (b64(ctx.encKey.raw) !== b64(ctx.cert.encRaw)) refuse("not_granted", "the held X25519 key isn't the certified one");
  // (3) Noise
  const R = responder({ s: ctx.encKey, prologue: pro, ephemeral: ctx.ephemeral ?? null });
  // (the record is at most 65,439 bytes: Noise refuses a message 1 over 65,535, which is the record plus 96 bytes)
  const { rs, payload } = R.readMessage1(message1);
  // (4) the record
  const env = await openByDevice(payload, { aud: p.aud, fleet: p.fleet, chain: ctx.chain }, "sb.browser-session.v1", "browser-session");
  const r = env.body;
  for (const k of ["fleet", "aud", "session", "host", "agent", "browser_gen", "host_gen"]) if (r[k] !== p[k]) refuse("bad_form", `the record's ${k} isn't the stream's`);
  if (r.app_session_pub !== b64(rs)) refuse("bad_signature", "the initiator's key isn't the record's app_session_pub");
  if (!(r.not_before_ms <= r.not_after_ms && r.not_after_ms <= r.at_ms + TWELVE_HOURS)) refuse("bad_form", "a session record's lifetime");
  if (ctx.now < r.not_before_ms || ctx.now >= r.not_after_ms) refuse("grant_expired", "outside the record's window");
  // (5) the live checks
  ctx.live(r);
  // (6) the compare-and-set, durable before message 2 exists
  const recordSha = await sha256b64(payload);
  ctx.store.commit((st) => {
    ctx.live(r); // (rechecked at commit time: nothing cached from before)
    const a = st.agents[r.agent] ?? { high: 0, live: null, retired: [] };
    if (p.resume_n === 0) {
      if (r.browser_gen <= a.high) refuse("browser_gen_stale", "a new session needs a browser_gen above the agent's highest");
      if (a.retired.includes(r.session) || a.live?.session === r.session) refuse("replay", "a session id seen before");
      if (a.live) a.retired = [...a.retired, a.live.session].slice(-RETIRED_KEPT);
      a.high = r.browser_gen;
      a.live = { session: r.session, browser_gen: r.browser_gen, app_static: r.app_session_pub, record_sha256: recordSha, resume_n: 0 };
    } else {
      const l = a.live;
      if (!l || l.session !== r.session || l.browser_gen !== r.browser_gen) refuse("browser_gen_stale", "not the agent's live session");
      if (l.app_static !== r.app_session_pub || l.record_sha256 !== recordSha) refuse("bad_form", "a resume with another key or record");
      if (p.resume_n !== l.resume_n + 1) refuse("replay", "resume_n isn't the next");
      l.resume_n = p.resume_n;
    }
    st.agents[r.agent] = a;
  });
  const accepted = { host_gen: r.host_gen, browser_gen: r.browser_gen, resume_n: p.resume_n };
  return Object.freeze({
    record: r,
    accepted,
    reply: () => R.writeMessage2(enc(canonText(accepted))),
  });
}
