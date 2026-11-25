// The browser channel's message 2, app side (design agent-autonomous-browser-channel.md r4.2 §3.4; addendum A2): the
// payload of an authenticated message 2 is one of two closed shapes, checked against the attempt that sent message 1.
//
//   accepted: { host_gen, browser_gen, resume_n }, the committed values, each the attempt's own;
//   refused:  { refused: "resume_n", host_gen, browser_gen, resume_n }, the host's answer that this session's record
//             is already live at resume_n: it must name EXACTLY the attempt's resume_n (attempts are sequential, so
//             the host committed it and the reply was lost), and the next attempt is resume_n + 1.
//
// Anything else ends the session (bad_form): another shape, an extra or missing key, another generation, a counter
// other than the attempt's, or a next counter past the safe integers. A refused message 2 carries no transport.

import { parseCanonical, refuse } from "../index.mjs";
import { exactKeys } from "../host/store.mjs";
import { RESUME_REFUSED } from "./accept.mjs";

const ACCEPTED = ["browser_gen", "host_gen", "resume_n"];
const REFUSED = ["browser_gen", "host_gen", "refused", "resume_n"];

/**
 * attempt: { host_gen, browser_gen, resume_n } of the attempt whose message 1 this answers. Returns
 * { accepted: true } or { refused: true, next } (the resume_n for the next attempt), or throws bad_form.
 */
export function message2Outcome(payload, attempt) {
  const m = parseCanonical(payload, 1024);
  const same = (k) => m[k] === attempt[k];
  if (exactKeys(m, ACCEPTED)) {
    if (!ACCEPTED.every(same)) refuse("bad_form", "message 2 isn't this attempt's");
    return { accepted: true };
  }
  if (exactKeys(m, REFUSED) && m.refused === RESUME_REFUSED) {
    if (!ACCEPTED.every(same)) refuse("bad_form", "a refusal that isn't this attempt's counter or generation");
    const next = attempt.resume_n + 1;
    if (!Number.isSafeInteger(next)) refuse("bad_form", "resume_n past the safe integers");
    return { refused: true, next };
  }
  refuse("bad_form", "message 2's payload");
}
