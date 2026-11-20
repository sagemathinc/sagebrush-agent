// turn_info: the model and the thinking level (effort) a turn runs with, as the backend itself reports them, so the page
// can show them under the agent's name (W3). Only what was reported, and only these two fields, each bounded: a field
// not reported, or not of its expected shape, is left out; nothing left, no event. Never copied from an earlier turn.
//
//   Claude: the model in the query's system/init; the effort in a hook's input (effort.level, PreToolUse or Stop).
//   Codex: both in its answer to thread/start (model, reasoningEffort).

// (a model id as the backend gives it: Claude's with a context suffix ("…[1m]"), a cloud provider's with "/" or "@")
const MODEL = /^[A-Za-z0-9._:\/@[\]-]{1,128}$/;
const EFFORT = /^[a-z0-9]{1,16}$/;

/** A turn_info event for the fields given that are well-formed, or null if none is. */
export function turnInfo({ model, effort } = {}) {
  const m = typeof model === "string" && MODEL.test(model) ? model : undefined;
  const e = typeof effort === "string" && EFFORT.test(effort) ? effort : undefined;
  if (m === undefined && e === undefined) return null;
  return { type: "turn_info", ...(m !== undefined ? { model: m } : {}), ...(e !== undefined ? { effort: e } : {}) };
}
