// The Delegate protocol's requests, checked closed (design/workspace-agent-protocol.md §6.1, `delegate.1`): every
// method's params have exactly the keys listed, every value its rule; anything else is refused `bad_request`, and an
// oversized document or request `too_large`.  What a check returns is the request in the form the store uses (a
// document's content as bytes).

import { NOT_WELL_FORMED, pathProblem, pathSetProblem } from "./task-paths.mjs";

export const FEATURE = "delegate.1";
export const LIMITS = Object.freeze({
  frame: 4 * 1024 * 1024, // each tasks.* request and each answer's raw frame, UTF-8 bytes (4 MiB)
  doc: 4 * 1024 * 1024, // one document's bytes
  docs: 4 * 1024 * 1024, // all of a request's documents
  title: 200, // characters
  prompt: 64 * 1024, // UTF-8 bytes (prompt, note)
  answer: 16 * 1024, // UTF-8 bytes
  pending: 8, // page requests in flight
});
export const ERRORS = Object.freeze(["bad_request", "forbidden", "not_found", "stale", "conflict", "too_large", "busy", "unavailable", "withdrawn", "final"]);
export const STATUSES = Object.freeze(["working", "proposal", "merged", "closed", "failed", "interrupted"]);
export const METHODS = Object.freeze(["tasks.start", "tasks.list", "tasks.get", "tasks.diff", "tasks.file", "tasks.merged", "tasks.close", "tasks.ask", "tasks.stop", "tasks.revoke", "tasks.resume", "tasks.answer"]);

/** A refusal the page sees as `error.data.code`. */
export class TaskError extends Error {
  constructor(code, message) {
    super(message);
    if (!ERRORS.includes(code)) throw new Error(`not a task error code: ${code}`);
    this.code = code;
  }
}
const bad = (m) => { throw new TaskError("bad_request", m); };
const enc = new TextEncoder();
const utf8Len = (s) => enc.encode(s).length;

const HEX32 = /^[0-9a-f]{32}$/, HEX40 = /^[0-9a-f]{40}$/;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
function keys(v, want, what) {
  if (!isObj(v)) bad(`${what} must be an object`);
  const extra = Object.keys(v).filter((k) => !want.includes(k)), missing = want.filter((k) => !Object.hasOwn(v, k));
  if (extra.length) bad(`${what}: unknown field ${JSON.stringify(extra[0].slice(0, 40))}`);
  if (missing.length) bad(`${what}: missing ${missing[0]}`);
}
const task = (v) => (typeof v === "string" && HEX32.test(v) ? v : bad("task must be 32 lowercase hex"));
const id32 = (v, what) => (typeof v === "string" && HEX32.test(v) ? v : bad(`${what} must be 32 lowercase hex`));
const oid = (v, what) => (typeof v === "string" && HEX40.test(v) ? v : bad(`${what} must be 40 lowercase hex`));
const int = (v, min, what) => (Number.isSafeInteger(v) && v >= min ? v : bad(`${what} must be an integer, at least ${min}`));
const text = (v, max, what) => (typeof v === "string" && !NOT_WELL_FORMED.test(v) && utf8Len(v) <= max ? v : bad(`${what} must be well-formed text of at most ${max} bytes`));
function path(v) {
  const why = pathProblem(v);
  if (why) bad(why);
  return v;
}
const kindOf = (p, k) => {
  if (k !== "notebook" && k !== "file") bad('kind must be "notebook" or "file"');
  if ((k === "notebook") !== /\.ipynb$/.test(p)) bad("a notebook's path ends .ipynb, and only a notebook's");
  return k;
};
/** A document's content as bytes: text (UTF-8), or {base64}. */
function content(v) {
  let b;
  if (typeof v === "string") { if (NOT_WELL_FORMED.test(v)) bad("content must be well-formed text"); b = Buffer.from(v, "utf8"); }
  else if (isObj(v) && Object.keys(v).length === 1 && typeof v.base64 === "string" && /^[A-Za-z0-9+/]*={0,2}$/.test(v.base64) && v.base64.length % 4 === 0) b = Buffer.from(v.base64, "base64");
  else bad("content must be text or {base64}");
  if (b.length > LIMITS.doc) throw new TaskError("too_large", `a document is at most ${LIMITS.doc} bytes`);
  return b;
}
function docs(v, what) {
  if (!Array.isArray(v)) bad(`${what} must be a list`);
  let total = 0;
  const out = v.map((d, i) => {
    keys(d, ["path", "kind", "content"], `${what}[${i}]`);
    const p = path(d.path), bytes = content(d.content);
    total += bytes.length;
    if (total > LIMITS.docs) throw new TaskError("too_large", `a request's documents are at most ${LIMITS.docs} bytes together`);
    return { path: p, kind: kindOf(p, d.kind), bytes };
  });
  const why = pathSetProblem(out.map((d) => d.path));
  if (why) bad(why);
  return out;
}
/** `{blob, content}` | `{absent: true}` | null (not sent), with the blob left for the store to check against the bytes. */
function side(v, what) {
  if (v === null) return null;
  if (isObj(v) && Object.keys(v).length === 1 && v.absent === true) return { absent: true };
  keys(v, ["blob", "content"], what);
  return { blob: oid(v.blob, `${what}.blob`), bytes: content(v.content) };
}

const CHECK = {
  "tasks.start": (p) => {
    keys(p, ["title", "prompt", "target", "run", "docs"], "params");
    if (typeof p.title !== "string" || NOT_WELL_FORMED.test(p.title) || [...p.title].length > LIMITS.title || p.title.trim() === "") bad(`title must be well-formed text of 1 to ${LIMITS.title} characters`);
    if (p.target !== "local") throw new TaskError("unavailable", 'only the target "local" is offered');
    if (typeof p.run !== "boolean") bad("run must be true or false");
    const d = docs(p.docs, "docs");
    if (!d.length) bad("a task needs at least one document");
    return { title: p.title, prompt: text(p.prompt, LIMITS.prompt, "prompt"), target: "local", run: p.run, docs: d };
  },
  "tasks.list": (p) => (keys(p, [], "params"), {}),
  "tasks.get": (p) => (keys(p, ["task", "after"], "params"), { task: task(p.task), after: int(p.after, 0, "after") }),
  "tasks.diff": (p) => (keys(p, ["task", "commit"], "params"), { task: task(p.task), commit: oid(p.commit, "commit") }),
  "tasks.file": (p) => (keys(p, ["task", "commit", "path"], "params"), { task: task(p.task), commit: oid(p.commit, "commit"), path: path(p.path) }),
  "tasks.merged": (p) => {
    keys(p, ["task", "proposal", "seq", "merge_id", "files"], "params");
    if (!Array.isArray(p.files)) bad("files must be a list");
    let total = 0;
    const files = p.files.map((f, i) => {
      keys(f, ["path", "kind", "proposal_blob", "mine", "merged"], `files[${i}]`);
      const pp = path(f.path), mine = side(f.mine, `files[${i}].mine`), merged = side(f.merged, `files[${i}].merged`);
      for (const s of [mine, merged]) if (s?.bytes) { total += s.bytes.length; if (total > LIMITS.docs) throw new TaskError("too_large", `a request's documents are at most ${LIMITS.docs} bytes together`); }
      return { path: pp, kind: kindOf(pp, f.kind), proposal_blob: f.proposal_blob === null ? null : oid(f.proposal_blob, `files[${i}].proposal_blob`), mine, merged };
    });
    const why = pathSetProblem(files.map((f) => f.path));
    if (why) bad(why);
    return { task: task(p.task), proposal: oid(p.proposal, "proposal"), seq: int(p.seq, 0, "seq"), merge_id: id32(p.merge_id, "merge_id"), files };
  },
  "tasks.close": (p) => (keys(p, ["task", "proposal", "seq"], "params"), { task: task(p.task), proposal: p.proposal === null ? null : oid(p.proposal, "proposal"), seq: int(p.seq, 0, "seq") }),
  "tasks.ask": (p) => (keys(p, ["task", "proposal", "seq", "note", "current"], "params"), { task: task(p.task), proposal: oid(p.proposal, "proposal"), seq: int(p.seq, 0, "seq"), note: text(p.note, LIMITS.prompt, "note"), current: docs(p.current, "current") }),
  "tasks.stop": (p) => (keys(p, ["task"], "params"), { task: task(p.task) }),
  "tasks.revoke": (p) => (keys(p, ["task"], "params"), { task: task(p.task) }),
  // (note: optional, what the person tells Claude as the task goes on (Stop, then Resume with a note), bounded as Ask's)
  "tasks.resume": (p) => (keys(p, isObj(p) && Object.hasOwn(p, "note") ? ["task", "note"] : ["task"], "params"), { task: task(p.task), ...(Object.hasOwn(p, "note") ? { note: text(p.note, LIMITS.prompt, "note") } : {}) }),
  "tasks.answer": (p) => (keys(p, ["task", "qid", "revision", "answer_id", "text"], "params"), { task: task(p.task), qid: int(p.qid, 1, "qid"), revision: int(p.revision, 1, "revision"), answer_id: id32(p.answer_id, "answer_id"), text: text(p.text, LIMITS.answer, "text") }),
};

/** The checked params of a `tasks.*` request, or a TaskError. */
export function checkRequest(method, params) {
  if (!Object.hasOwn(CHECK, method)) throw new TaskError("bad_request", "not a tasks method");
  return CHECK[method](params ?? bad("params must be an object"));
}
