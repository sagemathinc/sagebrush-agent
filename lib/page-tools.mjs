// The branch and run tools: the page's verbs git_branch, git_commit, git_status, git_wait, run_notebook, run_file,
// run_stop and latex_build, each a tool of the same name. Their words and parameters are the page's own
// (page-verbs.json, a copy of the page's schema.json entries that the page's repository checks); the page checks every
// call against the person's grant ("May run code", the branch's owner), so they run without a question.

import { readFileSync } from "node:fs";
import { z } from "zod";

/** The page's 8 verbs, as the page words them. */
export const PAGE_VERBS = JSON.parse(readFileSync(new URL("./page-verbs.json", import.meta.url), "utf8")).verbs;
export const PAGE_TOOL_VERBS = ["git_branch", "git_commit", "git_status", "git_wait", "run_notebook", "run_file", "run_stop", "latex_build"];
/** The verbs that run code in the page: their calls wait as long as the run may, and a stopped one asks the page to stop. */
export const RUN_VERBS = ["run_notebook", "run_file", "latex_build"];

// What the model is told beyond the page's own words (board's, quoted word for word in the review).
export const BUSY_LINE = 'If this call runs out of time, the run may still be stopping in the page: a "busy" answer right after means wait before trying again, not call again at once.';
export const PAGE_TEXT = {
  tooLarge: "The page's answer was too large to pass on (over 256 KiB, or more than 4 pages), so none of it was used.",
  notPng: (n) => `Page ${n}: the page sent an image that isn't a PNG, so it was left out.`,
};

// The page's own bounds these tools rely on (the review page's run-verbs.ts RUN_LIMITS and branch-store.ts STORE_LIMITS)
export const RUN_DEFAULT_S = 120, RUN_MAX_S = 600, WAIT_DEFAULT_S = 50, WAIT_MAX_S = 50;
/** The allowance past a run's or a wait's own bound for the call and its answer (not a promise the page has settled). */
export const MARGIN_S = 30;
export const RESULT_MAX = 256 * 1024, PAGES_MAX = 4;
/** How long the agent's own run_stop may wait for its answer, which is dropped. */
export const STOP_MS = 5 * 1000;

/** A call's own timer: a run's timeout_s, or a wait's seconds (each capped at the page's bound, so it is finite for any
 * argument; the argument itself goes to the page as given), plus the margin. */
export function callMs(verb, a) {
  const take = (v, dflt, max) => (Number.isInteger(v) && v >= 1 ? Math.min(v, max) : dflt);
  if (RUN_VERBS.includes(verb)) return (take(a?.timeout_s, RUN_DEFAULT_S, RUN_MAX_S) + MARGIN_S) * 1000;
  if (verb === "git_wait") return (take(a?.seconds, WAIT_DEFAULT_S, WAIT_MAX_S) + MARGIN_S) * 1000;
  return null;
}

/** A tool's description: the page's, and for a run the busy line. */
export const describe = (verb) => PAGE_VERBS["workspace." + verb].description + (RUN_VERBS.includes(verb) ? " " + BUSY_LINE : "");

/** The zod form of a page verb's parameters (the JSON Schema forms the page uses: objects closed, strings with their
 * lengths and pattern, integers with their minimum, arrays of integers with their item counts, booleans). */
export function zodFor(params) {
  const field = (s) => {
    let t;
    if (s.type === "string") {
      t = z.string();
      if (s.minLength !== undefined) t = t.min(s.minLength);
      if (s.maxLength !== undefined) t = t.max(s.maxLength);
      if (s.pattern !== undefined) t = t.regex(new RegExp(s.pattern));
    } else if (s.type === "integer") {
      t = z.number().int();
      if (s.minimum !== undefined) t = t.min(s.minimum);
    } else if (s.type === "boolean") {
      t = z.boolean();
    } else if (s.type === "array" && s.items?.type === "integer") {
      t = z.array(field(s.items));
      if (s.minItems !== undefined) t = t.min(s.minItems);
      if (s.maxItems !== undefined) t = t.max(s.maxItems);
    } else throw new Error(`a parameter form these tools don't know: ${JSON.stringify(s)}`);
    return s.description !== undefined ? t.describe(s.description) : t;
  };
  const required = new Set(params.required ?? []);
  const shape = Object.fromEntries(Object.entries(params.properties ?? {}).map(([k, s]) => [k, required.has(k) ? field(s) : field(s).optional()]));
  return z.object(shape).strict();
}

const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
/** Whether `s` is strict base64 whose bytes begin with the PNG signature (its format only: the image isn't decoded, only
 * its first 12 characters). */
export function isPng(s) {
  if (typeof s !== "string" || s.length < 12 || !BASE64.test(s)) return false;
  const head = Buffer.from(s.slice(0, 12), "base64");
  return PNG.every((b, i) => head[i] === b);
}

/** latex_build's answer for the model: refused whole past 256 KiB or 4 pages; else each page a PNG image block (or its
 * line, if it isn't one), and the answer as text with each page's n, w and h only. */
export function latexContent(r) {
  const obj = !!r && typeof r === "object" && !Array.isArray(r);
  if (Buffer.byteLength(JSON.stringify(r) ?? "") > RESULT_MAX || (obj && "pages" in r && (!Array.isArray(r.pages) || r.pages.length > PAGES_MAX))) {
    return { content: [{ type: "text", text: PAGE_TEXT.tooLarge }], isError: true };
  }
  const pages = obj && Array.isArray(r.pages) ? r.pages : [];
  const blocks = [];
  for (const p of pages) {
    if (isPng(p?.png)) blocks.push({ type: "image", data: p.png, mimeType: "image/png" });
    else blocks.push({ type: "text", text: PAGE_TEXT.notPng(p?.n) });
  }
  const text = obj && "pages" in r ? { ...r, pages: pages.map((p) => ({ n: p?.n, w: p?.w, h: p?.h })) } : r;
  return { content: [{ type: "text", text: JSON.stringify(text) }, ...blocks] };
}
