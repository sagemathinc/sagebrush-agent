// Fleet protocol, the browser relay (design agent-autonomous-browser-relay.md r2.1 §2, §5): the relay's durable state,
// one SQLite file (WAL, synchronous=FULL), written only by the relay process.
// - consumed: host-open nonces, app request ids and commit authorizations, each kept until its own absolute expiry by
//   the wall clock (so a restart never re-admits one), then pruned. Host nonces and commit authorizations are signed
//   requests whose timestamp is within 5 minutes: CONSUMED_MS. An app request id has no timestamp: the service keeps
//   it for its record's acceptance window (service.mjs);
// - the feed's cursor (a safe integer), which only moves forward and survives a restart; the one way back is reset(),
//   on the Worker's signed cursor_expired refusal, after every slot has been closed.
// Every write throws on failure; the caller refuses (fail closed).

import { DatabaseSync } from "node:sqlite";

/** How long a consumed id is kept: the window an open, request id or authorization can be replayed in. */
export const CONSUMED_MS = 600_000;

const KINDS = new Set(["host", "app", "commit"]);

/** Open (or create) the store at `path` (":memory:" for tests that don't restart). */
export function openStore(path) {
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
  db.exec("CREATE TABLE IF NOT EXISTS consumed (id TEXT PRIMARY KEY, expires INTEGER NOT NULL) STRICT;");
  db.exec("CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v INTEGER NOT NULL) STRICT;");
  const insert = db.prepare("INSERT OR IGNORE INTO consumed (id, expires) VALUES (?, ?)");
  const has = db.prepare("SELECT 1 AS x FROM consumed WHERE id = ?");
  const countAll = db.prepare("SELECT COUNT(*) AS n FROM consumed");
  const prune = db.prepare("DELETE FROM consumed WHERE expires <= ?");
  const getCursor = db.prepare("SELECT v FROM state WHERE k = 'cursor'");
  const dropCursor = db.prepare("DELETE FROM state WHERE k = 'cursor'");
  const putCursor = db.prepare("INSERT INTO state (k, v) VALUES ('cursor', ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v WHERE excluded.v > state.v");
  return {
    /** Consume `id` of `kind` at wall time `now`, kept until `until` (default now + CONSUMED_MS): true if it was new. */
    consume(kind, id, now, until = now + CONSUMED_MS) {
      if (!KINDS.has(kind) || typeof id !== "string" || id === "") throw new Error("a consumed id needs its kind and value");
      if (!Number.isSafeInteger(until) || until <= now) throw new Error("a consumed id's expiry is after now");
      return insert.run(`${kind}:${id}`, until).changes === 1; // (one insert wins: duplicates that both verified get false)
    },
    /** How many ids are kept (the storage bound's measure). */
    count() { return Number(countAll.get().n); },
    /** Whether `id` of `kind` was consumed (without consuming it). */
    consumed(kind, id) { return has.get(`${kind}:${id}`) !== undefined; },
    /** Delete consumed ids whose window has passed. */
    prune(now) { prune.run(now); },
    /** The feed's committed cursor, or -1 before the first success. */
    cursor() { const row = getCursor.get(); return row ? Number(row.v) : -1; },
    /** Commit a cursor; true only if it moved forward (a cursor never goes back). */
    advance(cursor) {
      if (!Number.isSafeInteger(cursor) || cursor < 0) throw new Error("a cursor is a non-negative safe integer");
      return putCursor.run(cursor).changes === 1;
    },
    /** Forget the cursor (the next poll starts from since=0): only on the Worker's signed cursor_expired. */
    reset() { dropCursor.run(); },
    close() { db.close(); },
  };
}
