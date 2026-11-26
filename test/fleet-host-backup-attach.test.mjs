// Host backup, delta attach-d3: `host backup attach [--discard]` over real temporary state and secrets directories and
// a fake repository (its key slots, opened by the password in host.key): the input's closed shape, the refusals, the
// phases, a crash at every durable step, the probe (only open_failed runs add-key again), --discard, and the secrets.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";
import { CODE_KEY, DEST, HANDLE, HOST_KEY, JOURNAL, NEW_KEY, attach, backupAttachCommand, checkInput, parseInput } from "../lib/fleet/host/backup-attach.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const CODE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const input = () => ({ v: 1, dest: { type: "s3", endpoint: "https://s3.example.com", bucket: "b-1", prefix: "host/x", region: "us-east-1" },
  credential: { access_key_id: "AKIDEXAMPLE", secret_access_key: "s3cr3t-value" }, backup_code: CODE });
const rand = () => Buffer.alloc(32, 7);
const NEW = `${Buffer.alloc(32, 7).toString("base64url")}\n`;

/**
 * A world: <base>/backup/state and <base>/host-secrets, and the repository's slots (the code's at first). The binary
 * opens the repository with host.key's first line; `faults` (an op's queue of results) override its answers in order;
 * `commitThenFail` makes the next add-key commit the slot, then report failure (a lost response).
 */
function world() {
  const base = mkdtempSync(join(tmpdir(), "sb-attach-"));
  mkdirSync(join(base, "backup"), { mode: 0o700 });
  chmodSync(join(base, "backup"), 0o700);
  const state = join(base, "backup", "state");
  const secrets = join(base, "host-secrets");
  const repo = { slots: [CODE], calls: [], faults: { snapshots: [], "add-key": [] }, commitThenFail: false };
  const pw = (f) => { try { return readFileSync(f, "utf8").split("\n")[0]; } catch { return null; } };
  const binary = async (req) => {
    repo.calls.push(req.op);
    const fault = repo.faults[req.op].shift();
    if (fault) return fault;
    if (!repo.slots.includes(pw(join(state, HOST_KEY)))) return { ok: false, code: "open_failed" };
    if (req.op === "snapshots") return { ok: true, value: { snapshots: [] } };
    repo.slots.push(pw(req.password_file));
    if (repo.commitThenFail) { repo.commitThenFail = false; return { ok: false, code: "timed_out" }; }
    return { ok: true, value: {} };
  };
  const deps = { binary, enabled: () => false, restoreOpen: () => false };
  const opts = (more = {}) => ({ state, secrets, uid: UID, rand, ...more });
  return { base, state, secrets, repo, deps, opts };
}

/** Every file under the state and secrets directories, by name relative to the base, with its bytes and mode. */
function files(w) {
  const out = {};
  const go = (dir, rel) => {
    for (const n of readdirSync(dir).sort()) {
      const p = join(dir, n), r = `${rel}/${n}`;
      const st = lstatSync(p);
      if (st.isDirectory()) go(p, r);
      else if (st.isSymbolicLink()) out[r] = { link: fs.readlinkSync(p) };
      else out[r] = { bytes: readFileSync(p), mode: st.mode & 0o7777 };
    }
  };
  for (const [d, r] of [[w.state, "state"], [w.secrets, "secrets"]]) if (existsSync(d)) go(d, r);
  return out;
}
const journal = (w) => JSON.parse(readFileSync(join(w.state, JOURNAL), "utf8"));

/** Attached: exactly the three files and the credential, 0600; host.key the one new slot's; the code in no file. */
function assertAttached(w) {
  const f = files(w);
  assert.deepEqual(Object.keys(f), [`state/${JOURNAL}`, `state/${DEST}`, `state/${HOST_KEY}`, `secrets/${HANDLE}`]);
  for (const v of Object.values(f)) assert.equal(v.mode, 0o600);
  assert.deepEqual(journal(w), { v: 1, phase: "attached" });
  assert.equal(f[`state/${HOST_KEY}`].bytes.toString(), NEW);
  assert.deepEqual(w.repo.slots, [CODE, NEW.trim()], "exactly one new slot");
  for (const [name, v] of Object.entries(f)) assert.equal(v.bytes.includes(CODE), false, `the code's bytes aren't in ${name}`);
  assert.equal(existsSync(join(w.base, "backup", "enabled")), false, "enabled is never written");
  const d = JSON.parse(f[`state/${DEST}`].bytes);
  assert.deepEqual(d, { type: "s3", endpoint: "https://s3.example.com", bucket: "b-1", prefix: "host/x", region: "us-east-1", credential: { secret: HANDLE } });
  assert.deepEqual(JSON.parse(f[`secrets/${HANDLE}`].bytes), input().credential);
}

test("the input's closed shape: each field missing, extra or malformed refuses (bad_form); one JSON object, bounded", () => {
  assert.deepEqual(checkInput(input()), input());
  // The destination's own rules are the binary's: an IPv6 endpoint with a port passes here.
  const v6 = input();
  v6.dest.endpoint = "https://[2001:db8::1]:8443";
  assert.deepEqual(checkInput(v6), v6);
  const bad = [
    (x) => { delete x.v; }, (x) => { x.v = 2; }, (x) => { x.extra = 1; }, (x) => { delete x.dest; }, (x) => { delete x.credential; }, (x) => { delete x.backup_code; },
    (x) => { x.dest.type = "b2"; }, (x) => { x.dest.extra = 1; }, (x) => { delete x.dest.region; }, (x) => { x.dest.endpoint = "http://s3.example.com"; },
    (x) => { x.dest.endpoint = "https://a\tb"; }, (x) => { x.dest.bucket = ""; }, (x) => { x.dest.bucket = "b".repeat(64); }, (x) => { x.dest.prefix = "a\nb"; },
    (x) => { x.dest.region = "r".repeat(65); }, (x) => { x.dest.region = 1; }, (x) => { x.credential.access_key_id = "a\u007f"; },
    (x) => { x.credential.extra = 1; }, (x) => { x.credential.access_key_id = ""; }, (x) => { x.credential.secret_access_key = 5; },
    (x) => { x.backup_code = CODE.toLowerCase(); }, (x) => { x.backup_code = CODE.slice(1); }, (x) => { x.backup_code = `${CODE}\n`; }, (x) => { x.backup_code = "ABCDEFGHIJKLMNOPQRSTUVWXY1"; },
  ];
  for (const f of bad) { const x = input(); f(x); refused(() => checkInput(x), "bad_form"); }
  assert.deepEqual(parseInput(Buffer.from(JSON.stringify(input()))), input());
  refused(() => parseInput(Buffer.from("not json")), "bad_form");
  refused(() => parseInput(Buffer.from("[]")), "bad_form");
  refused(() => parseInput(Buffer.alloc(64 * 1024 + 1, 0x20)), "bad_form");
  // A valid object, padded past the bound: refused for its size alone.
  const padded = `${JSON.stringify(input())}${" ".repeat(64 * 1024)}`;
  refused(() => parseInput(Buffer.from(padded)), "bad_form");
  assert.deepEqual(parseInput(Buffer.from(padded.slice(0, 64 * 1024))), input());
});

test("success: the code opens the repository, one new slot is added and promoted; exactly attach's files remain, the code in none", async () => {
  const w = world();
  assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true });
  assertAttached(w);
  assert.deepEqual(w.repo.calls, ["snapshots", "add-key", "snapshots"]);
  for (const d of [w.state, w.secrets]) assert.equal(lstatSync(d).mode & 0o7777, 0o700);
  // Attached is terminal: attach again refuses (in_progress), nothing changed.
  const before = files(w);
  await rejects(attach(input(), w.deps, w.opts()), "in_progress");
  assert.deepEqual(files(w), before);
});

test("refusals before any write: enabled (or not a plain no), an open restore, a path present without its journal, a link, a private directory that isn't", async () => {
  for (const [what, change] of [["enabled", (w) => { w.deps.enabled = () => true; }], ["unsure", (w) => { w.deps.enabled = () => undefined; }],
    ["a restore", (w) => { w.deps.restoreOpen = () => true; }]]) {
    const w = world();
    change(w);
    await rejects(attach(input(), w.deps, w.opts()), "in_progress");
    assert.equal(existsSync(w.state), false, `${what}: nothing written`);
    assert.deepEqual(w.repo.calls, []);
  }
  for (const name of [`state/${DEST}`, `state/${HOST_KEY}`, `state/${NEW_KEY}`, `state/${CODE_KEY}`, `secrets/${HANDLE}`]) {
    for (const kind of ["file", "link"]) {
      const w = world();
      for (const d of [w.state, w.secrets]) { mkdirSync(d, { mode: 0o700 }); chmodSync(d, 0o700); }
      const p = join(w.base, name.startsWith("state/") ? "backup" : "", name.replace(/^secrets\//, "host-secrets/"));
      if (kind === "file") writeFileSync(p, "x", { mode: 0o600 }); else symlinkSync("/etc/passwd", p);
      const before = files(w);
      await rejects(attach(input(), w.deps, w.opts()), "not_granted");
      assert.deepEqual(files(w), before, `${name} (${kind}): nothing written or removed`);
      assert.deepEqual(w.repo.calls, []);
    }
  }
  // The journal itself a link, or malformed: refused, nothing changed.
  const text = (j) => (p) => writeFileSync(p, `${JSON.stringify(j)}\n`, { mode: 0o600 });
  for (const [plant, code] of [[(p) => symlinkSync("/etc/passwd", p), "not_granted"], [(p) => { writeFileSync(p, "{\"v\":1,\"phase\":\"begun\"}\n"); chmodSync(p, 0o644); }, "not_granted"],
    [text({ v: 1, phase: "nope" }), "bad_form"], [text({ v: 1, phase: "probing" }), "bad_form"], [text({ v: 1, phase: "probing", swap: "sideways" }), "bad_form"],
    [text({ v: 1, phase: "begun", swap: "back" }), "bad_form"], [text({ v: 2, phase: "begun" }), "bad_form"], [(p) => writeFileSync(p, "{", { mode: 0o600 }), "bad_form"]]) {
    const w = world();
    mkdirSync(w.state, { mode: 0o700 });
    chmodSync(w.state, 0o700);
    plant(join(w.state, JOURNAL));
    const before = files(w);
    await rejects(attach(input(), w.deps, w.opts()), code);
    assert.deepEqual(w.repo.calls, []);
    if (code === "bad_form") assert.deepEqual(files(w), before, "nothing changed");
  }
  // A state directory that isn't private.
  const w = world();
  mkdirSync(w.state, { mode: 0o755 });
  chmodSync(w.state, 0o755);
  await rejects(attach(input(), w.deps, w.opts()), "not_granted");
  assert.deepEqual(readdirSync(w.state), []);
});

test("a wrong code (and any failure of the first open): every attach path removed, refused with the binary's code, no add-key", async () => {
  for (const fault of [{ ok: false, code: "open_failed" }, { ok: false, code: "destination_unavailable" }, { ok: false, code: "timed_out" }, { ok: false, code: "config_invalid" }, { ok: false, code: "destination_refused" }]) {
    const w = world();
    w.repo.faults.snapshots.push(fault);
    await rejects(attach(input(), w.deps, w.opts()), fault.code);
    assert.deepEqual(files(w), {});
    assert.deepEqual(w.repo.calls, ["snapshots"]);
    assert.deepEqual(w.repo.slots, [CODE]);
    // The person can attach again from nothing.
    assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true });
    assertAttached(w);
  }
});

/** An io that crashes (throws) at its `k`th open or rename: a crash at every durable step. */
function crashingIo(k) {
  let n = 0;
  const tick = () => { n += 1; if (n === k) throw Object.assign(new Error("crash"), { code: "ECRASH" }); };
  return { ...realIo, open: (...a) => { tick(); return realIo.open(...a); }, rename: (...a) => { tick(); return realIo.rename(...a); } };
}

test("a crash at every durable step, with add-key committed or not: the next attach ends attached with exactly one new slot, never a second add-key after a commit", async () => {
  let steps = 0;
  for (let k = 1; ; k += 1) {
    const w = world();
    let crashed = false;
    try { await attach(input(), w.deps, w.opts({ io: crashingIo(k) })); } catch (e) { if (e?.code !== "ECRASH") throw e; crashed = true; }
    if (!crashed) break;
    steps += 1;
    const committed = w.repo.slots.length === 2;
    const adds = w.repo.calls.filter((c) => c === "add-key").length;
    // A crash after `attached` was renamed into place (its directory's fsync): attach had finished, so a rerun refuses.
    if (existsSync(join(w.state, JOURNAL)) && journal(w).phase === "attached") await rejects(attach(input(), w.deps, w.opts()), "in_progress");
    else assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true }, `crash at ${k}`);
    assertAttached(w);
    if (committed) assert.equal(w.repo.calls.filter((c) => c === "add-key").length, adds, `crash at ${k}: no second add-key after a commit`);
  }
  assert.ok(steps >= 20, `every durable step crashed once (${steps})`);
});

test("remote commit, response lost: recovery probes the new key, which opens; no second add-key", async () => {
  const w = world();
  w.repo.commitThenFail = true;
  await rejects(attach(input(), w.deps, w.opts()), "timed_out");
  assert.deepEqual(journal(w), { v: 1, phase: "slot-pending" });
  assert.equal(w.repo.slots.length, 2);
  w.repo.calls.length = 0;
  assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true });
  assertAttached(w);
  assert.deepEqual(w.repo.calls, ["snapshots", "snapshots"], "the probe, then the final open; no add-key");
});

test("add-key not committed: the probe is open_failed, so the keys swap back and add-key runs exactly once", async () => {
  const w = world();
  w.repo.faults["add-key"].push({ ok: false, code: "timed_out" });
  await rejects(attach(input(), w.deps, w.opts()), "timed_out");
  assert.deepEqual(w.repo.slots, [CODE]);
  w.repo.calls.length = 0;
  assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true });
  assertAttached(w);
  assert.deepEqual(w.repo.calls, ["snapshots", "add-key", "snapshots"]);
});

test("the probe: only open_failed runs add-key; every other code stays probing with both secrets, runs no add-key, and refuses", async () => {
  const OTHERS = ["destination_unavailable", "timed_out", "spawn_failed", "bad_result", "aborted", "repository_missing", "config_invalid", "add_key_failed", undefined];
  for (const committed of [true, false]) {
    for (const code of OTHERS) {
      const w = world();
      if (committed) w.repo.commitThenFail = true; else w.repo.faults["add-key"].push({ ok: false, code: "timed_out" });
      await rejects(attach(input(), w.deps, w.opts()), "timed_out");
      // The probe answers `code` (twice: two runs stay probing).
      for (let run = 0; run < 2; run += 1) {
        w.repo.faults.snapshots.push({ ok: false, code });
        w.repo.calls.length = 0;
        await rejects(attach(input(), w.deps, w.opts()), code ?? "outcome_unknown");
        assert.deepEqual(w.repo.calls, ["snapshots"], `${code}: the probe only, no add-key`);
        assert.deepEqual(journal(w), { v: 1, phase: "probing", swap: "forward" });
        assert.equal(readFileSync(join(w.state, HOST_KEY), "utf8"), NEW, "the new key in host.key");
        assert.equal(readFileSync(join(w.state, CODE_KEY), "utf8"), `${CODE}\n`, "the code kept for a swap back");
        assert.equal(existsSync(join(w.state, NEW_KEY)), false);
      }
      // A later run's probe decides: committed opens (no add-key); uncommitted is open_failed (add-key once).
      w.repo.calls.length = 0;
      assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true });
      assertAttached(w);
      assert.deepEqual(w.repo.calls, committed ? ["snapshots", "snapshots"] : ["snapshots", "add-key", "snapshots"], `${code}, committed ${committed}`);
    }
  }
});

test("a crash mid-swap in probing is finished in the journal's direction", async () => {
  // Forward: host.key moved to attach-code.key, attach-new.key not yet moved.
  {
    const w = world();
    w.repo.commitThenFail = true;
    await rejects(attach(input(), w.deps, w.opts()), "timed_out");
    writeFileSync(join(w.state, JOURNAL), `${JSON.stringify({ v: 1, phase: "probing", swap: "forward" })}\n`);
    fs.renameSync(join(w.state, HOST_KEY), join(w.state, CODE_KEY));
    w.repo.calls.length = 0;
    assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true });
    assertAttached(w);
    assert.deepEqual(w.repo.calls, ["snapshots", "snapshots"]);
  }
  // Back (after an open_failed probe): host.key (new) moved back to attach-new.key, the code not yet in host.key.
  {
    const w = world();
    w.repo.faults["add-key"].push({ ok: false, code: "timed_out" });
    await rejects(attach(input(), w.deps, w.opts()), "timed_out");
    fs.renameSync(join(w.state, HOST_KEY), join(w.state, CODE_KEY));
    writeFileSync(join(w.state, JOURNAL), `${JSON.stringify({ v: 1, phase: "probing", swap: "back" })}\n`);
    w.repo.calls.length = 0;
    assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true });
    assertAttached(w);
    assert.deepEqual(w.repo.calls, ["add-key", "snapshots"], "the back swap finished, then add-key once");
  }
});

test("--discard: allowed and complete at begun; refused (nothing removed) at every later phase, with no journal, and after success", async () => {
  // begun: the files written, the first open never answered (a crash).
  {
    const w = world();
    w.repo.faults.snapshots.push(null);
    w.deps.binary = async () => { throw Object.assign(new Error("crash"), { code: "ECRASH" }); };
    await assert.rejects(attach(input(), w.deps, w.opts()));
    assert.deepEqual(journal(w), { v: 1, phase: "begun" });
    assert.deepEqual(await attach(null, w.deps, w.opts({ discard: true })), { discarded: true });
    assert.deepEqual(files(w), {});
  }
  // begun with the destination not attach's (another handle), or absent: refused.
  for (const dest of [null, JSON.stringify({ credential: { secret: "other" } })]) {
    const w = world();
    w.deps.binary = async () => { throw Object.assign(new Error("crash"), { code: "ECRASH" }); };
    await assert.rejects(attach(input(), w.deps, w.opts()));
    if (dest === null) fs.unlinkSync(join(w.state, DEST)); else writeFileSync(join(w.state, DEST), dest);
    const before = files(w);
    await rejects(attach(null, w.deps, w.opts({ discard: true })), "not_granted");
    assert.deepEqual(files(w), before);
  }
  // slot-pending, probing, promoting.
  for (const phase of ["slot-pending", "probing", "promoting"]) {
    const w = world();
    w.repo.commitThenFail = true;
    await rejects(attach(input(), w.deps, w.opts()), "timed_out");
    writeFileSync(join(w.state, JOURNAL), `${JSON.stringify(phase === "probing" ? { v: 1, phase, swap: "forward" } : { v: 1, phase })}\n`);
    const before = files(w);
    await rejects(attach(null, w.deps, w.opts({ discard: true })), "not_granted");
    assert.deepEqual(files(w), before, phase);
  }
  // No journal, attach's files present.
  {
    const w = world();
    await attach(input(), w.deps, w.opts());
    fs.unlinkSync(join(w.state, JOURNAL));
    const before = files(w);
    await rejects(attach(null, w.deps, w.opts({ discard: true })), "not_granted");
    assert.deepEqual(files(w), before);
  }
  // Success, then --discard: refused, every file intact.
  {
    const w = world();
    await attach(input(), w.deps, w.opts());
    const before = files(w);
    await rejects(attach(null, w.deps, w.opts({ discard: true })), "not_granted");
    assert.deepEqual(files(w), before);
    assertAttached(w);
  }
});

test("the command line: argument errors are 2; not root refused; the input only from stdin; one line of codes, never the code or a secret", async () => {
  const w = world();
  const run = (argv, more = {}) => backupAttachCommand(argv, { uid: () => UID, rootUid: UID, state: w.state, secrets: w.secrets, rand,
    stdin: async () => Buffer.from(JSON.stringify(input())), exclusion: { path: join(w.base, "backup", "lock"), uid: UID }, ...w.deps, ...more });
  for (const argv of [[], ["attach", "x"], ["attach", "--discard", "x"], ["detach"], ["attach", CODE]]) assert.equal((await run(argv)).code, 2);
  assert.deepEqual(await run(["attach"], { uid: () => UID + 1 }), { code: 1, line: { v: 1, refused: "not_granted" } });
  assert.deepEqual(await run(["attach"], { stdin: async () => Buffer.from("{}") }), { code: 1, line: { v: 1, refused: "bad_form" } });
  w.repo.faults.snapshots.push({ ok: false, code: "open_failed" });
  const wrong = await run(["attach"]);
  assert.deepEqual(wrong, { code: 1, line: { v: 1, refused: "open_failed" } });
  const ok = await run(["attach"]);
  assert.deepEqual(ok, { code: 0, line: { v: 1, attached: true } });
  for (const out of [wrong, ok]) for (const s of [CODE, "s3cr3t-value", "AKIDEXAMPLE", w.base]) assert.equal(JSON.stringify(out).includes(s), false);
  assertAttached(w);
  assert.deepEqual(await run(["attach", "--discard"]), { code: 1, line: { v: 1, refused: "not_granted" } });
});

test("the entrypoint: `sagebrush-agent host backup` dispatches through host-main (usage 2; a non-root caller refused, stdin unread)", { skip: UID === 0 }, () => {
  const bin = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
  const usage = spawnSync(process.execPath, [bin, "host", "backup"], { encoding: "utf8" });
  assert.equal(usage.status, 2);
  assert.match(usage.stderr, /usage: sagebrush-agent host backup attach \[--discard\]/);
  const st = spawnSync(process.execPath, [bin, "host", "backup", "attach"], { encoding: "utf8", input: JSON.stringify(input()) });
  assert.deepEqual([st.status, st.stdout], [1, '{"v":1,"refused":"not_granted"}\n']);
});

test("the probe opens but the final open doesn't: promoting is durable first, so the next run never swaps the new key away", async () => {
  const w = world();
  w.repo.commitThenFail = true;
  await rejects(attach(input(), w.deps, w.opts()), "timed_out");
  w.repo.faults.snapshots.push(null, { ok: false, code: "destination_unavailable" }); // (the probe opens; the final open fails)
  await rejects(attach(input(), w.deps, w.opts()), "destination_unavailable");
  assert.deepEqual(journal(w), { v: 1, phase: "promoting" });
  assert.equal(readFileSync(join(w.state, HOST_KEY), "utf8"), NEW);
  w.repo.calls.length = 0;
  assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true });
  assertAttached(w);
  assert.deepEqual(w.repo.calls, ["snapshots"]);
});

test("a crash at every durable step of RECOVERY (both a committed and an uncommitted add-key): the next attach ends attached, the code's file gone", async () => {
  for (const committed of [true, false]) {
    let steps = 0;
    for (let k = 1; ; k += 1) {
      const w = world();
      if (committed) w.repo.commitThenFail = true; else w.repo.faults["add-key"].push({ ok: false, code: "timed_out" });
      await rejects(attach(input(), w.deps, w.opts()), "timed_out");
      let crashed = false;
      try { await attach(input(), w.deps, w.opts({ io: crashingIo(k) })); } catch (e) { if (e?.code !== "ECRASH") throw e; crashed = true; }
      if (!crashed) break;
      steps += 1;
      if (journal(w).phase === "attached") await rejects(attach(input(), w.deps, w.opts()), "in_progress");
      else assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true }, `committed ${committed}, crash at ${k}`);
      assertAttached(w);
    }
    assert.ok(steps >= 8, `committed ${committed}: every recovery step crashed once (${steps})`);
  }
});

test("begun's recovery removes the crashed attempt's files: a corrected input is attached, not refused as another file", async () => {
  const w = world();
  const real = w.deps.binary;
  w.deps.binary = async () => { throw Object.assign(new Error("crash"), { code: "ECRASH" }); };
  await assert.rejects(attach(input(), w.deps, w.opts()));
  assert.deepEqual(journal(w), { v: 1, phase: "begun" });
  w.deps.binary = real;
  const fixed = input();
  fixed.credential.secret_access_key = "a-corrected-secret";
  assert.deepEqual(await attach(fixed, w.deps, w.opts()), { attached: true });
  assert.deepEqual(JSON.parse(readFileSync(join(w.secrets, HANDLE), "utf8")), fixed.credential);
});

test("recovery over a planted link or a file of another mode: not_granted, nothing renamed or removed", async () => {
  for (const name of [NEW_KEY, HOST_KEY, CODE_KEY]) {
    for (const kind of ["link", "mode"]) {
      const w = world();
      w.repo.commitThenFail = true;
      await rejects(attach(input(), w.deps, w.opts()), "timed_out");
      const p = join(w.state, name);
      if (existsSync(p)) fs.unlinkSync(p);
      if (kind === "link") symlinkSync(join(w.base, "outside"), p); else { writeFileSync(p, "x\n"); chmodSync(p, 0o644); }
      const before = files(w);
      const calls = w.repo.calls.length;
      await rejects(attach(input(), w.deps, w.opts()), "not_granted");
      assert.deepEqual(files(w), before, `${name} (${kind})`);
      assert.equal(w.repo.calls.length, calls, "nothing run");
    }
  }
});

test("the command holds the backup/restore exclusion: held by another, attach is busy and writes nothing", async () => {
  const w = world();
  const { withExclusion } = await import("../lib/fleet/host/restore-begin.mjs");
  const exclusion = { path: join(w.base, "backup", "lock"), uid: UID, waitMs: 0 };
  const out = await withExclusion(() => backupAttachCommand(["attach"], { uid: () => UID, rootUid: UID, state: w.state, secrets: w.secrets, rand,
    stdin: async () => Buffer.from(JSON.stringify(input())), exclusion, ...w.deps }), exclusion);
  assert.deepEqual(out, { code: 1, line: { v: 1, refused: "in_progress" } });
  assert.equal(existsSync(w.state), false);
  assert.deepEqual(w.repo.calls, []);
});

/** Kill the flock child holding `path` (the command's real exclusion), then let its death be seen. */
function killHolder(path) {
  let n = 0;
  for (const pid of readdirSync("/proc").filter((p) => /^[0-9]+$/.test(p))) {
    let cmd;
    try { cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0"); } catch { continue; }
    if (cmd[0].endsWith("flock") && cmd.includes(path)) { process.kill(Number(pid), "SIGKILL"); n += 1; }
  }
  assert.ok(n > 0, `a holder of ${path} was found`);
}
const settle = () => new Promise((r) => { setTimeout(r, 200); });

// The exclusion lost INSIDE each awaited binary call (the call itself then answering normally): outcome_unknown, no
// later binary call or effect, the journal kept at its phase; the next attach recovers to exactly one new slot.
for (const [where, prepare, callIndex, phase] of [
  ["the first open", () => {}, 0, "begun"],
  ["add-key", () => {}, 1, "slot-pending"],
  ["the probe", (w) => { w.repo.commitThenFail = true; }, 0, "probing"],
  ["the final open", () => {}, 2, "promoting"],
]) {
  test(`the exclusion lost inside ${where}: outcome_unknown, nothing after it, the journal kept (${phase}); the next attach recovers`, async () => {
    const w = world();
    const exclusion = { path: join(w.base, "backup", "attach.lock"), uid: UID, waitMs: 0 };
    const cmd = () => backupAttachCommand(["attach"], { uid: () => UID, rootUid: UID, state: w.state, secrets: w.secrets, rand,
      stdin: async () => Buffer.from(JSON.stringify(input())), exclusion, ...w.deps });
    prepare(w);
    if (where === "the probe") assert.deepEqual(await cmd(), { code: 1, line: { v: 1, refused: "timed_out" } }); // (add-key committed, its answer lost)
    const real = w.deps.binary;
    let n = 0;
    w.deps.binary = async (req, o) => {
      const r = await real(req, o);
      if (n++ === callIndex) { killHolder(exclusion.path); await settle(); }
      return r;
    };
    w.repo.calls.length = 0;
    const before = w.repo.slots.length;
    assert.deepEqual(await cmd(), { code: 1, line: { v: 1, refused: "outcome_unknown" } });
    assert.equal(w.repo.calls.length, callIndex + 1, `${where}: no binary call after it`);
    assert.deepEqual(journal(w).phase, phase, `${where}: the journal kept at ${phase}`);
    if (where === "the first open" || where === "add-key") assert.equal(w.repo.calls.filter((c) => c === "add-key").length, where === "add-key" ? 1 : 0);
    assert.ok(w.repo.slots.length <= before + 1);
    // A later attach (the exclusion free again) recovers, never adding a second slot.
    w.deps.binary = real;
    assert.deepEqual(await cmd(), { code: 0, line: { v: 1, attached: true } });
    assertAttached(w);
  });
}

test("each guard layer alone: after a binary call (a transient probe answer, no effect after it) and before an effect (a back swap's second rename)", async () => {
  // The lock lost inside the probe, which answers destination_unavailable: no effect follows it, so only the check right
  // after the binary call reports the loss (outcome_unknown, not the probe's code).
  {
    const w = world();
    w.repo.commitThenFail = true;
    await rejects(attach(input(), w.deps, w.opts()), "timed_out");
    let lost = false;
    const guard = () => { if (lost) throw new FleetError("outcome_unknown", "lost"); };
    w.repo.faults.snapshots.push({ ok: false, code: "destination_unavailable" });
    const real = w.deps.binary;
    w.deps.binary = async (req, o) => { const r = await real(req, o); lost = true; return r; };
    await rejects(attach(input(), w.deps, w.opts({ guard })), "outcome_unknown");
    assert.deepEqual(journal(w), { v: 1, phase: "probing", swap: "forward" });
  }
  // The lock lost at the back swap's first rename (after an open_failed probe): the second rename and the journal's
  // slot-pending never happen; the next run finishes the swap in the journal's direction and runs add-key once.
  {
    const w = world();
    w.repo.faults["add-key"].push({ ok: false, code: "timed_out" });
    await rejects(attach(input(), w.deps, w.opts()), "timed_out");
    let lost = false, renames = 0;
    const guard = () => { if (lost) throw new FleetError("outcome_unknown", "lost"); };
    const io = { ...realIo, rename: (a, b) => { realIo.rename(a, b); if (b.endsWith(JOURNAL)) return; renames += 1; if (renames === 3) lost = true; } }; // (keys only: 2 forward, then the first back)
    await rejects(attach(input(), w.deps, w.opts({ guard, io })), "outcome_unknown");
    assert.equal(renames, 3, "no rename after the loss");
    assert.deepEqual(journal(w), { v: 1, phase: "probing", swap: "back" });
    w.repo.calls.length = 0;
    assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true });
    assertAttached(w);
    assert.deepEqual(w.repo.calls, ["add-key", "snapshots"]);
  }
});

test("each effect checks the lock first: lost right after the previous effect, nothing more is written or removed", async () => {
  const lostGuard = () => { const g = { lost: false }; g.guard = () => { if (g.lost) throw new FleetError("outcome_unknown", "lost"); }; return g; };
  // A journal write: lost at the back swap's second rename; the journal stays `probing` (back), never slot-pending.
  {
    const w = world();
    w.repo.faults["add-key"].push({ ok: false, code: "timed_out" });
    await rejects(attach(input(), w.deps, w.opts()), "timed_out");
    const g = lostGuard();
    let renames = 0;
    const io = { ...realIo, rename: (a, b) => { realIo.rename(a, b); if (b.endsWith(JOURNAL)) return; renames += 1; if (renames === 4) g.lost = true; } };
    await rejects(attach(input(), w.deps, w.opts({ guard: g.guard, io })), "outcome_unknown");
    assert.deepEqual(journal(w), { v: 1, phase: "probing", swap: "back" });
  }
  // An exclusive write: lost once `begun` is durable; no destination, credential or key is written.
  {
    const w = world();
    const g = lostGuard();
    const io = { ...realIo, rename: (a, b) => { realIo.rename(a, b); if (b.endsWith(JOURNAL)) g.lost = true; } };
    await rejects(attach(input(), w.deps, w.opts({ guard: g.guard, io })), "outcome_unknown");
    assert.deepEqual(Object.keys(files(w)), [`state/${JOURNAL}`]);
    assert.deepEqual(w.repo.calls, []);
  }
  // A removal: a wrong code's cleanup, lost after its first removal; the journal and the rest stay for the next run.
  {
    const w = world();
    w.repo.faults.snapshots.push({ ok: false, code: "open_failed" });
    const g = lostGuard();
    const fsx = { ...fs, unlinkSync: (p) => { fs.unlinkSync(p); g.lost = true; } };
    await rejects(attach(input(), w.deps, w.opts({ guard: g.guard, fsx })), "outcome_unknown");
    assert.deepEqual(Object.keys(files(w)), [`state/${JOURNAL}`, `state/${DEST}`, `secrets/${HANDLE}`]);
    assert.deepEqual(journal(w), { v: 1, phase: "begun" });
    assert.deepEqual(await attach(input(), w.deps, w.opts()), { attached: true });
    assertAttached(w);
  }
});
