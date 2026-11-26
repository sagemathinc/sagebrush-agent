// Host backup, init-run d6 §1, §2, §7 (rows 1-11): `host backup init [--discard]` over real temporary directories, a
// fake repository with real key slots (opened by the password in host.key), the real unit installer over a temporary
// unit directory, a fake terminal, and (row 10) a real pseudo-terminal.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";
import { backupEnabled, backupUnits } from "../lib/fleet/host/backup-scheduler.mjs";
import { CODE_KEY, DEST, HANDLE, HOST_KEY, JOURNAL, SWAP_KEY, backupInitCommand, checkInput, groupsOf, init, newCode, parseInput, realUnits } from "../lib/fleet/host/backup-init.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1; // (Linux-only rows; off Linux the file only loads)
const RELEASE = "/opt/sagebrush-agent";
const rand = (n) => Buffer.alloc(n, 7);
const HOSTPW = rand(32).toString("base64url");
const CODE = newCode(rand);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const input = () => ({ v: 1, dest: { type: "s3", endpoint: "https://s3.example.com", bucket: "b-1", prefix: "host/x", region: "us-east-1" },
  credential: { access_key_id: "AKIDEXAMPLE", secret_access_key: "s3cr3t-value" } });
const crash = () => Object.assign(new Error("crash"), { code: "ECRASH" });

/** The code as a terminal shows it (its groups joined by hyphens, indented on its own line), from a transcript. */
const shownCode = (text) => text.match(/\n {4}([A-Z2-7]{5}(?:-[A-Z2-7]{5}){3}-[A-Z2-7]{6})\r?\n/)?.[1].replaceAll("-", "") ?? null;

/** A terminal: it records what is written; each ask answers from `answers` ("right", "wrong" or null), else right. */
function fakeTty() {
  const t = { text: "", asks: 0, answers: [] };
  t.write = (s) => { t.text += s; };
  t.ask = async (prompt) => {
    t.text += prompt;
    t.asks += 1;
    const a = t.answers.length > 0 ? t.answers.shift() : "right";
    if (a === null) return null;
    const g = groupsOf(shownCode(t.text));
    const [x, y] = prompt.match(/group (\d) and group (\d)/).slice(1).map(Number);
    return a === "right" ? `${g[x - 1].toLowerCase()}-${g[y - 1]}` : `${g[y - 1]} ${g[x - 1]}`;
  };
  return t;
}

/**
 * A world: <base>/backup (absent: a fresh host), its state, <base>/host-secrets, a unit directory, and the
 * repository: absent until `init`, then its slots. The binary opens it with host.key's first line. `faults` (an op's
 * queue of results) override its answers in order; `lose[op]` makes the next such op commit, then report failure.
 */
function world() {
  const base = mkdtempSync(join(tmpdir(), "sb-init-"));
  const backup = join(base, "backup"), state = join(backup, "state"), secrets = join(base, "host-secrets"), unitDir = join(base, "units");
  mkdirSync(unitDir);
  const repo = { exists: false, slots: [], calls: [], faults: { init: [], snapshots: [], "add-key": [] }, lose: {} };
  const pw = (f) => { try { return readFileSync(f, "utf8").split("\n")[0]; } catch { return null; } };
  const binary = async (req) => {
    repo.calls.push(req.op);
    const fault = repo.faults[req.op].shift();
    if (fault) return fault;
    const key = pw(join(state, HOST_KEY));
    if (req.op === "init") {
      if (repo.exists) return { ok: false, code: "repository_exists" };
      repo.exists = true;
      repo.slots = [key];
    } else if (!repo.exists) return { ok: false, code: "repository_missing" };
    else if (!repo.slots.includes(key)) return { ok: false, code: "open_failed" };
    else if (req.op === "snapshots") return { ok: true, value: { snapshots: [] } };
    else repo.slots.push(pw(req.password_file));
    if (repo.lose[req.op]) { repo.lose[req.op] = false; return { ok: false, code: "timed_out" }; }
    return { ok: true, value: {} };
  };
  const systemctl = [];
  const units = realUnits({ dir: unitDir, rootUid: UID, run: async (argv) => { systemctl.push(argv.join(" ")); return { code: 0 }; } });
  const tty = fakeTty();
  const deps = { binary, enabled: () => backupEnabled({ dir: backup, rootUid: UID }).enabled !== false, restoreOpen: () => false, tty, units };
  const opts = (more = {}) => ({ state, secrets, uid: UID, rand, release: RELEASE, ...more });
  return { base, backup, state, secrets, unitDir, repo, systemctl, tty, deps, opts };
}

/** Every entry under the base (directories too), with its mode and a file's bytes: "nothing written" compares these. */
function tree(w) {
  const out = {};
  const go = (dir, rel) => {
    for (const n of readdirSync(dir).sort()) {
      const p = join(dir, n), r = rel ? `${rel}/${n}` : n;
      const st = lstatSync(p);
      if (st.isDirectory()) { out[r] = { dir: st.mode & 0o7777 }; go(p, r); } else if (st.isSymbolicLink()) out[r] = { link: fs.readlinkSync(p) };
      else out[r] = { bytes: readFileSync(p).toString("base64"), mode: st.mode & 0o7777, ino: st.ino };
    }
  };
  go(w.base, "");
  return out;
}
/** Init's files (under backup and the secrets), relative to the base. */
const initFiles = (w) => Object.keys(tree(w)).filter((k) => (k.startsWith("backup/") || k.startsWith("host-secrets/")) && !tree(w)[k].dir);
const journal = (w) => JSON.parse(readFileSync(join(w.state, JOURNAL), "utf8"));
const ops = (w, op) => w.repo.calls.filter((c) => c === op).length;

/** Initialized (row 1): exactly §2's files less the code's and the swap's, root 0600; two slots; enabled; the units. */
function assertInitialized(w) {
  const t = tree(w);
  assert.deepEqual(initFiles(w), ["backup/enabled", `backup/state/${DEST}`, `backup/state/${HOST_KEY}`, `backup/state/${JOURNAL}`, `host-secrets/${HANDLE}`]);
  for (const k of initFiles(w)) assert.equal(t[k].mode, 0o600, k);
  for (const d of ["backup", "backup/state", "host-secrets"]) assert.equal(t[d].dir, 0o700, d);
  assert.equal(t["backup/enabled"].bytes, "");
  assert.deepEqual(journal(w), { v: 1, phase: "initialized" });
  assert.equal(readFileSync(join(w.state, HOST_KEY), "utf8"), `${HOSTPW}\n`);
  assert.deepEqual(w.repo.slots, [HOSTPW, CODE], "exactly two slots: host.key's and the code's");
  assert.deepEqual(JSON.parse(readFileSync(join(w.state, DEST), "utf8")),
    { type: "s3", endpoint: "https://s3.example.com", bucket: "b-1", prefix: "host/x", region: "us-east-1", credential: { secret: HANDLE } });
  assert.deepEqual(JSON.parse(readFileSync(join(w.secrets, HANDLE), "utf8")), input().credential);
  const u = backupUnits(RELEASE);
  for (const [name, text] of [[u.names.service, u.service], [u.names.timer, u.timer]]) {
    assert.equal(readFileSync(join(w.unitDir, name), "utf8"), text, `${name} byte-equal`);
    assert.equal(lstatSync(join(w.unitDir, name)).mode & 0o7777, 0o644);
  }
  assert.deepEqual(w.systemctl.slice(-2), ["systemctl daemon-reload", "systemctl enable --now sagebrush-backup.timer"]);
  assert.equal(backupEnabled({ dir: w.backup, rootUid: UID }).enabled, true);
  // The code's bytes are in no file left anywhere under the base.
  for (const [k, v] of Object.entries(t)) if (v.bytes) assert.equal(Buffer.from(v.bytes, "base64").includes(CODE), false, `the code isn't in ${k}`);
}

test("the input's closed shape and the code's: attach's input without the code; 26 characters of [A-Z2-7] in groups of 5,5,5,5,6", () => {
  assert.deepEqual(checkInput(input()), input());
  for (const f of [(x) => { x.backup_code = CODE; }, (x) => { x.v = 2; }, (x) => { delete x.credential; }, (x) => { x.dest.endpoint = "http://x"; }, (x) => { x.credential.extra = 1; }]) {
    const x = input(); f(x); refused(() => checkInput(x), "bad_form");
  }
  refused(() => parseInput(Buffer.from("[")), "bad_form");
  refused(() => parseInput(Buffer.alloc(64 * 1024 + 1, 0x20)), "bad_form");
  assert.match(CODE, /^[A-Z2-7]{26}$/);
  for (let i = 0; i < 50; i += 1) assert.match(newCode(), /^[A-Z2-7]{26}$/);
  // 130 bits: every bit of the first 16 bytes and 2 of the 17th reach the code (a flipped bit changes it).
  for (let bit = 0; bit < 130; bit += 1) {
    const b = Buffer.alloc(17);
    b[bit >> 3] |= 0x80 >> (bit & 7);
    assert.notEqual(newCode(() => b), newCode(() => Buffer.alloc(17)), `bit ${bit}`);
  }
  assert.deepEqual(groupsOf(CODE).map((g) => g.length), [5, 5, 5, 5, 6]);
  assert.equal(groupsOf(CODE).join(""), CODE);
});

test("row 1, the happy path: init, the host slot, the code's slot, shown and confirmed, enabled, the units; exactly init's files, the code in none", async () => {
  const w = world();
  assert.deepEqual(await init(input(), w.deps, w.opts()), { initialized: true });
  assertInitialized(w);
  assert.deepEqual(w.repo.calls, ["init", "add-key"]);
  assert.equal(shownCode(w.tty.text), CODE, "the code was shown on the terminal");
  assert.match(w.tty.text, /\x1b\[2J/, "and cleared once confirmed");
  // Initialized is terminal: init again refuses, nothing changed.
  const before = tree(w);
  await rejects(init(input(), w.deps, w.opts()), "in_progress");
  assert.deepEqual(tree(w), before);
});

test("row 2, refusals before any write: each leaves the tree byte-identical and calls no binary", async () => {
  const cases = {
    "no terminal": (w) => { w.deps.tty = null; },
    "enabled (the scheduler's answer)": (w) => { w.deps.enabled = () => true; },
    "an enabled file alone": (w) => { mkdirSync(w.backup, { mode: 0o700 }); chmodSync(w.backup, 0o700); writeFileSync(join(w.backup, "enabled"), "", { mode: 0o600 }); },
    "an open restore": (w) => { w.deps.restoreOpen = () => true; },
    "restoreOpen not a plain no": (w) => { w.deps.restoreOpen = () => null; },
    "an attach journal": (w) => { mkdirSync(w.state, { recursive: true, mode: 0o700 }); chmodSync(w.backup, 0o700); chmodSync(w.state, 0o700); writeFileSync(join(w.state, "attach.json"), "{}", { mode: 0o600 }); },
    "an init path without its journal": (w) => { mkdirSync(w.state, { recursive: true, mode: 0o700 }); chmodSync(w.backup, 0o700); chmodSync(w.state, 0o700); writeFileSync(join(w.state, HOST_KEY), "x\n", { mode: 0o600 }); },
    "the credential without its journal": (w) => { mkdirSync(w.secrets, { mode: 0o700 }); chmodSync(w.secrets, 0o700); writeFileSync(join(w.secrets, HANDLE), "{}", { mode: 0o600 }); },
    "an init path that is a link": (w) => { mkdirSync(w.state, { recursive: true, mode: 0o700 }); chmodSync(w.backup, 0o700); chmodSync(w.state, 0o700); symlinkSync("/etc/hostname", join(w.state, CODE_KEY)); },
    "an init path of another mode": (w) => { mkdirSync(w.state, { recursive: true, mode: 0o700 }); chmodSync(w.backup, 0o700); chmodSync(w.state, 0o700); writeFileSync(join(w.state, JOURNAL), '{"v":1,"phase":"begun"}\n', { mode: 0o644 }); chmodSync(join(w.state, JOURNAL), 0o644); },
    "a directory of another mode": (w) => { mkdirSync(w.backup, { mode: 0o755 }); chmodSync(w.backup, 0o755); },
    "the secrets directory a link": (w) => { mkdirSync(join(w.base, "elsewhere"), { mode: 0o700 }); symlinkSync(join(w.base, "elsewhere"), w.secrets); },
  };
  const codes = {};
  for (const [what, set] of Object.entries(cases)) {
    const w = world();
    set(w);
    const before = tree(w);
    await assert.rejects(init(input(), w.deps, w.opts()), (e) => { codes[what] = e.code; return e instanceof FleetError; }, what);
    assert.deepEqual(tree(w), before, `${what}: nothing written`);
    assert.deepEqual(w.repo.calls, [], `${what}: no binary call`);
    assert.equal(w.tty.text, "", `${what}: nothing shown`);
  }
  assert.deepEqual(codes, {
    "no terminal": "not_granted", "enabled (the scheduler's answer)": "in_progress", "an enabled file alone": "in_progress", "an open restore": "in_progress",
    "restoreOpen not a plain no": "in_progress", "an attach journal": "not_granted", "an init path without its journal": "not_granted",
    "the credential without its journal": "not_granted", "an init path that is a link": "not_granted", "an init path of another mode": "not_granted",
    "a directory of another mode": "not_granted", "the secrets directory a link": "not_granted",
  });
});

/** An io that throws at its k-th open or rename. */
function crashingIo(k) {
  let n = 0;
  const tick = () => { n += 1; if (n === k) throw crash(); };
  return { ...realIo, open: (...a) => { tick(); return realIo.open(...a); }, rename: (...a) => { tick(); return realIo.rename(...a); } };
}
/** Run `f`, which may crash (ECRASH); true when it did. */
async function crashes(f) { try { await f(); return false; } catch (e) { if (e?.code !== "ECRASH") throw e; return true; } }

test("row 3, a crash at every durable step: the next init ends initialized with exactly two slots, never a third, never a second init after a commit", async () => {
  let steps = 0;
  for (let k = 1; ; k += 1) {
    const w = world();
    if (!(await crashes(() => init(input(), w.deps, w.opts({ io: crashingIo(k) }))))) break;
    steps += 1;
    const committed = w.repo.exists;
    if (existsSync(join(w.state, JOURNAL)) && journal(w).phase === "initialized") await rejects(init(input(), w.deps, w.opts()), "in_progress");
    else assert.deepEqual(await init(input(), w.deps, w.opts()), { initialized: true }, `crash at ${k}`);
    assertInitialized(w);
    if (committed) assert.equal(ops(w, "init"), 1, `crash at ${k}: no second init after a commit`);
    assert.ok(ops(w, "add-key") <= 2, `crash at ${k}`);
  }
  assert.ok(steps >= 25, `every durable step crashed once (${steps})`);
});

test("row 3, recovery's own steps: a crash at every durable step of a repo or a code-slot recovery; the next init ends initialized", async () => {
  for (const setup of ["repo: init uncommitted", "repo: init committed, lost", "code-slot: add-key uncommitted", "code-slot: add-key committed, lost"]) {
    let steps = 0;
    for (let k = 1; ; k += 1) {
      const w = world();
      if (setup === "repo: init uncommitted") w.repo.faults.init.push({ ok: false, code: "destination_unavailable" });
      if (setup === "repo: init committed, lost") w.repo.lose.init = true;
      if (setup === "code-slot: add-key uncommitted") w.repo.faults["add-key"].push({ ok: false, code: "destination_unavailable" });
      if (setup === "code-slot: add-key committed, lost") w.repo.lose["add-key"] = true;
      await assert.rejects(init(input(), w.deps, w.opts()));
      if (!(await crashes(() => init(null, w.deps, w.opts({ io: crashingIo(k) }))))) { assertInitialized(w); break; }
      steps += 1;
      if (journal(w).phase === "initialized") await rejects(init(null, w.deps, w.opts()), "in_progress");
      else assert.deepEqual(await init(null, w.deps, w.opts()), { initialized: true }, `${setup}: crash at ${k}`);
      assertInitialized(w);
      assert.equal(existsSync(join(w.state, SWAP_KEY)), false);
    }
    assert.ok(steps >= 8, `${setup}: every step crashed once (${steps})`);
  }
});

test("row 4, repo's probe: committed with its response lost advances with no second init; uncommitted runs init once", async () => {
  {
    const w = world();
    w.repo.lose.init = true;
    await rejects(init(input(), w.deps, w.opts()), "timed_out");
    assert.deepEqual(journal(w), { v: 1, phase: "repo", attempt: 1 });
    w.repo.calls.length = 0;
    assert.deepEqual(await init(null, w.deps, w.opts()), { initialized: true });
    assert.deepEqual(w.repo.calls, ["snapshots", "snapshots", "add-key"], "the probe opened: no init; then the code-slot's own probe and add-key");
    assertInitialized(w);
  }
  {
    const w = world();
    w.repo.faults.init.push({ ok: false, code: "destination_unavailable" });
    await rejects(init(input(), w.deps, w.opts()), "destination_unavailable");
    w.repo.calls.length = 0;
    assert.deepEqual(await init(null, w.deps, w.opts()), { initialized: true });
    assert.deepEqual(w.repo.calls, ["snapshots", "init", "add-key"], "repository_missing: init exactly once");
    assertInitialized(w);
  }
});

test("row 4, repo's probe: open_failed (a repository host.key doesn't open) refuses not_granted, every path kept; inconclusive answers keep everything twice, then the next run decides", async () => {
  {
    const w = world();
    w.repo.faults.init.push({ ok: false, code: "destination_unavailable" });
    await rejects(init(input(), w.deps, w.opts()), "destination_unavailable");
    Object.assign(w.repo, { exists: true, slots: ["someone else's"] });
    const before = tree(w);
    w.repo.calls.length = 0;
    await rejects(init(null, w.deps, w.opts()), "not_granted");
    assert.deepEqual(tree(w), before, "every path kept");
    assert.deepEqual(w.repo.calls, ["snapshots"], "no init");
    assert.deepEqual(w.repo.slots, ["someone else's"]);
  }
  for (const code of ["destination_unavailable", "timed_out", "spawn_failed", "bad_result", "aborted"]) {
    const w = world();
    w.repo.faults.init.push({ ok: false, code: "destination_unavailable" });
    await rejects(init(input(), w.deps, w.opts()), "destination_unavailable");
    const before = tree(w);
    for (let i = 0; i < 2; i += 1) {
      w.repo.faults.snapshots.push({ ok: false, code });
      w.repo.calls.length = 0;
      await rejects(init(null, w.deps, w.opts()), code === "aborted" ? "outcome_unknown" : code); // (a signal's `aborted`: reported unknown)
      assert.deepEqual(w.repo.calls, ["snapshots"], `${code}: no init`);
      assert.deepEqual(tree(w), before, `${code}: the phase and the keys kept`);
    }
    assert.deepEqual(await init(null, w.deps, w.opts()), { initialized: true });
    assertInitialized(w);
  }
});

test("row 5, a first init answering repository_exists: not_granted, init's paths removed, the repository untouched", async () => {
  const w = world();
  Object.assign(w.repo, { exists: true, slots: ["someone else's"] });
  await rejects(init(input(), w.deps, w.opts()), "not_granted");
  assert.deepEqual(initFiles(w), [], "every init path removed, the journal included");
  assert.deepEqual(w.repo.calls, ["init"]);
  assert.deepEqual(w.repo.slots, ["someone else's"]);
  assert.equal(w.tty.text, "");
  // The control: in row 4's committed case, an init repeated by recovery WOULD answer repository_exists, and this
  // first-run rule would then delete a live host.key. Recovery from `repo` therefore probes and never re-inits.
  const c = world();
  c.repo.lose.init = true;
  await rejects(init(input(), c.deps, c.opts()), "timed_out");
  assert.deepEqual(await c.deps.binary({ op: "init" }), { ok: false, code: "repository_exists" });
  c.repo.calls.length = 0;
  assert.deepEqual(await init(null, c.deps, c.opts()), { initialized: true });
  assert.equal(c.repo.calls.includes("init"), false);
  assertInitialized(c);
});

test("row 6, code-slot's probe: it opens, no add-key; open_failed, exactly one; anything else keeps the phase, no add-key", async () => {
  {
    const w = world();
    w.repo.lose["add-key"] = true;
    await rejects(init(input(), w.deps, w.opts()), "timed_out");
    assert.deepEqual(journal(w), { v: 1, phase: "code-slot" });
    w.repo.calls.length = 0;
    assert.deepEqual(await init(null, w.deps, w.opts()), { initialized: true });
    assert.deepEqual(w.repo.calls, ["snapshots"], "the code opens: no add-key");
    assertInitialized(w);
  }
  {
    const w = world();
    w.repo.faults["add-key"].push({ ok: false, code: "destination_unavailable" });
    await rejects(init(input(), w.deps, w.opts()), "destination_unavailable");
    w.repo.calls.length = 0;
    assert.deepEqual(await init(null, w.deps, w.opts()), { initialized: true });
    assert.deepEqual(w.repo.calls, ["snapshots", "add-key"], "open_failed: add-key once");
    assertInitialized(w);
  }
  for (const code of ["destination_unavailable", "timed_out", "spawn_failed", "bad_result", "repository_missing"]) {
    const w = world();
    w.repo.faults["add-key"].push({ ok: false, code: "destination_unavailable" });
    await rejects(init(input(), w.deps, w.opts()), "destination_unavailable");
    const before = tree(w);
    w.repo.faults.snapshots.push({ ok: false, code });
    w.repo.calls.length = 0;
    await rejects(init(null, w.deps, w.opts()), code);
    assert.deepEqual(w.repo.calls, ["snapshots"], `${code}: no add-key`);
    assert.deepEqual(journal(w), { v: 1, phase: "code-slot" });
    assert.equal(readFileSync(join(w.state, HOST_KEY), "utf8"), `${HOSTPW}\n`, `${code}: host.key the host password again`);
    assert.equal(existsSync(join(w.state, SWAP_KEY)), false);
    const after = tree(w);
    for (const k of Object.keys(before)) if (!k.endsWith(JOURNAL) && !k.endsWith(HOST_KEY)) assert.deepEqual(after[k], before[k], `${code}: ${k} kept`);
  }
});

test("row 6, a crash mid-swap is finished in the journal's direction; host.key is the host password after", async () => {
  for (const dir of ["forward", "back"]) {
    for (const at of ["after the first rename", "after the code is written"]) {
      const w = world();
      w.repo.faults["add-key"].push({ ok: false, code: "destination_unavailable" });
      await rejects(init(input(), w.deps, w.opts()), "destination_unavailable");
      // Leave the swap as a crash would: host.key moved aside, and (or not) the code written in its place.
      writeFileSync(join(w.state, JOURNAL), `${JSON.stringify({ v: 1, phase: "code-slot", swap: dir })}\n`, { mode: 0o600 });
      fs.renameSync(join(w.state, HOST_KEY), join(w.state, SWAP_KEY));
      if (at === "after the code is written") writeFileSync(join(w.state, HOST_KEY), `${CODE}\n`, { mode: 0o600 });
      w.repo.calls.length = 0;
      assert.deepEqual(await init(null, w.deps, w.opts()), { initialized: true }, `${dir}, ${at}`);
      assert.deepEqual(w.repo.calls, ["snapshots", "add-key"]);
      assertInitialized(w);
    }
  }
});

test("row 7, shown: an interrupt before confirmation shows the SAME code next time; a wrong group asks again", async () => {
  const w = world();
  w.tty.answers.push("wrong", null);
  await rejects(init(input(), w.deps, w.opts()), "in_progress");
  assert.deepEqual(journal(w), { v: 1, phase: "shown" });
  assert.equal(w.tty.asks, 2, "a wrong group asked again");
  assert.match(w.tty.text, /doesn't match/);
  assert.equal(shownCode(w.tty.text), CODE);
  assert.equal(readFileSync(join(w.state, CODE_KEY), "utf8"), `${CODE}\n`, "the code kept on the host until confirmed");
  w.tty.text = "";
  w.repo.calls.length = 0;
  assert.deepEqual(await init(null, w.deps, w.opts()), { initialized: true });
  assert.equal(shownCode(w.tty.text), CODE, "the same code, shown again");
  assert.deepEqual(w.repo.calls, [], "no repository op to show it again");
  assertInitialized(w);
});

test("row 8, --discard: from begun, and from repo after repository_missing or open_failed; refused (nothing removed) everywhere else", async () => {
  // From begun: a crash with the begun files written.
  {
    let w;
    for (let k = 1; ; k += 1) {
      w = world();
      await crashes(() => init(input(), w.deps, w.opts({ io: crashingIo(k) })));
      if (existsSync(join(w.state, CODE_KEY)) && journal(w).phase === "begun") break;
    }
    assert.deepEqual(await init(null, w.deps, w.opts({ discard: true })), { discarded: true });
    assert.deepEqual(initFiles(w), []);
    assert.deepEqual(w.repo.calls, []);
  }
  // From repo: the probe answers repository_missing, or open_failed.
  for (const answer of ["repository_missing", "open_failed"]) {
    const w = world();
    w.repo.faults.init.push({ ok: false, code: "destination_unavailable" });
    await rejects(init(input(), w.deps, w.opts()), "destination_unavailable");
    if (answer === "open_failed") Object.assign(w.repo, { exists: true, slots: ["someone else's"] });
    assert.deepEqual(await init(null, w.deps, w.opts({ discard: true })), { discarded: true }, answer);
    assert.deepEqual(initFiles(w), []);
  }
  // Refused: repo whose probe opens or is inconclusive, code-slot, shown, confirmed, initialized, no journal.
  const at = {
    "repo, the probe opens": (w) => { w.repo.lose.init = true; },
    "repo, the probe inconclusive": (w) => { w.repo.faults.init.push({ ok: false, code: "destination_unavailable" }); w.after = () => w.repo.faults.snapshots.push({ ok: false, code: "timed_out" }); },
    "code-slot": (w) => { w.repo.faults["add-key"].push({ ok: false, code: "destination_unavailable" }); },
    shown: (w) => { w.tty.answers.push(null); },
    confirmed: (w) => { let once = true; const u = w.deps.units; w.deps.units = async (x) => { if (once) { once = false; throw crash(); } return u(x); }; },
    initialized: () => {},
  };
  for (const [what, set] of Object.entries(at)) {
    const w = world();
    set(w);
    await init(input(), w.deps, w.opts()).catch(() => {});
    w.after?.();
    const before = tree(w);
    await rejects(init(null, w.deps, w.opts({ discard: true })), what === "initialized" ? "in_progress" : "not_granted");
    assert.deepEqual(tree(w), before, `${what}: nothing removed`);
  }
  const none = world();
  await rejects(init(null, none.deps, none.opts({ discard: true })), "not_granted");
  assert.deepEqual(tree(none), { units: { dir: lstatSync(none.unitDir).mode & 0o7777 } });
});

test("row 11 (T1), a confirmed init's own enable: admitted past its own enabled; nothing written twice; any other enabled refuses", async () => {
  // A crash after enabled is written, before the units: the next init is admitted and finishes.
  {
    const w = world();
    let once = true;
    const u = w.deps.units;
    w.deps.units = async (x) => { if (once) { once = false; throw crash(); } return u(x); };
    assert.equal(await crashes(() => init(input(), w.deps, w.opts())), true);
    assert.deepEqual(journal(w), { v: 1, phase: "confirmed" });
    assert.equal(w.deps.enabled(), true, "enabled already");
    const ino = lstatSync(join(w.backup, "enabled")).ino;
    assert.deepEqual(await init(null, w.deps, w.opts()), { initialized: true });
    assert.equal(lstatSync(join(w.backup, "enabled")).ino, ino, "enabled not written again");
    assertInitialized(w);
  }
  // A crash after the timer is enabled, before `initialized`: the same, the unit files not rewritten.
  {
    const w = world();
    const io = { ...realIo, open: (p, ...a) => { if (String(p).includes(`.${JOURNAL}.`) && w.systemctl.length === 2) throw crash(); return realIo.open(p, ...a); } };
    assert.equal(await crashes(() => init(input(), w.deps, w.opts({ io }))), true);
    assert.deepEqual(journal(w), { v: 1, phase: "confirmed" });
    const inos = readdirSync(w.unitDir).map((n) => lstatSync(join(w.unitDir, n)).ino);
    assert.deepEqual(await init(null, w.deps, w.opts()), { initialized: true });
    assert.deepEqual(readdirSync(w.unitDir).map((n) => lstatSync(join(w.unitDir, n)).ino), inos, "the units not rewritten");
    assertInitialized(w);
    await rejects(init(input(), w.deps, w.opts()), "in_progress");
  }
  // An enabled file with a journal in any phase but confirmed: refused, nothing written.
  for (const phase of ["begun", "code-slot", "shown"]) {
    const w = world();
    mkdirSync(w.state, { recursive: true, mode: 0o700 });
    chmodSync(w.backup, 0o700);
    chmodSync(w.state, 0o700);
    writeFileSync(join(w.state, JOURNAL), `${JSON.stringify({ v: 1, phase })}\n`, { mode: 0o600 });
    writeFileSync(join(w.backup, "enabled"), "", { mode: 0o600 });
    const before = tree(w);
    await rejects(init(input(), w.deps, w.opts()), "in_progress");
    assert.deepEqual(tree(w), before, phase);
  }
});

// ---- the command, its exclusion and its guard (row 9) ----

const cmdDeps = (w, more = {}) => ({ uid: () => UID, rootUid: UID, state: w.state, secrets: w.secrets, rand, release: RELEASE,
  stdin: async () => Buffer.from(JSON.stringify(input())), exclusion: { path: join(w.base, "init.lock"), uid: UID, waitMs: 0 }, ...w.deps, ...more });

test("the command line: argument errors are 2; not root refused; a resume reads no input; one line of codes, never the code or a secret on stdout or stderr", async () => {
  const w = world();
  for (const argv of [[], ["init", "x"], ["init", "--discard", "x"], ["init", "--force"], ["nope"]]) assert.equal((await backupInitCommand(argv, cmdDeps(w))).code, 2, JSON.stringify(argv));
  assert.deepEqual(await backupInitCommand(["init"], cmdDeps(w, { uid: () => UID + 1 })), { code: 1, line: { v: 1, refused: "not_granted" } });
  assert.deepEqual(await backupInitCommand(["init"], cmdDeps(w, { stdin: async () => Buffer.from("{}") })), { code: 1, line: { v: 1, refused: "bad_form" } });
  assert.deepEqual(await backupInitCommand(["init"], cmdDeps(w, { stdin: async () => Buffer.alloc(0) })), { code: 1, line: { v: 1, refused: "bad_form" } }, "a fresh init needs its input");
  assert.deepEqual(Object.keys(tree(w)).filter((k) => k !== "init.lock"), ["units"], "nothing written by any of them (but the exclusion's own lock file)");
  const printed = [];
  const [o, e] = [process.stdout.write, process.stderr.write];
  process.stdout.write = (s, ...a) => { printed.push(String(s)); return o.call(process.stdout, s, ...a); };
  process.stderr.write = (s, ...a) => { printed.push(String(s)); return e.call(process.stderr, s, ...a); };
  let lines;
  try {
    w.tty.answers.push(null);
    const first = await backupInitCommand(["init"], cmdDeps(w));
    const resumed = await backupInitCommand(["init"], cmdDeps(w, { stdin: async () => Buffer.alloc(0) }));
    lines = [first, resumed];
  } finally { process.stdout.write = o; process.stderr.write = e; }
  assert.deepEqual(lines, [{ code: 1, line: { v: 1, refused: "in_progress" } }, { code: 0, line: { v: 1, initialized: true } }]);
  for (const s of [CODE, ...groupsOf(CODE), HOSTPW, "s3cr3t-value", "AKIDEXAMPLE", w.base]) {
    assert.equal(JSON.stringify(lines).includes(s), false, "not in a line");
    assert.equal(printed.join("").includes(s), false, "not on stdout or stderr");
  }
  assertInitialized(w);
  assert.deepEqual(await backupInitCommand(["init", "--discard"], cmdDeps(w)), { code: 1, line: { v: 1, refused: "in_progress" } });
});

test("the entrypoint: `sagebrush-agent host backup init` dispatches through host-main (usage 2 names init; a non-root caller refused)", { skip: UID === 0 }, () => {
  const bin = fileURLToPath(new URL("../bin/sagebrush-agent.mjs", import.meta.url));
  const usage = spawnSync(process.execPath, [bin, "host", "backup", "init", "x"], { encoding: "utf8" });
  assert.equal(usage.status, 2);
  assert.match(usage.stderr, /^usage: sagebrush-agent host backup attach \[--discard\] \| backup init \[--discard\]/);
  const st = spawnSync(process.execPath, [bin, "host", "backup", "init"], { encoding: "utf8", input: JSON.stringify(input()) });
  assert.deepEqual([st.status, st.stdout], [1, '{"v":1,"refused":"not_granted"}\n']);
});

test("the command holds the backup/restore exclusion: held by another, init is busy and writes nothing", async () => {
  const w = world();
  const { withExclusion } = await import("../lib/fleet/host/restore-begin.mjs");
  const d = cmdDeps(w);
  assert.deepEqual(await withExclusion(() => backupInitCommand(["init"], d), d.exclusion), { code: 1, line: { v: 1, refused: "in_progress" } });
  assert.equal(existsSync(w.backup), false);
  assert.deepEqual(w.repo.calls, []);
});

/** Kill the flock child holding `path` (the command's real exclusion) and wait until it is dead. */
function killHolderNow(path) {
  const pids = [];
  for (const pid of readdirSync("/proc").filter((p) => /^[0-9]+$/.test(p))) {
    let cmd;
    try { cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0"); } catch { continue; }
    if (cmd[0].endsWith("flock") && cmd.includes(path)) { process.kill(Number(pid), "SIGKILL"); pids.push(pid); }
  }
  assert.ok(pids.length > 0, `a holder of ${path} was found`);
  // (its child inherited the locked file: killed too, so the lock is really free once this returns)
  for (const pid of readdirSync("/proc").filter((p) => /^[0-9]+$/.test(p))) {
    let st;
    try { st = readFileSync(`/proc/${pid}/stat`, "utf8"); } catch { continue; }
    if (pids.includes(st.slice(st.lastIndexOf(")") + 2).split(" ")[1])) { try { process.kill(Number(pid), "SIGKILL"); pids.push(pid); } catch { /* gone */ } }
  }
  const dead = (pid) => { try { return /\) [ZX] /.test(readFileSync(`/proc/${pid}/stat`, "utf8")); } catch { return true; } };
  const until = Date.now() + 5000;
  while (!pids.every(dead)) if (Date.now() > until) assert.fail("the holder didn't die");
}

// The exclusion lost INSIDE each awaited binary call (the call itself answering normally): outcome_unknown, no later
// binary call or effect, the journal kept at its phase; the next init recovers to exactly two slots.
for (const [where, prepare, callIndex, phase] of [
  ["init", () => {}, 0, { v: 1, phase: "repo", attempt: 1 }],
  ["add-key", () => {}, 1, { v: 1, phase: "code-slot" }],
  ["repo's probe", (w) => { w.repo.faults.init.push({ ok: false, code: "destination_unavailable" }); }, 0, { v: 1, phase: "repo", attempt: 1 }],
  ["code-slot's probe", (w) => { w.repo.faults["add-key"].push({ ok: false, code: "destination_unavailable" }); }, 0, { v: 1, phase: "code-slot", swap: "forward" }],
]) {
  test(`row 9, the exclusion lost inside ${where}: outcome_unknown, nothing after it, the journal kept; the next init recovers`, async () => {
    const w = world();
    const d = cmdDeps(w);
    prepare(w);
    if (where.endsWith("probe")) assert.deepEqual(await backupInitCommand(["init"], d), { code: 1, line: { v: 1, refused: "destination_unavailable" } });
    const real = w.deps.binary;
    let n = 0;
    const lossy = async (req, o) => { const r = await real(req, o); if (n++ === callIndex) killHolderNow(d.exclusion.path); return r; };
    w.repo.calls.length = 0;
    const before = w.repo.slots.length;
    assert.deepEqual(await backupInitCommand(["init"], { ...d, binary: lossy }), { code: 1, line: { v: 1, refused: "outcome_unknown" } });
    assert.equal(w.repo.calls.length, callIndex + 1, `${where}: no binary call after it`);
    assert.deepEqual(journal(w), phase, `${where}: the journal kept`);
    assert.ok(w.repo.slots.length <= Math.max(before, 1) + 1);
    assert.equal(w.tty.text, "", "nothing shown");
    assert.deepEqual(await backupInitCommand(["init"], d), { code: 0, line: { v: 1, initialized: true } });
    assertInitialized(w);
  });
}

for (const inside of ["enabled", "restoreOpen"]) {
  test(`row 9, the exclusion lost inside ${inside}: outcome_unknown, nothing inspected or created`, async () => {
    const w = world();
    const d = cmdDeps(w);
    const calls = [];
    const out = await backupInitCommand(["init"], { ...d,
      enabled: () => { calls.push("enabled"); if (inside === "enabled") killHolderNow(d.exclusion.path); return false; },
      restoreOpen: () => { calls.push("restoreOpen"); if (inside === "restoreOpen") killHolderNow(d.exclusion.path); return false; } });
    assert.deepEqual(out, { code: 1, line: { v: 1, refused: "outcome_unknown" } });
    assert.deepEqual(calls, inside === "enabled" ? ["enabled"] : ["enabled", "restoreOpen"]);
    assert.deepEqual(w.repo.calls, []);
    for (const p of [w.backup, w.secrets]) assert.equal(existsSync(p), false, `${p} not created`);
  });
}

test("row 9, each guard layer alone: on entry; right after a binary call with no effect after it; right before an effect", async () => {
  const lost = () => { throw new FleetError("outcome_unknown", "lost"); };
  {
    const w = world();
    const calls = [];
    await rejects(init(input(), { ...w.deps, enabled: () => { calls.push("enabled"); return false; } }, w.opts({ guard: lost })), "outcome_unknown");
    assert.deepEqual(calls, []);
  }
  // Lost inside repo's probe, which answers destination_unavailable (no effect follows it): only the check right after
  // the call reports the loss.
  {
    const w = world();
    w.repo.faults.init.push({ ok: false, code: "destination_unavailable" });
    await rejects(init(input(), w.deps, w.opts()), "destination_unavailable");
    let isLost = false;
    const guard = () => { if (isLost) lost(); };
    w.repo.faults.snapshots.push({ ok: false, code: "destination_unavailable" });
    const real = w.deps.binary;
    await rejects(init(null, { ...w.deps, binary: async (r, o) => { const x = await real(r, o); isLost = true; return x; } }, w.opts({ guard })), "outcome_unknown");
  }
  // Lost once `begun` is durable: no destination, credential or key is written, no binary call.
  {
    const w = world();
    let isLost = false;
    const guard = () => { if (isLost) lost(); };
    const io = { ...realIo, rename: (a, b) => { realIo.rename(a, b); if (b.endsWith(JOURNAL)) isLost = true; } };
    await rejects(init(input(), w.deps, w.opts({ guard, io })), "outcome_unknown");
    assert.deepEqual(initFiles(w), [`backup/state/${JOURNAL}`]);
    assert.deepEqual(w.repo.calls, []);
  }
  // Lost after the code is confirmed, before enabled: no enabled, no units.
  {
    const w = world();
    let isLost = false;
    const guard = () => { if (isLost) lost(); };
    const tty = { ...w.tty, ask: async (p) => { const a = await w.tty.ask(p); isLost = true; return a; } };
    await rejects(init(input(), { ...w.deps, tty }, w.opts({ guard })), "outcome_unknown");
    assert.deepEqual(journal(w), { v: 1, phase: "shown" });
    assert.equal(existsSync(join(w.backup, "enabled")), false);
    assert.deepEqual(w.systemctl, []);
  }
  // Lost while the terminal waits, the person then interrupting (no effect follows): the loss is what's reported.
  {
    const w = world();
    let isLost = false;
    const guard = () => { if (isLost) lost(); };
    w.tty.answers.push(null);
    const tty = { ...w.tty, ask: async (p) => { const a = await w.tty.ask(p); isLost = true; return a; } };
    await rejects(init(input(), { ...w.deps, tty }, w.opts({ guard })), "outcome_unknown");
    assert.deepEqual(journal(w), { v: 1, phase: "shown" });
  }
});

// ---- row 10: the terminal, through a real pseudo-terminal ----

const PTY = `import os, pty, re, sys, json
node, driver, base, mode = sys.argv[1:5]
pid, fd = pty.fork()
if pid == 0:
    os.dup2(0, 3)  # (the slave held open: with none open, the master would read EIO before node opens /dev/tty)
    for n, name, flags in ((0, "stdin", os.O_RDONLY), (1, "stdout", os.O_WRONLY | os.O_CREAT | os.O_TRUNC), (2, "stderr", os.O_WRONLY | os.O_CREAT | os.O_TRUNC)):
        os.dup2(os.open(os.path.join(base, name), flags, 0o600), n)
    os.execv(node, [node, driver, base])
out, answered = b"", False
while True:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    out += chunk
    text = out.decode("latin1")
    if not answered and "separated by a space: " in text:
        answered = True
        g = re.search(r"\\n {4}([A-Z2-7-]{30})\\r?\\n", text).group(1).split("-")
        a, b = map(int, re.search(r"group (\\d) and group (\\d)", text).groups())
        os.write(fd, b"\\x03" if mode == "interrupt" else f"{g[a - 1]} {g[b - 1]}\\n".encode())
_, status = os.waitpid(pid, 0)
sys.stdout.write(json.dumps({"tty": out.decode("latin1"), "exit": os.waitstatus_to_exitcode(status)}))
`;

/** The command as host-main runs it (the console's signals installed), its tty the real one; the repository a file. */
const driver = (repoUrl) => `import * as fs from "node:fs";
import { join } from "node:path";
import { backupInitCommand, realUnits } from "${repoUrl}lib/fleet/host/backup-init.mjs";
import { installCommandSignals } from "${repoUrl}lib/fleet/host/backup-binary.mjs";
const base = process.argv[2];
const state = join(base, "backup", "state"), uid = process.getuid();
const repoFile = join(base, "repo.json");
const load = () => { try { return JSON.parse(fs.readFileSync(repoFile, "utf8")); } catch { return null; } };
const pw = (f) => fs.readFileSync(f, "utf8").split("\\n")[0];
const binary = async (req) => {
  const slots = load();
  if (req.op === "init") { fs.writeFileSync(repoFile, JSON.stringify([pw(join(state, "host.key"))])); return { ok: true, value: {} }; }
  if (slots === null) return { ok: false, code: "repository_missing" };
  if (!slots.includes(pw(join(state, "host.key")))) return { ok: false, code: "open_failed" };
  if (req.op === "add-key") fs.writeFileSync(repoFile, JSON.stringify([...slots, pw(req.password_file)]));
  return { ok: true, value: req.op === "snapshots" ? { snapshots: [] } : {} };
};
installCommandSignals(new AbortController());
const out = await backupInitCommand(["init"], { uid: () => uid, rootUid: uid, state, secrets: join(base, "host-secrets"), release: "${RELEASE}",
  exclusion: { path: join(base, "init.lock"), uid, waitMs: 0 }, binary, enabled: () => false, restoreOpen: () => false,
  units: realUnits({ dir: join(base, "units"), rootUid: uid, run: async () => ({ code: 0 }) }) });
process.stdout.write(JSON.stringify(out.line) + "\\n");
process.exitCode = out.code;
`;

test("row 10, through a real pseudo-terminal: the code only on the terminal, a Ctrl-C at the prompt aborts (shown kept), the next run shows the same code and confirms", { skip: spawnSync("python3", ["-c", "import pty"]).status !== 0 }, () => {
  const base = mkdtempSync(join(tmpdir(), "sb-init-pty-"));
  const helpers = mkdtempSync(join(tmpdir(), "sb-init-pty-helpers-"));
  mkdirSync(join(base, "units"));
  writeFileSync(join(helpers, "pty.py"), PTY);
  writeFileSync(join(helpers, "driver.mjs"), driver(pathToFileURL(fileURLToPath(new URL("..", import.meta.url))).href.replace(/\/?$/, "/")));
  const run = (mode, stdin) => {
    writeFileSync(join(base, "stdin"), stdin);
    const r = spawnSync("python3", ["-I", join(helpers, "pty.py"), process.execPath, join(helpers, "driver.mjs"), base, mode], { encoding: "utf8", timeout: 60_000 });
    assert.equal(r.status, 0, r.stderr);
    return { ...JSON.parse(r.stdout), stdout: readFileSync(join(base, "stdout"), "utf8"), stderr: readFileSync(join(base, "stderr"), "utf8") };
  };
  const first = run("interrupt", JSON.stringify(input()));
  // The terminal's SIGINT reaches the whole foreground group: the command (its signal aborts the prompt) and the
  // exclusion's flock holder (the guard then sees the lock lost). Whichever is seen first names the refusal; either way
  // the code wasn't confirmed and the journal stays `shown`.
  assert.equal(first.exit, 1, first.stderr);
  assert.match(first.stdout, /^\{"v":1,"refused":"(in_progress|outcome_unknown)"\}\n$/);
  const code = shownCode(first.tty);
  assert.match(code ?? "", /^[A-Z2-7]{26}$/, "the code was shown on the terminal");
  assert.equal(JSON.parse(readFileSync(join(base, "backup", "state", JOURNAL), "utf8")).phase, "shown");
  const second = run("answer", "");
  assert.deepEqual([second.exit, second.stdout], [0, '{"v":1,"initialized":true}\n'], second.stderr);
  assert.equal(shownCode(second.tty), code, "the same code, shown again");
  assert.deepEqual(JSON.parse(readFileSync(join(base, "repo.json"), "utf8")).length, 2);
  assert.ok(JSON.parse(readFileSync(join(base, "repo.json"), "utf8")).includes(code), "the code opens the repository");
  for (const r of [first, second]) for (const s of [code, ...groupsOf(code)]) {
    assert.equal(r.stdout.includes(s), false, "never on stdout");
    assert.equal(r.stderr.includes(s), false, "never on stderr");
  }
  assert.equal(existsSync(join(base, "backup", "state", CODE_KEY)), false);
});

// ---- the guard inside the units' installation (TESTS T1 on the init PR) ----

test("row 9, the exclusion lost inside daemon-reload: no enable follows, the journal stays confirmed; the next init finishes", async () => {
  const w = world();
  const d = cmdDeps(w);
  let first = true;
  const units = realUnits({ dir: w.unitDir, rootUid: UID, run: async (argv) => {
    w.systemctl.push(argv.join(" "));
    if (argv[1] === "daemon-reload" && first) { first = false; killHolderNow(d.exclusion.path); }
    return { code: 0 };
  } });
  assert.deepEqual(await backupInitCommand(["init"], { ...d, units }), { code: 1, line: { v: 1, refused: "outcome_unknown" } });
  assert.deepEqual(w.systemctl, ["systemctl daemon-reload"], "no enable after the lost reload");
  assert.deepEqual(journal(w), { v: 1, phase: "confirmed" });
  assert.deepEqual(await backupInitCommand(["init"], { ...d, units }), { code: 0, line: { v: 1, initialized: true } });
  assertInitialized(w);
});

test("the units' guard, each layer alone: lost after the service file is written (no timer file, no systemctl), after the timer file (no reload), inside the reload (no enable)", async () => {
  const lostError = () => new FleetError("outcome_unknown", "lost");
  const u = backupUnits(RELEASE);
  for (const after of ["service written", "timer written", "inside reload"]) {
    const dir = mkdtempSync(join(tmpdir(), "sb-units-"));
    const calls = [];
    let isLost = false;
    const guard = () => { if (isLost) throw lostError(); };
    const io = { ...realIo, rename: (a, b) => {
      realIo.rename(a, b);
      if ((after === "service written" && b.endsWith(u.names.service)) || (after === "timer written" && b.endsWith(u.names.timer))) isLost = true;
    } };
    const run = async (argv) => { calls.push(argv[1]); if (after === "inside reload") isLost = true; return { code: 0 }; };
    await rejects(realUnits({ dir, run, io, rootUid: UID })(u, { guard }), "outcome_unknown");
    assert.deepEqual(readdirSync(dir).sort(), after === "service written" ? [u.names.service] : [u.names.service, u.names.timer].sort(), after);
    assert.deepEqual(calls, after === "inside reload" ? ["daemon-reload"] : [], after);
  }
  // The control: with the lock held throughout, both files and both calls.
  const dir = mkdtempSync(join(tmpdir(), "sb-units-"));
  const calls = [];
  await realUnits({ dir, rootUid: UID, run: async (argv) => { calls.push(argv[1]); return { code: 0 }; } })(u, { guard: () => {} });
  assert.deepEqual(calls, ["daemon-reload", "enable"]);
  // Unchanged files aren't rewritten, and a failing call refuses with nothing after it.
  const ino = lstatSync(join(dir, u.names.timer)).ino;
  const failing = [];
  await rejects(realUnits({ dir, rootUid: UID, run: async (argv) => { failing.push(argv[1]); return { code: 1 }; } })(u, {}), "outcome_unknown");
  assert.equal(lstatSync(join(dir, u.names.timer)).ino, ino);
  assert.deepEqual(failing, ["daemon-reload"]);
  // A call that rejects (a spawn failure, its deadline, the command's signal): a registered refusal, nothing after it.
  const thrown = [];
  await rejects(realUnits({ dir, rootUid: UID, run: async (argv) => { thrown.push(argv[1]); throw Object.assign(new Error("x"), { code: "effect_failed" }); } })(u, {}), "outcome_unknown");
  assert.deepEqual(thrown, ["daemon-reload"]);
});

test("an existing unit is skipped only when proven: a regular root 0644 file, byte-equal; same bytes with another mode, a link, or another owner never stays", async () => {
  const u = backupUnits(RELEASE);
  const setUp = () => {
    const dir = mkdtempSync(join(tmpdir(), "sb-units-"));
    const calls = [];
    return { dir, calls, run: async (argv) => { calls.push(argv[1]); return { code: 0 }; } };
  };
  // Same bytes, mode 0777: rewritten at 0644 before the reload.
  {
    const x = setUp();
    for (const [n, t] of [[u.names.service, u.service], [u.names.timer, u.timer]]) { writeFileSync(join(x.dir, n), t); chmodSync(join(x.dir, n), 0o777); }
    await realUnits({ dir: x.dir, run: x.run, rootUid: UID })(u, {});
    for (const n of [u.names.service, u.names.timer]) assert.equal(lstatSync(join(x.dir, n)).mode & 0o7777, 0o644, n);
    assert.deepEqual(x.calls, ["daemon-reload", "enable"]);
  }
  // A link to a byte-equal file elsewhere: the link itself is replaced by a regular file; its target is untouched.
  {
    const x = setUp();
    const outside = join(mkdtempSync(join(tmpdir(), "sb-units-outside-")), "service");
    writeFileSync(outside, u.service, { mode: 0o644 });
    chmodSync(outside, 0o644);
    symlinkSync(outside, join(x.dir, u.names.service));
    await realUnits({ dir: x.dir, run: x.run, rootUid: UID })(u, {});
    const st = lstatSync(join(x.dir, u.names.service));
    assert.ok(st.isFile() && !st.isSymbolicLink(), "a regular file now");
    assert.equal(readFileSync(join(x.dir, u.names.service), "utf8"), u.service);
    assert.equal(lstatSync(outside).mode & 0o7777, 0o644);
    assert.equal(readFileSync(outside, "utf8"), u.service, "the link's target untouched");
  }
  // Another owner (the files are this test's uid, root is another): never proven, so the write's own proof refuses
  // before any reload or enable.
  {
    const x = setUp();
    for (const [n, t] of [[u.names.service, u.service], [u.names.timer, u.timer]]) { writeFileSync(join(x.dir, n), t); chmodSync(join(x.dir, n), 0o644); }
    await rejects(realUnits({ dir: x.dir, run: x.run, rootUid: UID + 1 })(u, {}), "outcome_unknown");
    assert.deepEqual(x.calls, [], "no reload or enable over a unit that isn't root's");
  }
  // The command: a pre-created byte-exact 0777 unit ends root 0644 (row 1's invariant).
  {
    const w = world();
    writeFileSync(join(w.unitDir, u.names.timer), u.timer);
    chmodSync(join(w.unitDir, u.names.timer), 0o777);
    assert.deepEqual(await init(input(), w.deps, w.opts()), { initialized: true });
    assertInitialized(w);
  }
});

// ---- the console's signal (SEC H1, N1 on the init PR) ----

test("a signal during a binary call: a registered refusal (outcome_unknown, never `aborted`), the journal kept, nothing after it; the next init recovers", async () => {
  const { setCommandSignal } = await import("../lib/fleet/host/backup-binary.mjs");
  for (const during of ["repository init", "code-slot's probe"]) {
    const w = world();
    const d = cmdDeps(w);
    if (during === "code-slot's probe") {
      w.repo.faults["add-key"].push({ ok: false, code: "destination_unavailable" });
      assert.equal((await backupInitCommand(["init"], d)).line.refused, "destination_unavailable");
    }
    const controller = new AbortController();
    setCommandSignal(controller.signal);
    const real = w.deps.binary;
    const op = during === "repository init" ? "init" : "snapshots";
    // As runBackupOp answers a call the signal stopped: the effect may have happened (here it has), then `aborted`.
    const stopped = async (req, o) => { const r = await real(req, o); if (req.op === op && !controller.signal.aborted) { controller.abort(); return { ok: false, code: "aborted" }; } return r; };
    w.repo.calls.length = 0;
    let out;
    try { out = await backupInitCommand(["init"], { ...d, binary: stopped }); } finally { setCommandSignal(null); }
    assert.deepEqual(out, { code: 1, line: { v: 1, refused: "outcome_unknown" } }, during);
    assert.deepEqual(w.repo.calls, [op], `${during}: nothing after it`);
    assert.deepEqual(journal(w).phase, during === "repository init" ? "repo" : "code-slot");
    assert.equal(w.tty.text, "");
    assert.deepEqual(await backupInitCommand(["init"], d), { code: 0, line: { v: 1, initialized: true } }, `${during}: recovered`);
    assertInitialized(w);
    assert.equal(ops(w, "init"), during === "repository init" ? 1 : 0, "init never repeated (the log counts from the signalled run)");
  }
});

test("a signal that lands as the answer is typed: nothing after it (no confirmed, no enabled, no units); the next init finishes", async () => {
  const { setCommandSignal } = await import("../lib/fleet/host/backup-binary.mjs");
  const w = world();
  const d = cmdDeps(w);
  const controller = new AbortController();
  const tty = { ...w.tty, ask: async (p) => { const a = await w.tty.ask(p); controller.abort(); return a; } };
  setCommandSignal(controller.signal);
  let out;
  try { out = await backupInitCommand(["init"], { ...d, tty }); } finally { setCommandSignal(null); }
  assert.deepEqual(out, { code: 1, line: { v: 1, refused: "outcome_unknown" } });
  assert.deepEqual(journal(w), { v: 1, phase: "shown" });
  assert.equal(existsSync(join(w.backup, "enabled")), false);
  assert.deepEqual(w.systemctl, []);
  assert.deepEqual(await backupInitCommand(["init"], d), { code: 0, line: { v: 1, initialized: true } });
  assertInitialized(w);
});

/** A driver: the command as host-main runs it (the console's signals installed, the real stdin), over seams. */
const stdinDriver = (repoUrl, which) => `import * as fs from "node:fs";
import { join } from "node:path";
import { installCommandSignals } from "${repoUrl}lib/fleet/host/backup-binary.mjs";
const base = process.argv[2], uid = process.getuid();
installCommandSignals(new AbortController());
const binary = async (req) => { fs.appendFileSync(join(base, "calls"), req.op + "\\n"); return { ok: false, code: "destination_unavailable" }; };
const deps = { uid: () => uid, rootUid: uid, state: join(base, "backup", "state"), secrets: join(base, "host-secrets"), release: "${RELEASE}",
  exclusion: { path: join(base, "x.lock"), uid, waitMs: 0 }, binary, enabled: () => false, restoreOpen: () => false };
const out = ${which === "init"
  ? `await (await import("${repoUrl}lib/fleet/host/backup-init.mjs")).backupInitCommand(["init"], { ...deps, tty: { write() {}, ask: async () => null }, units: async () => {} });`
  : `await (await import("${repoUrl}lib/fleet/host/backup-attach.mjs")).backupAttachCommand(["attach"], deps);`}
process.stdout.write(JSON.stringify(out.line) + "\\n");
process.exit(out.code);
`;

for (const which of ["init", "attach"]) {
  test(`N1, ${which}: stdin held open, a SIGTERM ends the wait at once (a registered refusal, nothing read or written)`, async () => {
    const { spawn } = await import("node:child_process");
    const base = mkdtempSync(join(tmpdir(), "sb-stdin-"));
    const helpers = mkdtempSync(join(tmpdir(), "sb-stdin-helpers-"));
    writeFileSync(join(helpers, "driver.mjs"), stdinDriver(pathToFileURL(fileURLToPath(new URL("..", import.meta.url))).href.replace(/\/?$/, "/"), which));
    const child = spawn(process.execPath, [join(helpers, "driver.mjs"), base], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (b) => { stdout += b; });
    child.stderr.on("data", (b) => { stderr += b; });
    const exited = new Promise((r) => child.on("exit", (code) => r(code)));
    child.stdin.write('{"v":1,'); // (part of an input, and the pipe stays open)
    await new Promise((r) => { setTimeout(r, 300); });
    const t0 = Date.now();
    child.kill("SIGTERM");
    const code = await Promise.race([exited, new Promise((r) => { setTimeout(() => r("still waiting"), 5000); })]);
    if (code === "still waiting") child.kill("SIGKILL");
    child.stdin.destroy();
    assert.equal(code, 1, `${which}: ended by the signal (${stderr})`);
    assert.ok(Date.now() - t0 < 5000);
    assert.equal(stdout, '{"v":1,"refused":"bad_form"}\n');
    assert.equal(existsSync(join(base, "calls")), false, "no binary call");
    assert.equal(existsSync(join(base, "backup")), false, "nothing created");
    assert.equal(existsSync(join(base, "host-secrets")), false);
  });
}
