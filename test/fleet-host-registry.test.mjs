// Host supervisor freeze r3.1 §2.2, §3.3, §7: the UID registry and its durable store. uids and gids are monotonic and
// never reused; an id is recorded once; run states move only along the allowed transitions; lifecycle ops increment
// `life`; one writer per host (flock); a change is visible only after it is durable, and a failed write poisons the
// instance until a reload, leaving disk and memory equal; anything but the exact closed shape is refused at load.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, statSync, readdirSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { UID_RANGE, GID_RANGE } from "../lib/fleet/host/registry.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-registry-")), "state");
const disk = (root) => JSON.parse(readFileSync(join(root, "registry", "registry.json"), "utf8"));
const regFile = (root) => join(root, "registry", "registry.json");
/** Open the host store and return its registry view, with close() closing the store. */
const Registry = { open: async (root, opts) => { const h = await HostStore.open(root, opts); const r = h.registry; r.close = () => h.close(); r.store = h; return r; } };

test("uids and gids come from their ranges, in order, and survive a reopen", async () => {
  const dir = fresh();
  const r = await Registry.open(dir);
  const a = newId(), b = newId(), t = newId();
  assert.equal(r.addAgent(a, 1), UID_RANGE[0]);
  assert.equal(r.addAgent(b, 1, [t]), UID_RANGE[0] + 1);
  assert.equal(r.addTag(t), GID_RANGE[0]);
  assert.equal(r.addTag(t), GID_RANGE[0]); // stable
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(regFile(dir)).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(join(dir, "registry")), ["registry.json"]); // no temp file left behind
  await r.close();
  const again = await Registry.open(dir);
  assert.deepEqual(again.agent(b), { uid: UID_RANGE[0] + 1, state: "provisioned", life: 0, gen: 1, tags: [t] });
  assert.equal(again.addAgent(newId(), 2), UID_RANGE[0] + 2);
  await again.close();
});

test("an id is recorded once, ever: deleting doesn't free the id or the uid", async () => {
  const r = await Registry.open(fresh());
  const a = newId();
  const uid = r.addAgent(a, 1);
  r.setState(a, "deleted", "delete");
  refused(() => r.addAgent(a, 2), "bad_form");
  assert.equal(r.addAgent(newId(), 2), uid + 1);
  await r.close();
});

test("the uid range runs out with uid_exhausted, never wrapping", async () => {
  const dir = fresh();
  await (await Registry.open(dir)).close();
  const j = disk(dir); j.next_uid = UID_RANGE[1];
  writeFileSync(regFile(dir), JSON.stringify(j));
  const r = await Registry.open(dir);
  assert.equal(r.addAgent(newId(), 1), UID_RANGE[1]);
  refused(() => r.addAgent(newId(), 1), "uid_exhausted");
  await r.close();
});

test("run states: allowed moves pass; revoked and deleted never run again; lifecycle ops increment life", async () => {
  const r = await Registry.open(fresh());
  const a = newId();
  r.addAgent(a, 1);
  assert.equal(r.setState(a, "running").life, 0);
  assert.equal(r.setState(a, "paused", "pause").life, 1);
  assert.equal(r.setState(a, "running", "resume").life, 2);
  assert.equal(r.setState(a, "stopped", "stop").life, 3);
  assert.deepEqual(r.runnable(), []);
  assert.equal(r.setState(a, "running", "resume").life, 4);
  assert.deepEqual(r.runnable(), [a]);
  assert.equal(r.setState(a, "revoked", "revoke-caps").life, 5);
  refused(() => r.setState(a, "running", "resume"), "not_granted");
  refused(() => r.setState(a, "stopped", "stop"), "not_granted");
  refused(() => r.setGrant(a, 2, []), "not_granted");
  r.setState(a, "deleted", "delete");
  refused(() => r.setState(a, "revoked"), "not_granted");
  refused(() => r.setState(newId(), "running"), "not_granted");
  refused(() => r.setState(a, "flying"), "bad_form");
  const b = newId();
  r.addAgent(b, 1);
  refused(() => r.setState(b, "running", "teleport"), "bad_form");
  assert.equal(r.poisoned, false); // refusals before a write never poison
  await r.close();
});

test("recovery starts only agents recorded as running; paused and stopped stay down", async () => {
  const dir = fresh();
  const r = await Registry.open(dir);
  const [run, pause, stop, fresh_] = [newId(), newId(), newId(), newId()];
  for (const id of [run, pause, stop, fresh_]) r.addAgent(id, 1);
  r.setState(run, "running");
  r.setState(pause, "running"); r.setState(pause, "paused", "pause");
  r.setState(stop, "running"); r.setState(stop, "stopped", "stop");
  await r.close();
  const again = await Registry.open(dir);
  assert.deepEqual(again.runnable(), [run]);
  await again.close();
});

test("grant updates move the generation forward only", async () => {
  const r = await Registry.open(fresh());
  const a = newId(), t = newId();
  r.addAgent(a, 3);
  assert.deepEqual(r.setGrant(a, 4, [t]).tags, [t]);
  refused(() => r.setGrant(a, 2, []), "bad_form");
  refused(() => r.setGrant(a, 5, ["not-an-id"]), "bad_form");
  refused(() => r.setGrant(a, 5, [t, t]), "bad_form");
  await r.close();
});

// ---- H1: commit, then publish; a failed write poisons until a reload, and disk and memory end equal

const failAt = (step, code = "ENOSPC") => {
  const boom = () => { throw Object.assign(new Error(code), { code }); };
  let dirOpen = false;
  return {
    ...realIo,
    open: (p, f, m) => { if (step === "open" && f === "w") boom(); dirOpen = f === "r"; return realIo.open(p, f, m); },
    write: (fd, b, o, l) => { if (step === "write") boom(); return realIo.write(fd, b, o, l); },
    fsync: (fd) => { if ((step === "fsync" && !dirOpen) || (step === "dirfsync" && dirOpen)) boom(); return realIo.fsync(fd); },
    rename: (a, b) => { if (step === "rename") boom(); return realIo.rename(a, b); },
  };
};

for (const step of ["open", "write", "fsync", "rename", "dirfsync"]) {
  test(`a failure at ${step} poisons the instance; after a reload memory equals disk`, async () => {
    const dir = fresh();
    const a = newId();
    { const r = await Registry.open(dir); r.addAgent(a, 1); r.setState(a, "running"); r.setState(a, "paused", "pause"); await r.close(); }
    const r = await Registry.open(dir, { io: failAt(step) });
    assert.throws(() => r.setState(a, "running", "resume"), /ENOSPC/);
    assert.equal(r.poisoned, true);
    refused(() => r.agent(a), "outcome_unknown");
    refused(() => r.runnable(), "outcome_unknown");
    refused(() => r.addAgent(newId(), 1), "outcome_unknown");
    r.reload();
    const onDisk = disk(dir).agents[a];
    assert.deepEqual(r.agent(a), onDisk);
    // Before the rename nothing changed on disk; after it, the change is durable but was never published until reload.
    assert.deepEqual(onDisk.state, step === "dirfsync" ? "running" : "paused");
    assert.deepEqual(r.runnable(), step === "dirfsync" ? [a] : []);
    await r.close();
  });
}

test("the reviewers' probe: a temp path that is a directory (EISDIR) leaves disk paused and memory refusing", async () => {
  const dir = fresh();
  const a = newId();
  const r = await Registry.open(dir);
  r.addAgent(a, 1); r.setState(a, "running"); r.setState(a, "paused", "pause");
  mkdirSync(join(dir, "registry", `.registry.json.${process.pid}.tmp`));
  assert.throws(() => r.setState(a, "running", "resume"));
  refused(() => r.runnable(), "outcome_unknown");
  assert.deepEqual(disk(dir).agents[a], { uid: UID_RANGE[0], state: "paused", life: 1, gen: 1, tags: [] });
  r.reload();
  assert.deepEqual(r.runnable(), []);
  await r.close();
});

test("a file changed underneath the instance poisons it on the next write", async () => {
  const dir = fresh();
  const r = await Registry.open(dir);
  r.addAgent(newId(), 1);
  const j = disk(dir); j.next_uid += 5;
  writeFileSync(regFile(dir), JSON.stringify(j));
  refused(() => r.addAgent(newId(), 1), "outcome_unknown");
  r.reload();
  assert.equal(r.addAgent(newId(), 1), j.next_uid);
  await r.close();
});

// ---- H2: one writer per host

test("a second open in the same process refuses while the first holds the lock; after close it opens", async () => {
  const dir = fresh();
  const r = await Registry.open(dir);
  await rejects(Registry.open(dir), "in_progress");
  r.addAgent(newId(), 1);
  await r.close();
  const again = await Registry.open(dir);
  assert.equal(Object.keys(disk(dir).agents).length, 1);
  await again.close();
});

test("a second process can't open while one holds it, and no uid is handed out twice", async () => {
  const dir = fresh();
  const url = new URL("../lib/fleet/host/host-store.mjs", import.meta.url).href;
  const holder = spawn(process.execPath, ["--input-type=module", "-e",
    `const { HostStore } = await import(${JSON.stringify(url)}); const h = await HostStore.open(${JSON.stringify(dir)});
     process.stdout.write(String(h.registry.addAgent(${JSON.stringify(newId())}, 1)) + "\\n"); process.stdin.resume(); process.stdin.on("end", async () => { await h.close(); process.exit(0); });`],
  { stdio: ["pipe", "pipe", "inherit"] });
  const first = await new Promise((res) => holder.stdout.once("data", (b) => res(Number(String(b).trim()))));
  assert.equal(first, UID_RANGE[0]);
  await rejects(Registry.open(dir), "in_progress");
  holder.stdin.end();
  await new Promise((res) => holder.once("exit", res));
  const r = await Registry.open(dir);
  assert.equal(r.addAgent(newId(), 1), UID_RANGE[0] + 1);
  assert.equal(Object.keys(disk(dir).agents).length, 2);
  await r.close();
});

test("a killed holder releases the lock (it dies with its process)", async () => {
  const dir = fresh();
  const url = new URL("../lib/fleet/host/host-store.mjs", import.meta.url).href;
  const holder = spawn(process.execPath, ["--input-type=module", "-e",
    `const { HostStore } = await import(${JSON.stringify(url)}); await HostStore.open(${JSON.stringify(dir)}); process.stdout.write("open\\n"); setInterval(() => {}, 1e6);`],
  { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((res) => holder.stdout.once("data", res));
  await rejects(Registry.open(dir), "in_progress");
  holder.kill("SIGKILL");
  await new Promise((res) => holder.once("exit", res));
  let r;
  for (let i = 0; i < 50 && !r; i++) { try { r = await Registry.open(dir); } catch { await new Promise((s) => setTimeout(s, 100)); } }
  assert.ok(r, "the lock was released after SIGKILL");
  await r.close();
});

// ---- H3: the exact closed shape, refused at load

test("anything but the exact closed shape is refused at load and left as found", async () => {
  const variants = [
    () => "{not json",
    (j) => ({ ...j, v: 2 }),
    (j) => ({ ...j, extra: 1 }),
    (j) => ({ ...j, next_uid: 1000 }),
    (j, a) => { j.agents[a].uid = j.next_uid; return j; },
    (j, a, b) => { j.agents[b].uid = j.agents[a].uid; return j; },
    (j, a) => { j.agents[a].state = "flying"; return j; },
    (j, a) => { j.agents.root = j.agents[a]; return j; },
    (j, a) => { j.agents[a].life = -1; return j; },
    (j, a) => { delete j.agents[a].tags; return j; },
    (j, a) => { j.agents[a].tags = "x"; return j; },
    (j, a) => { j.agents[a].tags = ["not-an-id"]; return j; },
    (j, a) => { const t = newId(); j.agents[a].tags = [t, t]; return j; },
    (j, a) => { j.agents[a].tags = Array.from({ length: 17 }, () => newId()); return j; },
    (j, a) => { j.agents[a].note = "x"; return j; },
    (j) => { j.tags[newId()] = { gid: GID_RANGE[0], extra: 1 }; j.next_gid += 1; return j; },
    (j) => ({ ...j, agents: [] }),
  ];
  for (const mutate of variants) {
    const dir = fresh();
    const r = await Registry.open(dir);
    const a = newId(), b = newId();
    r.addAgent(a, 1); r.addAgent(b, 1);
    await r.close();
    const file = regFile(dir);
    const out = mutate(JSON.parse(readFileSync(file, "utf8")), a, b);
    writeFileSync(file, typeof out === "string" ? out : JSON.stringify(out));
    const tampered = readFileSync(file, "utf8");
    await rejects(Registry.open(dir), "bad_form");
    assert.equal(readFileSync(file, "utf8"), tampered); // left as found, for repair
  }
});

// ---- residuals: short and zero writes, lock loss, failed reload

const writeHook = (fn) => ({ ...realIo, write: fn });

for (const [label, io] of [
  ["a short write (1 byte, honestly reported)", () => writeHook((fd, b, o) => realIo.write(fd, b, o, 1))],
  ["a zero-byte write", () => writeHook(() => 0)],
  ["a partial write then an error", () => { let n = 0; return writeHook((fd, b, o, l) => { if (n++ === 0) return realIo.write(fd, b, o, Math.min(l, 3)); throw Object.assign(new Error("EIO"), { code: "EIO" }); }); }],
  ["a write claiming more than asked", () => writeHook((fd, b, o, l) => { realIo.write(fd, b, o, l); return l + 1; })],
]) {
  test(`${label}: nothing is published, the instance is poisoned, disk stays whole`, async () => {
    const dir = fresh();
    { const r = await Registry.open(dir); r.addAgent(newId(), 1); await r.close(); }
    const before = readFileSync(regFile(dir), "utf8");
    const hook = io();
    const r = await Registry.open(dir, { io: label.startsWith("a short") ? writeHook((fd, b, o, l) => realIo.write(fd, b, o, l)) : hook });
    if (label.startsWith("a short")) { await r.close(); } // (a short write is retried, so it must succeed: check below)
    if (label.startsWith("a short")) {
      const r2 = await Registry.open(dir, { io: hook });
      const id = newId();
      const uid = r2.addAgent(id, 1);
      assert.equal(r2.poisoned, false);
      assert.deepEqual(r2.agent(id), disk(dir).agents[id]); // looped to completion: memory equals the whole file
      assert.equal(uid, UID_RANGE[0] + 1);
      await r2.close();
      return;
    }
    assert.throws(() => r.addAgent(newId(), 1));
    assert.equal(r.poisoned, true);
    refused(() => r.runnable(), "outcome_unknown");
    assert.equal(readFileSync(regFile(dir), "utf8"), before); // the rename never happened
    r.reload();
    assert.equal(Object.keys(r.store.registry.runnable()).length, 0);
    await r.close();
  });
}

test("the lock helper dies: the view poisons at once; a second opener succeeds; the old view refuses commits and reload", async () => {
  const dir = fresh();
  const r = await Registry.open(dir);
  const a = newId();
  r.addAgent(a, 1); r.setState(a, "running");
  // Kill the helper process that holds this store's flock (it is the only one with this lock path).
  const { execFileSync } = await import("node:child_process");
  const pids = String(execFileSync("pgrep", ["-f", join(dir, ".lock")])).trim().split("\n").filter(Boolean);
  assert.ok(pids.length >= 1);
  for (const p of pids) { try { process.kill(Number(p), "SIGKILL"); } catch {} }
  let second;
  for (let i = 0; i < 50 && !second; i++) { try { second = await Registry.open(dir); } catch { await new Promise((s) => setTimeout(s, 100)); } }
  assert.ok(second, "a second opener got the lock");
  assert.equal(r.poisoned, true);
  refused(() => r.runnable(), "outcome_unknown");
  refused(() => r.setState(a, "paused", "pause"), "outcome_unknown");
  refused(() => r.reload(), "outcome_unknown");
  assert.deepEqual(second.runnable(), [a]);
  second.setState(a, "paused", "pause");
  assert.equal(disk(dir).agents[a].state, "paused");
  await second.close();
});

test("close() ends every view: no reads, commits or reloads afterwards", async () => {
  const dir = fresh();
  const r = await Registry.open(dir);
  r.addAgent(newId(), 1);
  await r.close();
  refused(() => r.runnable(), "in_progress");
  refused(() => r.addAgent(newId(), 1), "in_progress");
  refused(() => r.reload(), "in_progress");
});

test("a failed reload leaves a healthy view poisoned; the same from an already-poisoned view; a good file clears it", async () => {
  const dir = fresh();
  const r = await Registry.open(dir);
  const a = newId();
  r.addAgent(a, 1); r.setState(a, "running");
  const good = readFileSync(regFile(dir), "utf8");
  writeFileSync(regFile(dir), "{");
  refused(() => r.reload(), "bad_form");          // healthy before; now poisoned
  assert.equal(r.poisoned, true);
  refused(() => r.runnable(), "outcome_unknown");
  refused(() => r.reload(), "bad_form");          // already poisoned; still poisoned
  refused(() => r.runnable(), "outcome_unknown");
  writeFileSync(regFile(dir), good);
  r.reload();
  assert.deepEqual(r.runnable(), [a]);
  await r.close();
});

test("a write that claims every byte but writes fewer: refused before the rename; poisoned; disk unchanged", async () => {
  const dir = fresh();
  { const r = await Registry.open(dir); r.addAgent(newId(), 1); await r.close(); }
  const before = readFileSync(regFile(dir), "utf8");
  const r = await Registry.open(dir, { io: writeHook((fd, b, o, l) => { realIo.write(fd, b, o, 1); return l; }) });
  assert.throws(() => r.addAgent(newId(), 1), /read-back/);
  assert.equal(r.poisoned, true);
  refused(() => r.runnable(), "outcome_unknown");
  assert.equal(readFileSync(regFile(dir), "utf8"), before);
  assert.deepEqual(readdirSync(join(dir, "registry")), ["registry.json"]); // the bad temp file is removed
  r.reload();
  assert.equal(Object.keys(disk(dir).agents).length, 1);
  await r.close();
});

test("the lock holder dies and the commit runs before Node sees the exit: the OS check refuses it", async () => {
  const dir = fresh();
  const r = await Registry.open(dir);
  const a = newId();
  r.addAgent(a, 1);
  const { execFileSync } = await import("node:child_process");
  const pids = String(execFileSync("pgrep", ["-f", join(dir, ".lock")])).trim().split("\n").filter(Boolean).map(Number);
  // The flock process is the oldest; kill them all, then wait synchronously (no event-loop turn) until /proc agrees.
  for (const p of pids) { try { process.kill(p, "SIGKILL"); } catch {} }
  const gone = (p) => { try { const st = readFileSync(`/proc/${p}/stat`, "utf8"); const c = st[st.lastIndexOf(")") + 2]; return c === "Z" || c === "X"; } catch { return true; } };
  const t0 = Date.now();
  while (!pids.every(gone) && Date.now() - t0 < 5000) { /* spin: Node can't process the exit event here */ }
  refused(() => r.setState(a, "running"), "outcome_unknown");
  assert.equal(disk(dir).agents[a].state, "provisioned");
});
