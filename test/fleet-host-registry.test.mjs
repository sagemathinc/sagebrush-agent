// Host supervisor freeze r3.1 §2.2, §3.3, §7: the UID registry and its durable store. uids and gids are monotonic and
// never reused; an id is recorded once; run states move only along the allowed transitions; lifecycle ops increment
// `life`; one writer per host (flock); a change is visible only after it is durable, and a failed write poisons the
// instance until a reload, leaving disk and memory equal; anything but the exact closed shape is refused at load.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, statSync, readdirSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { Registry, UID_RANGE, GID_RANGE } from "../lib/fleet/host/registry.mjs";
import { realIo } from "../lib/fleet/host/store.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-registry-")), "state");
const disk = (dir) => JSON.parse(readFileSync(join(dir, "registry.json"), "utf8"));

test("uids and gids come from their ranges, in order, and survive a reopen", async () => {
  const dir = fresh();
  const r = await Registry.open(dir);
  const a = newId(), b = newId(), t = newId();
  assert.equal(r.addAgent(a, 1), UID_RANGE[0]);
  assert.equal(r.addAgent(b, 1, [t]), UID_RANGE[0] + 1);
  assert.equal(r.addTag(t), GID_RANGE[0]);
  assert.equal(r.addTag(t), GID_RANGE[0]); // stable
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(join(dir, "registry.json")).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(dir).filter((f) => f !== ".lock"), ["registry.json"]); // no temp file left behind
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
  writeFileSync(join(dir, "registry.json"), JSON.stringify(j));
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
    write: (fd, d) => { if (step === "write") boom(); return realIo.write(fd, d); },
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
  mkdirSync(join(dir, `.registry.json.${process.pid}.tmp`));
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
  writeFileSync(join(dir, "registry.json"), JSON.stringify(j));
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
  const url = new URL("../lib/fleet/host/registry.mjs", import.meta.url).href;
  const holder = spawn(process.execPath, ["--input-type=module", "-e",
    `const { Registry } = await import(${JSON.stringify(url)}); const r = await Registry.open(${JSON.stringify(dir)});
     process.stdout.write(String(r.addAgent(${JSON.stringify(newId())}, 1)) + "\\n"); process.stdin.resume(); process.stdin.on("end", async () => { await r.close(); process.exit(0); });`],
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
  const url = new URL("../lib/fleet/host/registry.mjs", import.meta.url).href;
  const holder = spawn(process.execPath, ["--input-type=module", "-e",
    `const { Registry } = await import(${JSON.stringify(url)}); await Registry.open(${JSON.stringify(dir)}); process.stdout.write("open\\n"); setInterval(() => {}, 1e6);`],
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
    const file = join(dir, "registry.json");
    const out = mutate(JSON.parse(readFileSync(file, "utf8")), a, b);
    writeFileSync(file, typeof out === "string" ? out : JSON.stringify(out));
    const tampered = readFileSync(file, "utf8");
    await rejects(Registry.open(dir), "bad_form");
    assert.equal(readFileSync(file, "utf8"), tampered); // left as found, for repair
  }
});
