// Host supervisor freeze r3.1 §2.2, §3.3, §7: the UID registry. uids and gids are monotonic and never reused; an id is
// recorded once; run states move only along the allowed transitions; lifecycle ops increment `life`; every change is
// durable before it is reported; a corrupt registry is refused rather than replaced.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, statSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { Registry, UID_RANGE, GID_RANGE } from "../lib/fleet/host/registry.mjs";

const refused = (fn, code) => assert.throws(fn, (e) => e instanceof FleetError && e.code === code);
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-registry-")), "state");

test("uids and gids come from their ranges, in order, and survive a reopen", () => {
  const dir = fresh();
  const r = new Registry(dir);
  const a = newId(), b = newId(), t = newId();
  assert.equal(r.addAgent(a, 1), UID_RANGE[0]);
  assert.equal(r.addAgent(b, 1, [t]), UID_RANGE[0] + 1);
  assert.equal(r.addTag(t), GID_RANGE[0]);
  assert.equal(r.addTag(t), GID_RANGE[0]); // stable
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(join(dir, "registry.json")).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(dir), ["registry.json"]); // no temp file left behind
  const again = new Registry(dir);
  assert.deepEqual(again.agent(b), { uid: UID_RANGE[0] + 1, state: "provisioned", life: 0, gen: 1, tags: [t] });
  assert.equal(again.addAgent(newId(), 2), UID_RANGE[0] + 2);
});

test("an id is recorded once, ever: deleting doesn't free the id or the uid", () => {
  const r = new Registry(fresh());
  const a = newId();
  const uid = r.addAgent(a, 1);
  r.setState(a, "deleted", "delete");
  refused(() => r.addAgent(a, 2), "bad_form");
  assert.equal(r.addAgent(newId(), 2), uid + 1);
});

test("the uid range runs out with uid_exhausted, never wrapping", () => {
  const dir = fresh();
  new Registry(dir);
  const file = join(dir, "registry.json");
  const j = JSON.parse(readFileSync(file, "utf8"));
  j.next_uid = UID_RANGE[1];
  writeFileSync(file, JSON.stringify(j));
  const r = new Registry(dir);
  assert.equal(r.addAgent(newId(), 1), UID_RANGE[1]);
  refused(() => r.addAgent(newId(), 1), "uid_exhausted");
});

test("run states: allowed moves pass; revoked and deleted never run again; lifecycle ops increment life", () => {
  const r = new Registry(fresh());
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
});

test("recovery starts only agents recorded as running; paused and stopped stay down", () => {
  const dir = fresh();
  const r = new Registry(dir);
  const [run, pause, stop, fresh_] = [newId(), newId(), newId(), newId()];
  for (const id of [run, pause, stop, fresh_]) r.addAgent(id, 1);
  r.setState(run, "running");
  r.setState(pause, "running"); r.setState(pause, "paused", "pause");
  r.setState(stop, "running"); r.setState(stop, "stopped", "stop");
  assert.deepEqual(new Registry(dir).runnable(), [run]);
});

test("grant updates move the generation forward only", () => {
  const r = new Registry(fresh());
  const a = newId(), t = newId();
  r.addAgent(a, 3);
  assert.deepEqual(r.setGrant(a, 4, [t]).tags, [t]);
  refused(() => r.setGrant(a, 2, []), "bad_form");
  refused(() => r.setGrant(a, 5, ["not-an-id"]), "bad_form");
});

test("a corrupt or tampered registry is refused, not replaced", () => {
  const variants = [
    (j) => "{not json",
    (j) => JSON.stringify({ ...j, v: 2 }),
    (j) => JSON.stringify({ ...j, next_uid: 1000 }),
    (j) => { const a = Object.keys(j.agents)[0]; j.agents[a].uid = j.next_uid; return JSON.stringify(j); },
    (j) => { const [a, b] = Object.keys(j.agents); j.agents[b].uid = j.agents[a].uid; return JSON.stringify(j); },
    (j) => { const a = Object.keys(j.agents)[0]; j.agents[a].state = "flying"; return JSON.stringify(j); },
    (j) => { j.agents["root"] = j.agents[Object.keys(j.agents)[0]]; return JSON.stringify(j); },
    (j) => { const a = Object.keys(j.agents)[0]; j.agents[a].life = -1; return JSON.stringify(j); },
  ];
  for (const mutate of variants) {
    const dir = fresh();
    const r = new Registry(dir);
    r.addAgent(newId(), 1); r.addAgent(newId(), 1);
    const file = join(dir, "registry.json");
    const before = readFileSync(file, "utf8");
    writeFileSync(file, mutate(JSON.parse(before)));
    const tampered = readFileSync(file, "utf8");
    refused(() => new Registry(dir), "bad_form");
    assert.equal(readFileSync(file, "utf8"), tampered); // left as found, for repair
  }
});
