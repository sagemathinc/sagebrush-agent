// Host restore e2e r1.7 and delta d2: the restore worker's real adapters, over a fake launcher that records every argv
// and answers per command. Each destination effect is a launcher call with an expect naming the exact object; the
// identities, owners, members and unrestorable paths are the input's; cleanup touches only the bound object.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { CLASSES, newRestoreRun, newRecord, step } from "../lib/fleet/host/restore-record.mjs";
import { destOf } from "../lib/fleet/host/restore-fill.mjs";
import { checkInput } from "../lib/fleet/host/restore-inputs.mjs";
import { EMPTY_LISTING, launcherRunner, restoreAdapters } from "../lib/fleet/host/restore-adapters.mjs";

const UID = typeof process.getuid === "function" ? process.getuid() : -1, GID = typeof process.getgid === "function" ? process.getgid() : -1;
const rejects = (p, code) => assert.rejects(p, (e) => e instanceof FleetError && e.code === code, code);
const RUN = newRestoreRun(1795500000000, () => Buffer.alloc(6)), RUN2 = newRestoreRun(1795600000000, () => Buffer.alloc(6, 1));
const SNAP = "1".repeat(64);
const EPOCH = { boot_id: "00000000-0000-4000-8000-000000000000", mnt_id: 7 }, FSID = "0123456789abcdef";
const obj = (over = {}) => ({ type: "dir", mode: 0o700, uid: 70000, gid: 70000, dev: [8, 1], ino: 4242, gen: 1, mnt_id: 7, projid: 70000, inherit: true, ...over });
const line = (x) => JSON.stringify(x) + "\n";

function inputOf(kind, id, { owners = { uids: [70000], gid: 70000, projid: 70000 }, members } = {}) {
  const classes = Object.fromEntries(CLASSES[kind]
    .map((c, i) => [c, { dest: { epoch: EPOCH, fsid: FSID, object: obj({ ino: 4242 + i }) }, owners: c === "archive-config" ? { uids: [0], gid: 0, projid: owners.projid } : owners, unrestorable: [`${c}/skipped`] }]));
  return checkInput({ v: 1, kind, id, run: RUN, nonce: newId(), classes, members: members ?? (kind === "agent" ? [{ agent: id, uid: 70000 }] : kind === "tag" ? [{ agent: newId(), uid: 70000 }] : []) });
}

/** A fake launcher: `answer(args)` → { code, stdout } (default: identify/inspect-home answer `objects`, everything else 0). */
function launcherWith(answer) {
  const calls = [];
  const launch = async (args, opts = {}) => { calls.push({ args, opts }); return answer(args, opts); };
  return { calls, launch };
}
function setup(kind, { answer, ...over } = {}) {
  const id = newId();
  const input = inputOf(kind, id, over);
  const base = mkdtempSync(join(tmpdir(), "sb-adapt-"));
  const expectDir = join(base, "expect"), staging = join(base, "staging"), copies = join(base, "copies");
  const idents = { home: obj({ ino: 4242 }), sessions: obj({ ino: 4243 }), archive: obj({ ino: 4242 }), tag: obj({ ino: 4242 }) };
  const l = launcherWith(answer ?? ((args) => {
    if (args[0] === "inspect-home") return { code: 0, stdout: line({ epoch: EPOCH, fsid: FSID, dir: obj(), entries: { home: idents.home, "var-tmp": obj({ ino: 9 }), sessions: idents.sessions } }) };
    if (args[0] === "identify") return { code: 0, stdout: line({ epoch: EPOCH, fsid: FSID, object: idents[kind] ?? obj() }) };
    if (args[0] === "tree-digest") return { code: 0, stdout: EMPTY_LISTING };
    return { code: 0, stdout: "" };
  }));
  const fenced = new Set(input.members.map((m) => m.agent)), empty = new Set(input.members.map((m) => m.agent));
  const a = restoreAdapters(input, {
    launch: l.launch, mount: "/srv/sagebrush", fenceRaised: async (x) => fenced.has(x), sliceEmpty: async (x) => empty.has(x),
    expectDir, staging, copies, rootUid: UID, rootGid: GID,
  });
  return { id, input, a, calls: l.calls, expectDir, staging, copies, fenced, empty, idents, base };
}
const readExpect = (p) => JSON.parse(readFileSync(p, "utf8"));
const flag = (args, f) => args[args.indexOf(`--${f}`) + 1];

test("launcherRunner: the launcher by argv; tree-digest in its transient scope; a bad scope refused", async () => {
  const runs = [];
  const run = async (argv, o) => { runs.push([argv, o.ms]); return { code: 0, stdout: "" }; };
  const launch = launcherRunner({ run, launcher: "/opt/sagebrush/bin/sagebrush-agent-launch" });
  await launch(["identify", "--anchor", "/srv/sagebrush/tags", "--name", "x"], { ms: 5 });
  const scope = { unit: `sagebrush-validate-a-${newId()}.scope`, memoryMax: "1G", runtimeMaxSec: 600 };
  await launch(["tree-digest", "--class", "home"], { ms: 7, scope });
  assert.deepEqual(runs, [
    [["/opt/sagebrush/bin/sagebrush-agent-launch", "identify", "--anchor", "/srv/sagebrush/tags", "--name", "x"], 5],
    [["systemd-run", "--scope", "--quiet", "--collect", `--unit=${scope.unit}`, "-p", "MemoryMax=1G", "-p", "RuntimeMaxSec=600", "--", "/opt/sagebrush/bin/sagebrush-agent-launch", "tree-digest", "--class", "home"], 7],
  ]);
  for (const bad of [{ ...scope, unit: "evil.scope" }, { ...scope, memoryMax: "1G; rm" }, { ...scope, runtimeMaxSec: 0 }]) {
    assert.throws(() => launch(["tree-digest"], { ms: 1, scope: bad }), (e) => e.code === "bad_form");
  }
  assert.throws(() => launcherRunner({ run, launcher: "relative" }), (e) => e.code === "bad_form");
});

test("identifyDest: an agent's classes by inspect-home, an archive and a tag folder by identify under their own anchors; anything else refuses", async () => {
  const ag = setup("agent");
  assert.deepEqual(await ag.a.identifyDest("agent", ag.id, "sessions"), { epoch: EPOCH, fsid: FSID, object: ag.idents.sessions });
  assert.deepEqual(ag.calls.at(-1).args, ["inspect-home", "--mount", "/srv/sagebrush", "--agent", ag.id, "--tree", "home"]);
  for (const [kind, anchor] of [["archive", "/srv/sagebrush/archive"], ["tag", "/srv/sagebrush/tags"]]) {
    const s = setup(kind);
    assert.deepEqual((await s.a.identifyDest(kind, s.id, kind)).object, s.idents[kind]);
    assert.deepEqual(s.calls.at(-1).args, ["identify", "--anchor", anchor, "--name", s.id]);
  }
  // Another set or class: refused before any call.
  await rejects(ag.a.identifyDest("agent", newId(), "home"), "bad_form");
  await rejects(ag.a.identifyDest("agent", ag.id, "tag"), "bad_form");
  // Missing; a failed exit; not one JSON line; not a directory's identity.
  const cases = [
    [{ code: 0, stdout: line({ epoch: EPOCH, fsid: FSID, object: null }) }, "not_found"],
    [{ code: 66, stdout: "" }, "outcome_unknown"],
    [{ code: 0, stdout: "{}\n{}\n" }, "outcome_unknown"],
    [{ code: 0, stdout: "\n" + line({ epoch: EPOCH, fsid: FSID, object: obj() }) }, "outcome_unknown"], // a valid object after a blank line
    [{ code: 66, stdout: line({ epoch: EPOCH, fsid: FSID, object: obj() }) }, "outcome_unknown"], // a valid line from a failed run
    [{ code: 0, stdout: "not json\n" }, "outcome_unknown"],
    [{ code: 0, stdout: line({ epoch: EPOCH, fsid: FSID, object: obj({ type: "file" }) }) }, "outcome_unknown"],
    [{ code: 0, stdout: line({ epoch: { boot_id: "x", mnt_id: 7 }, fsid: FSID, object: obj() }) }, "outcome_unknown"],
  ];
  for (const [out, code] of cases) { const s = setup("archive", { answer: () => out }); await rejects(s.a.identifyDest("archive", s.id, "archive"), code); }
  // inspect-home's entry is checked like identify's object: not a directory's identity is unknown.
  for (const entry of [obj({ type: "file" }), obj({ dev: [8] }), { ...obj(), extra: 1 }]) {
    const bad = setup("agent", { answer: () => ({ code: 0, stdout: line({ epoch: EPOCH, fsid: FSID, dir: obj(), entries: { home: entry, sessions: obj() } }) }) });
    await rejects(bad.a.identifyDest("agent", bad.id, "home"), "outcome_unknown");
  }
  const noSessions = setup("agent", { answer: () => ({ code: 0, stdout: line({ epoch: EPOCH, fsid: FSID, dir: obj(), entries: { home: obj() } }) }) });
  await rejects(noSessions.a.identifyDest("agent", noSessions.id, "sessions"), "not_found");
});

test("isEmpty: tree-digest of the identified object with the class's owners from the input; exactly the empty listing, exit 0", async () => {
  const s = setup("tag", { owners: { uids: [70001, 70002], gid: 80001, projid: 80001 }, members: [{ agent: newId(), uid: 70001 }, { agent: newId(), uid: 70002 }] });
  s.idents.tag = obj({ gid: 80001, projid: 80001 }); // a tag folder: the tag's group and project
  const identified = { epoch: EPOCH, fsid: FSID, object: s.idents.tag };
  assert.equal(await s.a.isEmpty("tag", s.id, "tag", identified), true);
  const call = s.calls.at(-1).args;
  assert.deepEqual(call.slice(0, 7), ["tree-digest", "--mount", "/srv/sagebrush", "--owner", `t-${s.id}`, "--class", "tag"]);
  assert.ok(!call.includes("--copy-sqlite"), "nothing copied for an emptiness check");
  assert.deepEqual(readExpect(flag(call, "expect")), { epoch: EPOCH, fsid: FSID, dest: s.idents.tag, uids: [70001, 70002], gid: 80001, projid: 80001 });
  for (const out of [{ code: 0, stdout: '{"v":1}\n{"path":"a","type":"file","size":1,"mode":420,"sha256":"x"}\n{"count":1,"total_bytes":1}\n' },
    { code: 75, stdout: EMPTY_LISTING }, { code: 0, stdout: EMPTY_LISTING + "\n" }, { code: 0, stdout: "" }]) {
    const t = setup("archive", { answer: () => out });
    assert.equal(await t.a.isEmpty("archive", t.id, "archive", { epoch: EPOCH, fsid: FSID, object: obj() }), false, JSON.stringify(out));
  }
});

test("cleanDest: only the record's bound object, emptied and kept: identify, then remove-tree --contents with exactly that object; another refuses with nothing removed", async () => {
  const s = setup("agent");
  const bound = { home: destOf(s.idents.home), sessions: destOf(s.idents.sessions) };
  let r = step(newRecord({ kind: "agent", id: s.id, run: RUN, snapshot: SNAP }), "bind", { dest: bound });
  await s.a.cleanDest(r);
  const rm = s.calls.filter((c) => c.args[0] === "remove-tree").map((c) => c.args);
  assert.deepEqual(rm.map((a) => a.slice(0, 6)), [
    ["remove-tree", "--contents", "--anchor", "/srv/sagebrush/agents", "--name", `${s.id}/home`],
    ["remove-tree", "--contents", "--anchor", "/srv/sagebrush/agents", "--name", `${s.id}/sessions`],
  ]);
  assert.deepEqual(readExpect(flag(rm[1], "expect")), { epoch: EPOCH, fsid: FSID, root: s.idents.sessions, owners: [0, 70000] });
  // The sessions identified now is another object: refused after home (in class order), sessions untouched.
  const t = setup("agent");
  t.idents.sessions = obj({ ino: 9999 });
  r = step(newRecord({ kind: "agent", id: t.id, run: RUN, snapshot: SNAP }), "bind", { dest: { home: destOf(t.idents.home), sessions: destOf(obj({ ino: 4243 })) } });
  await rejects(t.a.cleanDest(r), "not_granted");
  assert.deepEqual(t.calls.filter((c) => c.args[0] === "remove-tree").map((c) => c.args[5]), [`${t.id}/home`], "only the bound one was emptied");
  // A tag folder: its anchor and its members' uids; a failing removal is unknown.
  const g = setup("tag");
  await g.a.cleanDest(step(newRecord({ kind: "tag", id: g.id, run: RUN, snapshot: SNAP }), "bind", { dest: { tag: destOf(g.idents.tag) } }));
  assert.deepEqual(g.calls.at(-1).args.slice(0, 6), ["remove-tree", "--contents", "--anchor", "/srv/sagebrush/tags", "--name", g.id]);
  // An archive: both classes, each under its own anchor; the archive's configuration is root's alone.
  const rootObj = obj({ uid: 0, gid: 0, ino: 4243 });
  const c = setup("archive", { answer: (args) => ({ code: 0, stdout: args[0] === "identify" ? line({ epoch: EPOCH, fsid: FSID, object: args.includes("/srv/sagebrush/archive-config") ? rootObj : obj() }) : "" }) });
  await c.a.cleanDest(step(newRecord({ kind: "archive", id: c.id, run: RUN, snapshot: SNAP }), "bind", { dest: { archive: destOf(obj()), "archive-config": destOf(rootObj) } }));
  const crm = c.calls.filter((x) => x.args[0] === "remove-tree").map((x) => x.args);
  assert.deepEqual(crm.map((x) => x.slice(0, 6)), [
    ["remove-tree", "--contents", "--anchor", "/srv/sagebrush/archive", "--name", c.id],
    ["remove-tree", "--contents", "--anchor", "/srv/sagebrush/archive-config", "--name", c.id],
  ]);
  assert.deepEqual(readExpect(flag(crm[0], "expect")).owners, [0, 70000]);
  assert.deepEqual(readExpect(flag(crm[1], "expect")), { epoch: EPOCH, fsid: FSID, root: rootObj, owners: [0] });
  const f = setup("archive", { answer: (args) => (args[0] === "remove-tree" ? { code: 73, stdout: "" } : { code: 0, stdout: line({ epoch: EPOCH, fsid: FSID, object: obj() }) }) });
  await rejects(f.a.cleanDest(step(newRecord({ kind: "archive", id: f.id, run: RUN, snapshot: SNAP }), "bind", { dest: { archive: destOf(obj()), "archive-config": destOf(obj({ ino: 4244 })) } })), "outcome_unknown");
});

test("discardStaging: every attempt of the set under the staging anchor, any run, but the live one while staging or published; strangers left alone", async () => {
  const s = setup("agent");
  const owner = `a-${s.id}`;
  for (const [run, cls, att] of [[RUN, "home", "1"], [RUN, "home", "2"], [RUN, "sessions", "2"], [RUN2, "home", "1"]]) mkdirSync(join(s.staging, run, owner, cls, att), { recursive: true });
  mkdirSync(join(s.staging, "not-a-run", owner, "home", "1"), { recursive: true });
  mkdirSync(join(s.staging, RUN, owner, "home", "01"), { recursive: true });
  mkdirSync(join(s.staging, RUN, `a-${newId()}`, "home", "1"), { recursive: true }); // another set's
  let r = newRecord({ kind: "agent", id: s.id, run: RUN, snapshot: SNAP });
  r = step(r, "bind", { dest: { home: destOf(obj()), sessions: destOf(obj()) } });
  r = step(r, "retry"); // staging, attempt 2
  await s.a.discardStaging(r);
  const removed = s.calls.filter((c) => c.args[0] === "remove-tree").map((c) => flag(c.args, "name"));
  assert.deepEqual(removed.sort(), [`${RUN}/${owner}/home/1`, `${RUN2}/${owner}/home/1`].sort(), "attempt 2 (the live one) kept; strangers untouched");
  assert.ok(s.calls.filter((c) => c.args[0] === "remove-tree").every((c) => c.args[2] === s.staging && readExpect(flag(c.args, "expect")).owners.join() === "0"));
  // Settled: nothing kept.
  s.calls.length = 0;
  await s.a.discardStaging(step(r, "failed", { reason: "not_found" }));
  assert.equal(s.calls.filter((c) => c.args[0] === "remove-tree").length, 4);
  // No staging at all: nothing to do; an attempt identify reports gone: skipped.
  const t = setup("archive", { answer: (args) => (args[0] === "identify" ? { code: 0, stdout: line({ epoch: EPOCH, fsid: FSID, object: null }) } : { code: 0, stdout: "" }) });
  await t.a.discardStaging(newRecord({ kind: "archive", id: t.id, run: RUN, snapshot: SNAP }));
  mkdirSync(join(t.staging, RUN, `a-${t.id}`, "archive", "1"), { recursive: true });
  await t.a.discardStaging(step(newRecord({ kind: "archive", id: t.id, run: RUN, snapshot: SNAP }), "failed", { reason: "not_found" }));
  assert.equal(t.calls.filter((c) => c.args[0] === "remove-tree").length, 0);
});

test("removeCopies, stopped, projidOf, unrestorableOf: from the input and live", async () => {
  const s = setup("tag", { owners: { uids: [70001, 70002], gid: 80001, projid: 80001 }, members: [{ agent: newId(), uid: 70001 }, { agent: newId(), uid: 70002 }] });
  await s.a.removeCopies({ run: RUN });
  assert.deepEqual(s.calls.map((c) => c.args.slice(0, 5)), [["identify", "--anchor", s.copies, "--name", `${RUN}/t-${s.id}`], ["remove-tree", "--anchor", s.copies, "--name", `${RUN}/t-${s.id}`]]);
  assert.equal(await s.a.stopped(), true);
  const [m1, m2] = s.input.members;
  s.fenced.delete(m2.agent);
  assert.equal(await s.a.stopped(), false, "a member not restore-fenced");
  s.fenced.add(m2.agent);
  s.empty.delete(m1.agent);
  assert.equal(await s.a.stopped(), false, "a member's slice not empty");
  const ar = setup("archive");
  assert.equal(await ar.a.stopped(), true, "an archive has no one to stop");
  assert.equal(s.a.projidOf("tag", s.id), 80001);
  assert.deepEqual(s.a.unrestorableOf("tag", s.id, "tag"), ["tag/skipped"]);
  assert.throws(() => s.a.unrestorableOf("tag", newId(), "tag"), (e) => e.code === "bad_form");
});
