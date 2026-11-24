// Profiles piece 2 (host Claude profiles r2.1 §4, advisor r3.2 §8–§9, launcher amendment A4 r2.3 §2): the lifecycle of
// a profile directory against a fake host: real files under a temp root, owners kept by the test (chown needs root),
// and a fake runner for check-parents, setquota, chattr, lsattr, quota and the launcher's identify, profile-mounts and
// remove-tree. Each state is committed before the effects it allows; removal runs only after the drain, the login stop
// and a fresh storage-uid proof; an absent profile is gone only on positive evidence.
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { newId } from "../lib/fleet/index.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { PROFILES_ROOT, PROFILE_QUOTA_INODES, PROFILE_QUOTA_KB, profileDir, profileForbiddenRoots, profileLifecycle } from "../lib/fleet/host/profile-life.mjs";
import { STORAGE_UID_RANGE } from "../lib/fleet/host/profiles.mjs";

// process.getuid doesn't exist off POSIX; there every test here is skipped (host-linux-only), so ME is never used.
const ME = process.getuid?.() ?? -1;
const CL = { harness: "claude", provider: null, auth: "subscription" };
const BOOT = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";

/** A fake host. `h.calls` logs every command and adapter call in order. */
async function host({ continuity = ["projects"], quota = { mount: "/srv" }, seed = null } = {}) {
  const root = mkdtempSync(join(tmpdir(), "sb-prof-"));
  fs.mkdirSync(join(root, "srv/sagebrush"), { recursive: true });
  const owners = new Map(), labels = new Map(), limits = new Map(), inos = new Map();
  let nextIno = 100;
  const rel = (p) => p.slice(root.length);
  const fds = new Map(), events = [], immut = new Set(), inoOf = new Map();
  const fsx = {
    ...fs,
    chownSync: (p, uid, gid) => { owners.set(rel(p), [uid, gid]); events.push(`chown ${rel(p)}`); },
    mkdirSync: (p, o) => { const r = fs.mkdirSync(p, o); events.push(`mkdir ${rel(p)}`); return r; },
    openSync: (p, ...a) => { const fd = fs.openSync(p, ...a); fds.set(fd, rel(p)); return fd; },
    fsyncSync: (fd) => {
      if (h.fsyncFail === fds.get(fd)) throw Object.assign(new Error("EIO"), { code: "EIO" });
      fs.fsyncSync(fd);
      events.push(`fsync ${fds.get(fd)}`);
    },
    lstatSync: (p, o) => {
      const st = fs.lstatSync(p, o);
      const own = owners.get(rel(p)), ino = inoOf.get(rel(p));
      if (own || ino !== undefined) return Object.assign(Object.create(Object.getPrototypeOf(st)), st, own ? { uid: own[0], gid: own[1] } : {}, ino !== undefined ? { ino } : {});
      return st;
    },
  };
  const h = {
    root, owners, labels, limits, calls: [], fsid: "00000000abcd1234", epoch: { boot_id: BOOT, mnt_id: 20 },
    codes: {}, held: { empty: true, holders: [] }, drainFails: false, loginFails: false, events, immut, inoOf, dirMnt: null,
  };
  const ident = (pid) => {
    const p = profileDir(pid);
    let st;
    try { st = fsx.lstatSync(join(root, p)); } catch { return { epoch: h.epoch, fsid: h.fsid, object: null }; }
    if (!inos.has(p)) inos.set(p, nextIno++);
    const l = labels.get(p) ?? { id: 0, inherit: false };
    return { epoch: h.epoch, fsid: h.fsid, object: { type: "dir", mode: st.mode & 0o7777, uid: st.uid, gid: st.gid, dev: [8, 1], ino: inos.get(p), gen: 7, mnt_id: h.dirMnt ?? h.epoch.mnt_id, projid: l.id, inherit: l.inherit } };
  };
  h.ident = ident;
  h.inos = inos;
  const run = async (argv) => {
    const [cmd, ...a] = argv;
    const name = cmd === "/rel/bin/sagebrush-agent-launch" ? a[0] : cmd;
    h.calls.push(cmd === "/rel/bin/sagebrush-agent-launch" ? `launch ${a.join(" ")}` : argv.join(" "));
    const code = h.codes[name];
    if (code !== undefined && code !== 0) return { code, stdout: "" };
    switch (name) {
      case "check-parents": return { code: 0, stdout: "" };
      case "setquota": limits.set(a[1], { kb: Number(a[3]), inodes: Number(a[5]) }); return { code: 0, stdout: "" };
      case "chattr": if (!h.noLabel) labels.set(rel(a[3]), { id: Number(a[2]), inherit: true }); return { code: 0, stdout: "" };
      case "lsattr": {
        if (a[0] === "-d") return { code: 0, stdout: `${immut.has(rel(a[1])) ? "----i------------" : "-----------------"} ${a[1]}\n` };
        const l = labels.get(rel(a[2])) ?? { id: 0, inherit: false };
        return { code: 0, stdout: `${l.id} ${l.inherit ? "--------------P--" : "-----------------"} ${a[2]}\n` };
      }
      case "quota": {
        const q = limits.get(a[a.length - 1]) ?? { kb: 0, inodes: 0 };
        const kb = h.badLimit ? q.kb - 1 : q.kb;
        return { code: 0, stdout: `Disk quotas for project #${a[a.length - 1]}:\n     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n      /dev/sda1       0       0 ${kb}       0       0       0  ${q.inodes}       0\n` };
      }
      case "identify": return { code: 0, stdout: JSON.stringify(ident(a[4])) };
      case "profile-mounts": {
        const pid = a[2], op = a[4];
        if (op === "create") {
          const subs = [];
          for (let i = 5; i < a.length; i += 2) if (a[i] === "--subpath") subs.push(a[i + 1]);
          return { code: 0, stdout: JSON.stringify(subs.map((s) => {
            const mp = join(profileDir(pid), s);
            fs.mkdirSync(join(root, mp), { recursive: true });
            fs.chmodSync(join(root, mp), 0o555);
            owners.set(mp, [0, 0]);
            immut.add(mp);
            return { name: s, ino: fs.lstatSync(join(root, mp)).ino, gen: 9 };
          })) };
        }
        h.cleared = (h.cleared ?? 0) + 1;
        return { code: 0, stdout: "" };
      }
      case "remove-tree": {
        const pid = a[4];
        h.lastExpect = JSON.parse(fs.readFileSync(join(root, a[6]), "utf8"));
        if (h.removeHook) return h.removeHook(pid);
        const now = ident(pid).object; // the launcher: an absent target syncs the anchor (0); another object refuses
        if (now !== null && now.ino !== h.lastExpect.root.ino) return { code: 73, stdout: "" };
        fs.rmSync(join(root, profileDir(pid)), { recursive: true, force: true });
        return { code: 0, stdout: "" };
      }
      default: throw new Error(`unexpected command ${argv.join(" ")}`);
    }
  };
  if (seed) seed(join(root, "store"));
  const store = await HostStore.open(join(root, "store"));
  h.store = store;
  // The store's profiles, with markBound logged in the event order (durability before `bound`).
  const logged = new Proxy(store.profiles, { get: (t, k) => {
    if (k === "markBound") return (pid) => { events.push(`bound ${pid}`); return t.markBound(pid); };
    const v = t[k];
    return typeof v === "function" ? v.bind(t) : v;
  } });
  h.life = profileLifecycle({
    profiles: logged, run, launcher: "/rel/bin/sagebrush-agent-launch", quota, fsx, root, rootUid: ME,
    continuity: () => continuity,
    drain: async (pid) => { h.calls.push(`drain ${pid}`); if (h.drainFails) throw new Error("busy"); },
    loginStop: async (pid) => { h.calls.push(`login-stop ${pid}`); if (h.loginFails) throw new Error("live"); },
    uidProof: async (uid) => { h.calls.push(`uid-proof ${uid}`); h.onProof?.(); return h.held; },
  });
  return h;
}

const kinds = (h) => h.calls.map((c) => c.split(" ").slice(0, 2).join(" "));
const launcherCalls = (h) => h.calls.filter((c) => c.startsWith("launch ") && !c.startsWith("launch check-parents"));
const T = 30000;

test("create: the fixed parents first, INIT, quota and label VERIFIED (limits through quota -P), published to the storage uid, mountpoints, then bound", async () => {
  const h = await host();
  const pid = newId();
  assert.deepEqual(await h.life.create(pid, CL, newId(), T), { status: "bound" });
  const r = h.store.profiles.profile(pid);
  assert.equal(r.state, "bound");
  assert.deepEqual(r.mountpoints, [{ name: "projects", ino: fs.lstatSync(join(h.root, profileDir(pid), "projects")).ino, gen: 9 }]);
  assert.deepEqual(h.owners.get(profileDir(pid)), [r.storage_uid, r.storage_uid]);
  assert.equal(fs.statSync(join(h.root, profileDir(pid))).mode & 0o7777, 0o700);
  assert.deepEqual(h.limits.get(String(r.project_id)), { kb: PROFILE_QUOTA_KB, inodes: PROFILE_QUOTA_INODES });
  assert.deepEqual(kinds(h), ["launch check-parents", "launch check-parents", "launch check-parents", "setquota -P", "chattr +P", "lsattr -p", "quota -P", "launch identify", "launch profile-mounts"]);
  assert.ok(h.calls[0].endsWith("--allow-missing") && !h.calls[1].endsWith("--allow-missing"));
  assert.match(h.calls.at(-1), /--subpath projects --expect-dir \/run\/sagebrush\/profiles\//);
  await h.store.close();
});

test("create refuses without quotas, before anything; a label or a limit that didn't take stops it at creating", async () => {
  const h0 = await host({ quota: null });
  const pid0 = newId();
  assert.equal((await h0.life.create(pid0, CL, newId(), T)).status, "refused");
  assert.equal(h0.store.profiles.profile(pid0), null);
  assert.deepEqual(h0.calls, []);
  await h0.store.close();
  for (const knob of ["noLabel", "badLimit"]) {
    const h = await host();
    h[knob] = true;
    const pid = newId();
    await assert.rejects(h.life.create(pid, CL, newId(), T), /didn't take/);
    assert.equal(h.store.profiles.profile(pid).state, "creating");
    assert.equal(h.owners.get(profileDir(pid))?.[0], ME, `${knob}: never published to the storage uid`);
    // fixed, then recovery finishes it
    h[knob] = false;
    assert.equal((await h.life.recover(T)).profiles[pid].status, "bound");
    await h.store.close();
  }
});

test("recovery of creating: INIT and OWNED+labelled finish; OWNED without its label, or a populated directory, park", async () => {
  for (const [label, setup, want] of [
    ["init", () => {}, "bound"],
    ["owned+labelled", (h, pid, r) => { h.owners.set(profileDir(pid), [r.storage_uid, r.storage_uid]); h.labels.set(profileDir(pid), { id: r.project_id, inherit: true }); }, "bound"],
    ["owned, no label", (h, pid, r) => { h.owners.set(profileDir(pid), [r.storage_uid, r.storage_uid]); }, "parked"],
    ["populated", (h, pid) => { fs.writeFileSync(join(h.root, profileDir(pid), "x"), "y"); }, "parked"],
    ["a declared mountpoint inside", (h, pid, r) => { h.owners.set(profileDir(pid), [r.storage_uid, r.storage_uid]); h.labels.set(profileDir(pid), { id: r.project_id, inherit: true }); fs.mkdirSync(join(h.root, profileDir(pid), "projects")); }, "bound"],
  ]) {
    const h = await host();
    const pid = newId();
    h.store.profiles.beginCreate(pid, CL, newId());
    const r = h.store.profiles.profile(pid);
    fs.mkdirSync(join(h.root, PROFILES_ROOT, ".locks"), { recursive: true, mode: 0o700 });
    fs.chmodSync(join(h.root, PROFILES_ROOT), 0o700);
    fs.mkdirSync(join(h.root, profileDir(pid)), { mode: 0o700 });
    setup(h, pid, r);
    assert.equal((await h.life.recover(T)).profiles[pid].status, want, label);
    await h.store.close();
  }
});

async function bound(opts) {
  const h = await host(opts);
  const pid = newId();
  await h.life.create(pid, CL, newId(), T);
  h.calls.length = 0;
  return { h, pid, r: h.store.profiles.profile(pid) };
}

test("retire: retiring first, then drain, login stop and a fresh uid proof, and only then the launcher; removal recorded before remove-tree", async () => {
  const { h, pid, r } = await bound();
  assert.deepEqual(await h.life.retire(pid, T), { status: "retired" });
  assert.deepEqual(kinds(h), [`drain ${pid}`, `login-stop ${pid}`, `uid-proof ${r.storage_uid}`, "launch identify", "launch profile-mounts", "launch remove-tree"]);
  const after = h.store.profiles.profile(pid);
  assert.equal(after.state, "retired");
  assert.equal(after.gen, 2);
  assert.deepEqual(after.removal.owners, [ME, r.storage_uid]);
  assert.deepEqual(h.lastExpect, after.removal, "remove-tree got exactly the recorded expect");
  assert.equal(fs.existsSync(join(h.root, profileDir(pid))), false);
  await h.store.close();
});

test("a live storage uid, a failed drain or a failed login stop: pending, ZERO launcher calls, still retiring", async () => {
  for (const spoil of [(h) => { h.held = { empty: false, holders: ["pid 77"] }; }, (h) => { h.drainFails = true; }, (h) => { h.loginFails = true; }]) {
    const { h, pid } = await bound();
    spoil(h);
    const out = await h.life.retire(pid, T);
    assert.equal(out.status, "pending");
    assert.deepEqual(launcherCalls(h), []);
    assert.equal(h.store.profiles.profile(pid).state, "retiring");
    assert.equal(h.store.profiles.profile(pid).removal, null);
    await h.store.close();
  }
});

test("no mountpoints recorded (continuity none): no clear", async () => {
  const { h, pid } = await bound({ continuity: [] });
  assert.equal((await h.life.retire(pid, T)).status, "retired");
  assert.ok(!h.calls.some((c) => c.includes("profile-mounts")));
  await h.store.close();
});

test("absent-profile retries complete only on positive evidence; everything else parks", async () => {
  // remove-tree removes the profile, then fails its anchor fsync (75): pending, removal recorded.
  const setup = async () => {
    const { h, pid, r } = await bound();
    h.removeHook = (p) => { fs.rmSync(join(h.root, profileDir(p)), { recursive: true }); return { code: 75, stdout: "" }; };
    assert.equal((await h.life.retire(pid, T)).status, "pending");
    assert.notEqual(h.store.profiles.profile(pid).removal, null);
    h.removeHook = null;
    h.calls.length = 0;
    return { h, pid, r };
  };
  { // same epoch: remove-tree with the recorded expect, no clear; 0 completes
    const { h, pid } = await setup();
    const rec = h.store.profiles.profile(pid).removal;
    assert.equal((await h.life.retire(pid, T)).status, "retired");
    assert.ok(!h.calls.some((c) => c.includes("profile-mounts")));
    assert.deepEqual(h.lastExpect, rec);
    await h.store.close();
  }
  { // same epoch, but remove-tree refuses (an unrelated 73): parked, NOT retired
    const { h, pid } = await setup();
    h.codes["remove-tree"] = 73;
    assert.equal((await h.life.retire(pid, T)).status, "parked");
    assert.equal(h.store.profiles.profile(pid).state, "retiring");
    await h.store.close();
  }
  { // a verified reboot (another boot id), the same fsid: durably gone, NO remove-tree call
    const { h, pid } = await setup();
    h.epoch = { boot_id: "11111111-2222-3333-4444-555555555555", mnt_id: 31 };
    assert.equal((await h.life.retire(pid, T)).status, "retired");
    assert.ok(!h.calls.some((c) => c.includes("remove-tree")));
    await h.store.close();
  }
  for (const [label, spoil] of [
    ["a remount in one boot", (h) => { h.epoch = { ...h.epoch, mnt_id: 99 }; }],
    ["another filesystem", (h) => { h.fsid = "00000000ffff0000"; }],
    ["another filesystem after a reboot", (h) => { h.epoch = { boot_id: "11111111-2222-3333-4444-555555555555", mnt_id: 31 }; h.fsid = "00000000ffff0000"; }],
  ]) {
    const { h, pid } = await setup();
    spoil(h);
    assert.equal((await h.life.retire(pid, T)).status, "parked", label);
    assert.ok(!h.calls.some((c) => c.includes("remove-tree")), label);
    assert.equal(h.store.profiles.profile(pid).state, "retiring", label);
    await h.store.close();
  }
});

test("a present object with a removal recorded: the same durable object continues (re-recorded); a replacement parks", async () => {
  const setup = async () => {
    const { h, pid } = await bound();
    h.removeHook = () => ({ code: 75, stdout: "" }); // nothing removed, a 75
    await h.life.retire(pid, T);
    h.removeHook = null;
    h.calls.length = 0;
    return { h, pid };
  };
  { // after a reboot, the same durable object: the new identity is recorded, then the normal path
    const { h, pid } = await setup();
    h.epoch = { boot_id: "11111111-2222-3333-4444-555555555555", mnt_id: 31 };
    assert.equal((await h.life.retire(pid, T)).status, "retired");
    assert.equal(h.lastExpect.epoch.mnt_id, 31, "re-recorded in the current epoch");
    await h.store.close();
  }
  { // a replacement at the name (another inode): parked, no remove-tree
    const { h, pid } = await setup();
    h.inos.set(profileDir(pid), 9999);
    assert.equal((await h.life.retire(pid, T)).status, "parked");
    assert.ok(!h.calls.some((c) => c.includes("remove-tree")));
    await h.store.close();
  }
});

test("clear's 75 is pending and its 73 parks; a directory that isn't this profile's parks before any removal", async () => {
  for (const [code, want] of [[75, "pending"], [73, "parked"]]) {
    const { h, pid } = await bound();
    h.codes["profile-mounts"] = code;
    assert.equal((await h.life.retire(pid, T)).status, want);
    assert.ok(!h.calls.some((c) => c.includes("remove-tree")));
    await h.store.close();
  }
  for (const spoil of [(h, pid) => fs.chmodSync(join(h.root, profileDir(pid)), 0o755), (h, pid) => h.owners.set(profileDir(pid), [4242, 4242])]) {
    const { h, pid } = await bound();
    spoil(h, pid);
    assert.equal((await h.life.retire(pid, T)).status, "parked");
    assert.ok(!h.calls.some((c) => c.includes("remove-tree") || c.includes("profile-mounts")));
    await h.store.close();
  }
});

test("recovery: a retired leftover is removed after the login stop and the proof (no drain); a corrupt bound profile and orphans are reported", async () => {
  const { h, pid, r } = await bound();
  await h.life.retire(pid, T);
  fs.mkdirSync(join(h.root, profileDir(pid)), { mode: 0o700 }); // a leftover after a crash
  h.owners.set(profileDir(pid), [r.storage_uid, r.storage_uid]);
  h.labels.set(profileDir(pid), { id: r.project_id, inherit: true });
  const b = newId();
  await h.life.create(b, CL, newId(), T);
  fs.chmodSync(join(h.root, profileDir(b)), 0o755); // corrupt
  const orphan = newId();
  fs.mkdirSync(join(h.root, profileDir(orphan)));
  h.calls.length = 0;
  const out = await h.life.recover(T);
  assert.equal(out.profiles[pid].status, "removed");
  assert.ok(!h.calls.includes(`drain ${pid}`));
  assert.ok(h.calls.indexOf(`uid-proof ${r.storage_uid}`) < h.calls.findIndex((c) => c.startsWith("launch identify")));
  assert.equal(out.profiles[b].status, "parked");
  assert.deepEqual(out.orphans, [orphan]);
  assert.equal(h.store.profiles.profile(pid).state, "retired", "never recreated");
  await h.store.close();
});

test("an orphan: read-only identify, the proof, an exact re-identify, then remove-tree with owners [storage uid] only", async () => {
  const SU = STORAGE_UID_RANGE[0] + 3;
  const mk = async () => {
    const h = await host();
    await h.life.create(newId(), CL, newId(), T); // makes the roots
    const pid = newId();
    fs.mkdirSync(join(h.root, profileDir(pid)), { mode: 0o700 });
    h.owners.set(profileDir(pid), [SU, SU]);
    h.calls.length = 0;
    return { h, pid };
  };
  { const { h, pid } = await mk();
    assert.deepEqual(await h.life.removeOrphan(pid, T), { status: "removed" });
    assert.deepEqual(kinds(h), ["launch identify", `login-stop ${pid}`, `uid-proof ${SU}`, "launch identify", "launch remove-tree"]);
    assert.deepEqual(h.lastExpect.owners, [SU]);
    await h.store.close(); }
  { const { h, pid } = await mk();
    h.held = { empty: false, holders: ["pid 9"] };
    assert.equal((await h.life.removeOrphan(pid, T)).status, "refused");
    assert.deepEqual(launcherCalls(h).map((c) => c.split(" ")[1]), ["identify"], "only the read-only identify");
    await h.store.close(); }
  { const { h, pid } = await mk();
    h.onProof = () => h.inos.set(profileDir(pid), 7777); // another inode at the name, swapped in during the proof
    assert.equal((await h.life.removeOrphan(pid, T)).status, "refused");
    assert.ok(!h.calls.some((c) => c.includes("remove-tree")));
    await h.store.close(); }
  { const { h, pid } = await mk();
    h.owners.set(profileDir(pid), [ME, ME]); // not a storage uid's
    assert.equal((await h.life.removeOrphan(pid, T)).status, "refused");
    assert.ok(!h.calls.some((c) => c.includes("remove-tree") || c.startsWith("uid-proof")));
    await h.store.close(); }
  { const { h } = await mk();
    const rec = newId();
    await h.life.create(rec, CL, newId(), T);
    assert.equal((await h.life.removeOrphan(rec, T)).status, "refused", "a recorded profile is never an orphan");
    await h.store.close(); }
});

test("create syncs the new entry's parent after its mkdir, and the directory and its parent after publishing, before bound", async () => {
  for (const continuity of [[], ["projects"]]) {
    const h = await host({ continuity });
    const pid = newId();
    assert.equal((await h.life.create(pid, CL, newId(), T)).status, "bound");
    const ev = h.events, d = profileDir(pid), at = (e) => ev.indexOf(e), last = (e) => ev.lastIndexOf(e);
    const mk = at(`mkdir ${d}`), pub = last(`chown ${d}`), bnd = at(`bound ${pid}`);
    assert.ok(mk >= 0 && pub > mk && bnd > pub, `${continuity}: ${ev.join(", ")}`);
    assert.ok(ev.slice(mk, pub).includes(`fsync ${PROFILES_ROOT}`), `${continuity}: the root synced after the mkdir`);
    const after = ev.slice(pub, bnd);
    assert.ok(after.includes(`fsync ${d}`) && after.includes(`fsync ${PROFILES_ROOT}`), `${continuity}: synced after publishing, before bound`);
    await h.store.close();
  }
});

test("the roots: each made directory and its parent entry synced, the first time and on every retry, before anything beneath", async () => {
  const h = await host();
  const pid = newId();
  assert.equal((await h.life.create(pid, CL, newId(), T)).status, "bound");
  const ev = h.events, PARENT = "/srv/sagebrush", LOCKS = `${PROFILES_ROOT}/.locks`;
  const mkRoot = ev.indexOf(`mkdir ${PROFILES_ROOT}`), mkLocks = ev.indexOf(`mkdir ${LOCKS}`), mkDir = ev.indexOf(`mkdir ${profileDir(pid)}`);
  assert.ok(mkRoot >= 0 && mkLocks > mkRoot && mkDir > mkLocks, ev.join(", "));
  const between = ev.slice(mkLocks, mkDir);
  for (const d of [PARENT, PROFILES_ROOT, LOCKS]) assert.ok(between.includes(`fsync ${d}`), `${d} synced before the profile: ${between.join(", ")}`);
  // A retry (the roots already there, perhaps never synced: a crash): synced again.
  ev.length = 0;
  const pid2 = newId();
  assert.equal((await h.life.create(pid2, CL, newId(), T)).status, "bound");
  const before = ev.slice(0, ev.indexOf(`mkdir ${profileDir(pid2)}`));
  for (const d of [PARENT, PROFILES_ROOT, LOCKS]) assert.ok(before.includes(`fsync ${d}`), `retry: ${d}: ${before.join(", ")}`);
  // A creating profile whose directory a crash left unsynced: recovery syncs its entry before going on.
  const pid3 = newId();
  h.store.profiles.beginCreate(pid3, CL, newId());
  fs.mkdirSync(join(h.root, profileDir(pid3)), { mode: 0o700 });
  ev.length = 0;
  assert.equal((await h.life.recover(T)).profiles[pid3].status, "bound");
  const firstSet = ev.findIndex((e) => e === `chown ${profileDir(pid3)}`);
  assert.ok(ev.slice(0, firstSet).includes(`fsync ${PROFILES_ROOT}`), ev.join(", "));
  await h.store.close();
  // A failed sync of a root's parent (or of a root) stops creation before `creating` is committed; a retry syncs again.
  for (const bad of [PARENT, PROFILES_ROOT, LOCKS]) {
    const f = await host();
    f.fsyncFail = bad;
    const p = newId();
    await assert.rejects(f.life.create(p, CL, newId(), T), /EIO/, bad);
    assert.equal(f.store.profiles.profile(p), null, `${bad}: nothing committed`);
    assert.ok(!f.calls.some((c) => c.startsWith("setquota")), `${bad}: nothing beneath`);
    f.fsyncFail = null;
    f.events.length = 0;
    assert.equal((await f.life.create(p, CL, newId(), T)).status, "bound", `${bad}: the retry`);
    assert.ok(f.events.includes(`fsync ${bad}`), `${bad}: synced on the retry`);
    await f.store.close();
  }
});

test("bound recovery: only the exact final state passes; a lost label, mount, owner or mountpoint identity parks", async () => {
  const mp = (pid) => join(profileDir(pid), "projects");
  for (const [label, spoil, want] of [
    ["intact", () => {}, undefined],
    ["the label lost", (h, pid) => h.labels.delete(profileDir(pid)), "parked"],
    ["the limits removed", (h, pid, r) => h.limits.delete(String(r.project_id)), "parked"],
    ["the limits zeroed", (h, pid, r) => h.limits.set(String(r.project_id), { kb: 0, inodes: 0 }), "parked"],
    ["the block limit differs", (h, pid, r) => h.limits.set(String(r.project_id), { kb: PROFILE_QUOTA_KB * 2, inodes: PROFILE_QUOTA_INODES }), "parked"],
    ["the inode limit differs", (h, pid, r) => h.limits.set(String(r.project_id), { kb: PROFILE_QUOTA_KB, inodes: 1 }), "parked"],
    ["quota -P fails", (h) => { h.codes.quota = 1; }, "parked"],
    ["inherit lost", (h, pid, r) => h.labels.set(profileDir(pid), { id: r.project_id, inherit: false }), "parked"],
    ["another project", (h, pid, r) => h.labels.set(profileDir(pid), { id: r.project_id + 1, inherit: true }), "parked"],
    ["another mount", (h) => { h.dirMnt = 77; }, "parked"],
    ["the owner", (h, pid) => h.owners.set(profileDir(pid), [ME, ME]), "parked"],
    ["the mode", (h, pid) => fs.chmodSync(join(h.root, profileDir(pid)), 0o750), "parked"],
    ["missing", (h, pid) => { fs.chmodSync(join(h.root, mp(pid)), 0o755); fs.rmSync(join(h.root, profileDir(pid)), { recursive: true }); }, "parked"],
    ["a mountpoint not immutable", (h, pid) => h.immut.delete(mp(pid)), "parked"],
    ["a mountpoint's inode", (h, pid) => h.inoOf.set(mp(pid), 4242), "parked"],
    ["a mountpoint's mode", (h, pid) => fs.chmodSync(join(h.root, mp(pid)), 0o755), "parked"],
    ["a mountpoint's owner", (h, pid) => h.owners.set(mp(pid), [ME, ME]), "parked"],
    ["a mountpoint gone", (h, pid) => { fs.rmdirSync(join(h.root, mp(pid))); }, "parked"],
  ]) {
    const { h, pid, r } = await bound();
    spoil(h, pid, r);
    assert.equal((await h.life.recover(T)).profiles[pid]?.status, want, label);
    assert.equal(h.store.profiles.profile(pid).state, "bound", `${label}: reported, not changed`);
    await h.store.close();
  }
});

test("recovery reports a piece-1 bound record (no mountpoints) as parked, never startable; it retires", async () => {
  const pid = newId();
  const h = await host({ continuity: [], seed: (dir) => {
    fs.mkdirSync(join(dir, "profiles"), { recursive: true, mode: 0o700 });
    fs.writeFileSync(join(dir, "profiles", "profiles.json"), JSON.stringify({ v: 2, next_storage_uid: STORAGE_UID_RANGE[0] + 1, next_project: 100001, profiles: {
      [pid]: { harness: "claude", provider: null, auth: "subscription", sub: newId(), storage_uid: STORAGE_UID_RANGE[0], project_id: 100000, gen: 1, state: "bound" } } }), { mode: 0o600 });
  } });
  await h.life.create(newId(), CL, newId(), T); // a commit (the upgrade) and the roots
  assert.equal(h.store.profiles.profile(pid).mountpoints, null);
  const out = await h.life.recover(T);
  assert.equal(out.profiles[pid].status, "parked");
  assert.match(out.profiles[pid].reason, /never selectable/);
  assert.equal((await h.life.retire(pid, T)).status, "retired"); // never made: nothing to remove
  await h.store.close();
});

test("an orphan whose remove-tree unlinked it and then failed (75): the absent retry resyncs through remove-tree, never claims removed itself", async () => {
  const SU = STORAGE_UID_RANGE[0] + 3;
  const mk = async () => {
    const h = await host();
    await h.life.create(newId(), CL, newId(), T);
    const pid = newId();
    fs.mkdirSync(join(h.root, profileDir(pid)), { mode: 0o700 });
    h.owners.set(profileDir(pid), [SU, SU]);
    h.removeHook = (p) => { fs.rmSync(join(h.root, profileDir(p)), { recursive: true }); return { code: 75, stdout: "" }; };
    assert.equal((await h.life.removeOrphan(pid, T)).status, "pending");
    assert.equal(fs.existsSync(join(h.root, profileDir(pid))), false);
    h.removeHook = null;
    h.calls.length = 0;
    return { h, pid };
  };
  { const { h, pid } = await mk(); // the anchor sync succeeds: removed, through remove-tree, with no proof (nothing there)
    assert.deepEqual(await h.life.removeOrphan(pid, T), { status: "removed" });
    assert.deepEqual(kinds(h), ["launch identify", "launch remove-tree"]);
    assert.equal(h.lastExpect.root.ino, 0, "an expect that matches no object");
    assert.deepEqual(h.lastExpect.epoch, h.epoch);
    await h.store.close(); }
  { const { h, pid } = await mk(); // the sync fails again: pending, not removed
    h.codes["remove-tree"] = 75;
    assert.equal((await h.life.removeOrphan(pid, T)).status, "pending");
    await h.store.close(); }
  { const { h, pid } = await mk(); // something appeared at the name meanwhile: refused (73), nothing removed
    h.removeHook = (p) => { fs.mkdirSync(join(h.root, profileDir(p)), { mode: 0o700 }); return { code: 73, stdout: "" }; };
    assert.equal((await h.life.removeOrphan(pid, T)).status, "refused");
    await h.store.close(); }
});

test("profileForbiddenRoots: the one profiles root", () => {
  assert.deepEqual(profileForbiddenRoots(), ["/srv/sagebrush/claude-profiles"]);
  assert.ok(Object.isFrozen(profileForbiddenRoots()));
});
