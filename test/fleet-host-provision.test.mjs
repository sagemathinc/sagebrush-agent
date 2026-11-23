// Host supervisor freeze r3.1 §2.2, §5.2-§5.4: provisioning a new agent. A scripted runner keeps an in-memory passwd and
// group database that useradd and groupadd change, and an ownership overlay stands in for chown, so every check runs
// without root: exact argv, no subordinate ids, exact owners and modes, project quotas, and refusal of anything that
// exists and differs.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError } from "../lib/fleet/index.mjs";
import { NOLOGIN, QUOTA_INODES, provisioner } from "../lib/fleet/host/provision.mjs";

const A = "abcdefghijklmnopqrstuvwxya", T1 = "tagtagtagtagtagtagtagtagaa", T2 = "bbbbbbbbbbbbbbbbbbbbbbbbbe";
const UID = 70000, G1 = 80000, G2 = 80001;
const USER = `sb-${A}`, HOME = `/srv/sagebrush/agents/${A}/home`;
const host = (e) => !(e instanceof FleetError) && e.code === "effect_failed";
const grantAgent = (over = {}) => ({ agent: A, client: "claude", root: false, tags: [T1, T2], config: { resources: { disk_gb: 50 } }, ...over });

let seq = 0;
function setup({ quota = { mount: "/srv" }, passwd = {}, group = {}, over = {}, refuseCheck = null } = {}) {
  const root = join(os.tmpdir(), `sb-prov-${process.pid}-${seq++}`);
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(join(root, "etc"), { recursive: true });
  fs.mkdirSync(join(root, "srv"), { recursive: true }); // as on any Ubuntu host
  fs.writeFileSync(join(root, "etc/subuid"), "someone:100000:65536\n");
  fs.writeFileSync(join(root, "etc/subgid"), "someone:100000:65536\n");
  const db = { passwd: { ...passwd }, group: { ...group } }; // name -> fields
  const proj = new Map(); // path -> { id, inherit }: what chattr wrote, what lsattr reads (default: id 0, no flag)
  const calls = [];
  const run = async (argv, { ms }) => {
    assert.ok(ms > 0);
    calls.push(argv);
    for (const [m, fn] of Object.entries(over)) if (argv.join(" ").includes(m)) { const r = fn(argv); if (r) return { stdout: "", stderr: "", ...r }; }
    const [cmd, ...a] = argv;
    if (cmd === "getent") {
      const [d, key] = a;
      const hit = Object.values(db[d]).find((f) => f[0] === key || f[2] === key);
      return hit ? { code: 0, stdout: `${hit.join(":")}\n`, stderr: "" } : { code: 2, stdout: "", stderr: "" };
    }
    if (cmd === "chattr") { proj.set(a.at(-1), { id: Number(a[2]), inherit: true }); return { code: 0, stdout: "", stderr: "" }; }
    if (cmd === "lsattr") {
      const st = proj.get(a.at(-1)) ?? { id: 0, inherit: false };
      return { code: 0, stdout: `${String(st.id).padStart(5)} ${st.inherit ? "--------------e-------P" : "--------------e--------"} ${a.at(-1)}\n`, stderr: "" };
    }
    if (cmd === "groupadd") { db.group[a[2]] = [a[2], "x", a[1], ""]; return { code: 0, stdout: "", stderr: "" }; }
    if (cmd === "useradd") {
      const get = (k) => a[a.indexOf(k) + 1];
      const name = a.at(-1);
      db.passwd[name] = [name, "x", get("--uid"), get("--gid"), get("--comment"), get("--home-dir"), get("--shell")];
      return { code: 0, stdout: "", stderr: "" };
    }
    return { code: 0, stdout: "", stderr: "" };
  };
  const owner = new Map(); // path -> [uid, gid]
  const fsx = {
    ...fs,
    chownSync: (p, u, g) => owner.set(p, [u, g]),
    lstatSync: (p) => { const st = fs.lstatSync(p); const o = owner.get(p); return o ? Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: o[0], gid: o[1] }) : st; },
  };
  const checks = []; // the launcher's check-parents calls: allowMissing, and how many commands ran before it
  const checkParents = async (allowMissing) => {
    checks.push({ allowMissing, after: calls.length, dirs: fs.existsSync(join(root, "srv/sagebrush/agents")) });
    if (refuseCheck?.(allowMissing, checks.length)) throw Object.assign(new Error("provision: the fixed parents failed their check (73)"), { code: "effect_failed" });
  };
  const p = provisioner({ run, fsx, root, rootUid: 0, tagGid: (t) => ({ [T1]: G1, [T2]: G2 })[t], quota, checkParents });
  const runRaw = run;
  const stat = (path) => { const st = fsx.lstatSync(join(root, path)); return [st.uid, st.gid, st.mode & 0o7777]; };
  return { root, db, proj, calls, owner, p, stat, fsx, runRaw, checks };
}
const cmds = (calls, name) => calls.filter((c) => c[0] === name);
/** Every command that changes the host (getent and lsattr only read). */
const mutating = (calls) => calls.filter((c) => !["getent", "lsattr"].includes(c[0]));

test("a new agent: its tag groups, its group (gid = uid), and its user with no shell, no home made and no subordinate ids", async () => {
  const s = setup();
  await s.p.provision(A, UID, grantAgent(), 5000);
  assert.deepEqual(cmds(s.calls, "groupadd"), [["groupadd", "--gid", String(G1), `sbt-${T1}`], ["groupadd", "--gid", String(G2), `sbt-${T2}`], ["groupadd", "--gid", String(UID), USER]]);
  assert.deepEqual(cmds(s.calls, "useradd"), [["useradd", "--uid", String(UID), "--gid", String(UID), "--no-create-home", "--home-dir", HOME,
    "--shell", NOLOGIN, "--comment", "", "-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", USER]]);
  assert.deepEqual(s.db.passwd[USER], [USER, "x", String(UID), String(UID), "", HOME, NOLOGIN]);
});

test("its directories: exact owners and modes; tag folders setgid to the tag group", async () => {
  const s = setup();
  await s.p.provision(A, UID, grantAgent(), 5000);
  assert.deepEqual(s.stat("/srv/sagebrush"), [0, 0, 0o755]);
  assert.deepEqual(s.stat(`/srv/sagebrush/agents/${A}`), [0, 0, 0o755]);
  assert.deepEqual(s.stat(HOME), [UID, UID, 0o700]);
  assert.deepEqual(s.stat(`/srv/sagebrush/agents/${A}/var-tmp`), [UID, UID, 0o700]);
  // Exactly home, var-tmp and sessions in the agent directory; the config tree beside it, root-owned (L1).
  assert.deepEqual(s.stat(`/srv/sagebrush/agents/${A}/sessions`), [UID, UID, 0o700]);
  assert.deepEqual(s.fsx.readdirSync(join(s.root, `/srv/sagebrush/agents/${A}`)).sort(), ["home", "sessions", "var-tmp"]);
  assert.deepEqual(s.stat("/srv/sagebrush/agent-config"), [0, 0, 0o755]);
  assert.deepEqual(s.stat(`/srv/sagebrush/agent-config/${A}`), [0, 0, 0o700]);
  // The archive parents deprovision moves into: root-only.
  assert.deepEqual(s.stat("/srv/sagebrush/archive"), [0, 0, 0o700]);
  assert.deepEqual(s.stat("/srv/sagebrush/archive-config"), [0, 0, 0o700]);
  assert.deepEqual(s.stat(`/srv/sagebrush/tags/${T1}`), [0, G1, 0o2770]);
  assert.deepEqual(s.stat(`/srv/sagebrush/tags/${T2}`), [0, G2, 0o2770]);
});

test("project quotas: the agent's id on home and var-tmp, each tag's on its folder, inherited, with hard limits", async () => {
  const s = setup();
  await s.p.provision(A, UID, grantAgent({ config: { resources: { disk_gb: 7 } } }), 5000);
  const r = s.root;
  assert.deepEqual(cmds(s.calls, "chattr"), [
    ["chattr", "+P", "-p", String(UID), `${r}${HOME}`], ["chattr", "+P", "-p", String(UID), `${r}/srv/sagebrush/agents/${A}/var-tmp`],
    ["chattr", "+P", "-p", String(UID), `${r}/srv/sagebrush/agents/${A}/sessions`],
    ["chattr", "+P", "-p", String(UID), `${r}/srv/sagebrush/agent-config/${A}`], // the config tree is charged to the agent (L1)
    ["chattr", "+P", "-p", String(G1), `${r}/srv/sagebrush/tags/${T1}`], ["chattr", "+P", "-p", String(G2), `${r}/srv/sagebrush/tags/${T2}`],
  ]);
  const sq = cmds(s.calls, "setquota");
  assert.deepEqual(sq[0], ["setquota", "-P", String(UID), "0", String(7 * 1024 * 1024), "0", String(QUOTA_INODES), "/srv"]);
  assert.deepEqual(sq.at(-1), ["setquota", "-P", String(G2), "0", String(50 * 1024 * 1024), "0", String(QUOTA_INODES), "/srv"]);
  // Without project quotas nothing is set.
  const n = setup({ quota: null });
  await n.p.provision(A, UID, grantAgent(), 5000);
  assert.equal(cmds(n.calls, "chattr").length + cmds(n.calls, "setquota").length, 0);
  await n.p.requota(A, UID, grantAgent(), () => 1000);
  assert.equal(cmds(n.calls, "setquota").length, 0);
  await s.p.requota(A, UID, grantAgent({ config: { resources: { disk_gb: 9 } } }), () => 1000);
  assert.deepEqual(cmds(s.calls, "setquota").at(-1), ["setquota", "-P", String(UID), "0", String(9 * 1024 * 1024), "0", String(QUOTA_INODES), "/srv"]);
});

test("the config tree: a crash after mkdir and before its label is finished, then left alone; populated and unlabelled is refused", async () => {
  const cfg = `/srv/sagebrush/agent-config/${A}`;
  const s = setup();
  await s.p.provision(A, UID, grantAgent(), 5000);
  // A crash right after making it (root:root 0700, as final) and before chattr: the label is missing, the tree empty.
  s.proj.delete(`${s.root}${cfg}`);
  const before = cmds(s.calls, "chattr").length;
  await s.p.provision(A, UID, grantAgent(), 5000);
  assert.deepEqual(cmds(s.calls, "chattr").slice(before), [["chattr", "+P", "-p", String(UID), `${s.root}${cfg}`]]);
  await s.p.provision(A, UID, grantAgent(), 5000);
  assert.equal(cmds(s.calls, "chattr").length, before + 1, "labelled once: nothing redone");
  // An empty config tree carrying a FOREIGN project (or a lone inherit flag) is refused, never relabelled.
  for (const label of [{ id: 77777, inherit: true }, { id: 0, inherit: true }, { id: UID + 1, inherit: false }]) {
    s.proj.set(`${s.root}${cfg}`, label);
    const n = cmds(s.calls, "chattr").length;
    await assert.rejects(s.p.provision(A, UID, grantAgent(), 5000), /another project state/, JSON.stringify(label));
    assert.equal(cmds(s.calls, "chattr").length, n, "nothing relabelled");
  }
  s.proj.delete(`${s.root}${cfg}`);
  await s.p.provision(A, UID, grantAgent(), 5000);
  // A populated config tree without its label is never relabelled (it wouldn't charge what's already there).
  s.fsx.writeFileSync(join(s.root, `${cfg}/current`), "gen-1");
  s.proj.delete(`${s.root}${cfg}`);
  await assert.rejects(s.p.provision(A, UID, grantAgent(), 5000), /another project state/);
});

test("the fixed parents are checked by the launcher: tolerant first, strict before any effect beneath them", async () => {
  const s = setup();
  await s.p.provision(A, UID, grantAgent(), 5000);
  assert.deepEqual(s.checks.map((c) => c.allowMissing), [true, false]);
  // The tolerant check comes before ANY command; the strict one after the fixed parents exist and before any quota or
  // label below them.
  assert.equal(s.checks[0].after, 0, "first, before getent/groupadd");
  assert.equal(s.checks[0].dirs, false);
  assert.equal(s.checks[1].dirs, true);
  const firstBelow = s.calls.findIndex((c) => ["setquota", "chattr", "lsattr"].includes(c[0]));
  assert.ok(s.checks[1].after <= firstBelow, `strict check at ${s.checks[1].after}, first effect below at ${firstBelow}`);
  // A refusal at the first check (an ACL on an existing parent, a retained writer): nothing at all happens.
  const a = setup({ refuseCheck: (allow) => allow });
  await assert.rejects(a.p.provision(A, UID, grantAgent(), 5000), /fixed parents failed/);
  assert.deepEqual(a.calls, []);
  assert.equal(a.fsx.existsSync(join(a.root, "/srv/sagebrush")), false);
  // A refusal at the strict check (a writer swapped a parent after the first): nothing is made beneath the parents.
  const b = setup({ refuseCheck: (allow) => !allow });
  await assert.rejects(b.p.provision(A, UID, grantAgent(), 5000), /fixed parents failed/);
  assert.equal(b.fsx.existsSync(join(b.root, `/srv/sagebrush/agents/${A}`)), false);
  assert.equal(b.fsx.existsSync(join(b.root, `/srv/sagebrush/agent-config/${A}`)), false);
  assert.deepEqual(cmds(b.calls, "chattr"), []);
  assert.deepEqual(cmds(b.calls, "setquota"), []);
});

test("a redone provision creates nothing and changes nothing", async () => {
  const s = setup({ quota: null });
  await s.p.provision(A, UID, grantAgent(), 5000);
  const before = s.calls.length;
  await s.p.provision(A, UID, grantAgent(), 5000);
  const again = s.calls.slice(before);
  assert.equal(again.filter((c) => c[0] !== "getent").length, 0, JSON.stringify(again));
});

test("a name or number that exists and differs is a host-side failure, never adopted", async () => {
  const cases = {
    "the user name with another uid": { passwd: { [USER]: [USER, "x", "70001", "70000", "", HOME, NOLOGIN] } },
    "the uid with another name": { passwd: { other: ["other", "x", String(UID), "100", "", "/home/other", "/bin/bash"] } },
    "the user with a login shell": { passwd: { [USER]: [USER, "x", String(UID), String(UID), "", HOME, "/bin/bash"] }, group: { [USER]: [USER, "x", String(UID), ""] } },
    "the user with another home": { passwd: { [USER]: [USER, "x", String(UID), String(UID), "", "/home/x", NOLOGIN] }, group: { [USER]: [USER, "x", String(UID), ""] } },
    "the group name with another gid": { group: { [USER]: [USER, "x", "70005", ""] } },
    "the agent's gid held by another group": { group: { other: ["other", "x", String(UID), ""] } },
    "a tag gid held by another group": { group: { other: ["other", "x", String(G1), ""] } },
    // A duplicated group name: getent by name finds one entry, getent by gid another of the same name.
    "a duplicated group name": { group: { first: [USER, "x", "70005", ""], second: [USER, "x", String(UID), ""] } },
  };
  for (const [name, c] of Object.entries(cases)) {
    const s = setup(c);
    await assert.rejects(s.p.provision(A, UID, grantAgent(), 5000), host, name);
    assert.equal(cmds(s.calls, "useradd").length, 0, `${name}: no user made`);
  }
});

test("an agent user with a subordinate id range is refused", async () => {
  for (const f of ["etc/subuid", "etc/subgid"]) for (const key of [USER, String(UID)]) {
    const s = setup();
    fs.appendFileSync(join(s.root, f), `${key}:200000:65536\n`);
    await assert.rejects(s.p.provision(A, UID, grantAgent(), 5000), host, `${f} ${key}`);
  }
});

test("a directory that exists as a symlink, or with another owner or mode, is refused and left as it is", async () => {
  const s = setup();
  fs.mkdirSync(join(s.root, `/srv/sagebrush/agents/${A}`), { recursive: true });
  for (const p of ["/srv/sagebrush", "/srv/sagebrush/agents", "/srv/sagebrush/tags", `/srv/sagebrush/agents/${A}`]) {
    fs.mkdirSync(join(s.root, p), { recursive: true });
    fs.chmodSync(join(s.root, p), 0o755);
    s.owner.set(join(s.root, p), [0, 0]);
  }
  fs.symlinkSync("/etc", join(s.root, HOME));
  await assert.rejects(s.p.provision(A, UID, grantAgent(), 5000), host);
  assert.equal(fs.readlinkSync(join(s.root, HOME)), "/etc");
  const t = setup();
  fs.mkdirSync(join(t.root, `/srv/sagebrush/tags/${T1}`), { recursive: true });
  for (const p of ["/srv/sagebrush", "/srv/sagebrush/agents", "/srv/sagebrush/tags"]) { fs.mkdirSync(join(t.root, p), { recursive: true }); fs.chmodSync(join(t.root, p), 0o755); t.owner.set(join(t.root, p), [0, 0]); }
  fs.chmodSync(join(t.root, `/srv/sagebrush/tags/${T1}`), 0o777);
  t.owner.set(join(t.root, `/srv/sagebrush/tags/${T1}`), [0, G1]);
  await assert.rejects(t.p.provision(A, UID, grantAgent(), 5000), host);
  assert.equal(fs.statSync(join(t.root, `/srv/sagebrush/tags/${T1}`)).mode & 0o777, 0o777);
  // A regular file where the home should be, with the agent's owner and mode: not a directory, refused.
  const f = setup();
  for (const p of ["/srv/sagebrush", "/srv/sagebrush/agents", "/srv/sagebrush/tags", `/srv/sagebrush/agents/${A}`]) {
    fs.mkdirSync(join(f.root, p), { recursive: true }); fs.chmodSync(join(f.root, p), 0o755); f.owner.set(join(f.root, p), [0, 0]);
  }
  fs.writeFileSync(join(f.root, HOME), "");
  fs.chmodSync(join(f.root, HOME), 0o700);
  f.owner.set(join(f.root, HOME), [UID, UID]);
  f.proj.set(join(f.root, HOME), { id: UID, inherit: true }); // even with the right label: not a directory
  await assert.rejects(f.p.provision(A, UID, grantAgent(), 5000), host);
  assert.ok(fs.statSync(join(f.root, HOME)).isFile());
});

test("bad input or a failing command is host-side", async () => {
  await assert.rejects(setup().p.provision(A, 69999, grantAgent(), 5000), host);
  await assert.rejects(setup().p.provision(A, UID, grantAgent({ agent: T1 }), 5000), host);
  const bad = setup();
  const p = provisioner({ run: async () => ({ code: 0, stdout: "", stderr: "" }), tagGid: () => 1000, checkParents: async () => {} });
  await assert.rejects(p.provision(A, UID, grantAgent(), 5000), host, "a tag gid outside the tag range");
  void bad;
  for (const m of ["getent passwd", "groupadd", "useradd", "chattr", "setquota"]) {
    const s = setup({ over: { [m]: () => ({ code: m.startsWith("getent") ? 1 : 9 }) } });
    await assert.rejects(s.p.provision(A, UID, grantAgent(), 5000), host, m);
  }
  assert.throws(() => provisioner({ run: async () => ({}) }), (e) => e instanceof FleetError && e.code === "bad_form");
  assert.throws(() => provisioner({ run: async () => ({}), tagGid: () => 1 }), (e) => e instanceof FleetError && e.code === "bad_form", "no launcher check");
});

test("a pre-existing group with members is refused, never adopted: the private group, and a tag group before its folder exists", async () => {
  const priv = setup({ group: { [USER]: [USER, "x", String(UID), "attacker"] } });
  await assert.rejects(priv.p.provision(A, UID, grantAgent(), 5000), host);
  assert.equal(cmds(priv.calls, "useradd").length, 0);
  const tag = setup({ group: { [`sbt-${T1}`]: [`sbt-${T1}`, "x", String(G1), "attacker"] } });
  await assert.rejects(tag.p.provision(A, UID, grantAgent(), 5000), host);
  assert.equal(fs.existsSync(join(tag.root, `/srv/sagebrush/tags/${T1}`)), false, "refused before the tag folder is made");
  assert.equal(mutating(tag.calls).length, 0, "and before any change at all");
  // The same group with an empty member list is the matching state.
  const ok = setup({ group: { [`sbt-${T1}`]: [`sbt-${T1}`, "x", String(G1), ""] } });
  await ok.p.provision(A, UID, grantAgent(), 5000);
});

test("subordinate ids must come from the local files only: an nsswitch subid source other than files refuses first", async () => {
  const cases = {
    "subid: sss\n": false, "subid: files sss\n": false, "subid:\tldap files\n": false,
    "subid: files\n": true, "subid:   files [NOTFOUND=return]\n": true, "# subid: sss\npasswd: files systemd\n": true, "passwd: files\n": true,
  };
  for (const [text, allowed] of Object.entries(cases)) {
    const s = setup();
    fs.writeFileSync(join(s.root, "etc/nsswitch.conf"), text);
    if (allowed) await s.p.provision(A, UID, grantAgent(), 5000);
    else {
      await assert.rejects(s.p.provision(A, UID, grantAgent(), 5000), host, text);
      assert.equal(s.calls.length, 0, `${JSON.stringify(text)}: refused before any command`);
    }
  }
  await setup().p.provision(A, UID, grantAgent(), 5000); // no nsswitch.conf: glibc's default, the files
});

test("project quotas on an existing directory: matching is a no-op; another id or a missing inherit flag is refused, never rewritten", async () => {
  // A quota-enabled redo makes zero mutating calls.
  const s = setup();
  await s.p.provision(A, UID, grantAgent(), 5000);
  const before = s.calls.length;
  await s.p.provision(A, UID, grantAgent(), 5000);
  assert.deepEqual(mutating(s.calls.slice(before)), [], "a matching redo changes nothing");
  for (const [name, state] of [["another project id", { id: 77777, inherit: true }], ["no inherit flag", { id: UID, inherit: false }]]) {
    const t = setup();
    await t.p.provision(A, UID, grantAgent(), 5000);
    fs.writeFileSync(join(t.root, HOME, "work.txt"), "data"); // populated
    t.proj.set(join(t.root, HOME), state);
    const n = t.calls.length;
    await assert.rejects(t.p.provision(A, UID, grantAgent(), 5000), host, name);
    assert.deepEqual(mutating(t.calls.slice(n)), [], `${name}: nothing rewritten`);
    assert.deepEqual(t.proj.get(join(t.root, HOME)), state);
  }
});

test("a crash at any step retries to the exact final state; a populated incomplete directory is refused", async () => {
  const TAG = `/srv/sagebrush/tags/${T1}`;
  // Stop the first run right after a given command, the way a crash would, then retry with a healthy runner.
  const crashAfter = async (match) => {
    const s = setup({ over: { [match]: (argv) => { if (!s.crashed) { s.crashed = true; s.runRaw(argv, { ms: 1 }); throw Object.assign(new Error("crash"), { code: "crash" }); } } } });
    s.crashed = false;
    await assert.rejects(s.p.provision(A, UID, grantAgent(), 5000));
    s.crashed = true; // the retry runs normally
    await s.p.provision(A, UID, grantAgent(), 5000);
    return s;
  };
  for (const [name, match] of [["after the limits", "setquota -P 70000"], ["after the project label", "chattr +P -p 70000"], ["after the tag's label", `chattr +P -p ${G1}`]]) {
    const s = await crashAfter(match);
    assert.deepEqual(s.stat(HOME), [UID, UID, 0o700], name);
    assert.deepEqual(s.proj.get(join(s.root, HOME)), { id: UID, inherit: true }, name);
    assert.deepEqual(s.stat(TAG), [0, G1, 0o2770], name);
    assert.deepEqual(s.proj.get(join(s.root, TAG)), { id: G1, inherit: true }, name);
  }
  // After mkdir (INIT: root:root 0700, empty, unlabelled), and after the tag's owner was published (OWNED: root:sbt 0700).
  const make = (s, p, uid, gid) => { fs.mkdirSync(join(s.root, p), { recursive: true }); fs.chmodSync(join(s.root, p), 0o700); s.owner.set(join(s.root, p), [uid, gid]); };
  const parents = (s) => { for (const p of ["/srv/sagebrush", "/srv/sagebrush/agents", "/srv/sagebrush/tags", `/srv/sagebrush/agents/${A}`]) { fs.mkdirSync(join(s.root, p), { recursive: true }); fs.chmodSync(join(s.root, p), 0o755); s.owner.set(join(s.root, p), [0, 0]); } };
  const i = setup(); parents(i); make(i, HOME, 0, 0); make(i, TAG, 0, G1); i.proj.set(join(i.root, TAG), { id: G1, inherit: true });
  await i.p.provision(A, UID, grantAgent(), 5000);
  assert.deepEqual([i.stat(HOME), i.stat(TAG)], [[UID, UID, 0o700], [0, G1, 0o2770]]);
  // A populated INIT directory isn't a crash leftover: refused, left as it is.
  const f = setup(); parents(f); make(f, HOME, 0, 0); fs.writeFileSync(join(f.root, HOME, "x"), "data");
  await assert.rejects(f.p.provision(A, UID, grantAgent(), 5000), host);
  assert.deepEqual(f.stat(HOME), [0, 0, 0o700]);
  // A directory in its final owner and mode but unlabelled (what a provision without quotas makes): refused, not relabelled.
  const q = setup();
  await provisionWithoutQuotas(q);
  const n = q.calls.length;
  await assert.rejects(q.p.provision(A, UID, grantAgent(), 5000), host);
  assert.deepEqual(mutating(q.calls.slice(n)), []);
  // lsattr failing is host-side.
  const d = setup({ over: { lsattr: () => ({ code: 1 }) } });
  await assert.rejects(d.p.provision(A, UID, grantAgent(), 5000), host);
});

test("a project label that doesn't take (chattr exits 0, lsattr shows none) is refused, and the directory stays root-only", async () => {
  const s = setup({ over: { chattr: () => ({ code: 0 }) } }); // accepted, but nothing is labelled
  await assert.rejects(s.p.provision(A, UID, grantAgent(), 5000), host);
  assert.deepEqual(s.stat(HOME), [0, 0, 0o700], "never published");
});

test("the tag race: the tag group gets no access to a new tag folder until its project label is set and verified", async () => {
  const TAG = `/srv/sagebrush/tags/${T1}`;
  const trace = [];
  const s = setup({ over: {
    "chattr": (argv) => { if (argv.at(-1).endsWith(TAG)) trace.push("label"); },
    "lsattr": (argv) => { if (argv.at(-1).endsWith(TAG) && trace.includes("label")) trace.push("verify"); },
  } });
  const path = join(s.root, TAG);
  const { chownSync, chmodSync } = s.fsx;
  s.fsx.chownSync = (p, u, g) => { if (p === path) trace.push(`own ${u}:${g}`); return chownSync(p, u, g); };
  s.fsx.chmodSync = (p, m) => { if (p === path) trace.push(`mode ${m.toString(8)}`); return chmodSync(p, m); };
  await s.p.provision(A, UID, grantAgent(), 5000);
  assert.deepEqual(trace, ["own 0:0", "mode 700", "label", "verify", `own 0:${G1}`, "mode 2770"]);
});

/** A provision run on the same root and databases with quotas off: what a crash before the first label leaves. */
async function provisionWithoutQuotas(s) {
  const p = provisioner({ run: async (argv, o) => (argv[0] === "chattr" || argv[0] === "setquota" ? assert.fail("no quota calls") : s.runRaw(argv, o)), fsx: s.fsx, root: s.root, rootUid: 0, tagGid: (t) => ({ [T1]: G1, [T2]: G2 })[t], quota: null, checkParents: async () => {} });
  await p.provision(A, UID, grantAgent(), 5000);
}
