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
function setup({ quota = { mount: "/srv" }, passwd = {}, group = {}, over = {} } = {}) {
  const root = join(os.tmpdir(), `sb-prov-${process.pid}-${seq++}`);
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(join(root, "etc"), { recursive: true });
  fs.mkdirSync(join(root, "srv"), { recursive: true }); // as on any Ubuntu host
  fs.writeFileSync(join(root, "etc/subuid"), "someone:100000:65536\n");
  fs.writeFileSync(join(root, "etc/subgid"), "someone:100000:65536\n");
  const db = { passwd: { ...passwd }, group: { ...group } }; // name -> fields
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
  const p = provisioner({ run, fsx, root, rootUid: 0, tagGid: (t) => ({ [T1]: G1, [T2]: G2 })[t], quota });
  const stat = (path) => { const st = fsx.lstatSync(join(root, path)); return [st.uid, st.gid, st.mode & 0o7777]; };
  return { root, db, calls, owner, p, stat, fsx };
}
const cmds = (calls, name) => calls.filter((c) => c[0] === name);

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
  assert.deepEqual(s.stat(`/srv/sagebrush/tags/${T1}`), [0, G1, 0o2770]);
  assert.deepEqual(s.stat(`/srv/sagebrush/tags/${T2}`), [0, G2, 0o2770]);
});

test("project quotas: the agent's id on home and var-tmp, each tag's on its folder, inherited, with hard limits", async () => {
  const s = setup();
  await s.p.provision(A, UID, grantAgent({ config: { resources: { disk_gb: 7 } } }), 5000);
  const r = s.root;
  assert.deepEqual(cmds(s.calls, "chattr"), [
    ["chattr", "+P", "-p", String(UID), `${r}${HOME}`], ["chattr", "+P", "-p", String(UID), `${r}/srv/sagebrush/agents/${A}/var-tmp`],
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
  await assert.rejects(f.p.provision(A, UID, grantAgent(), 5000), host);
  assert.ok(fs.statSync(join(f.root, HOME)).isFile());
});

test("bad input or a failing command is host-side", async () => {
  await assert.rejects(setup().p.provision(A, 69999, grantAgent(), 5000), host);
  await assert.rejects(setup().p.provision(A, UID, grantAgent({ agent: T1 }), 5000), host);
  const bad = setup();
  const p = provisioner({ run: async () => ({ code: 0, stdout: "", stderr: "" }), tagGid: () => 1000 });
  await assert.rejects(p.provision(A, UID, grantAgent(), 5000), host, "a tag gid outside the tag range");
  void bad;
  for (const m of ["getent passwd", "groupadd", "useradd", "chattr", "setquota"]) {
    const s = setup({ over: { [m]: () => ({ code: m.startsWith("getent") ? 1 : 9 }) } });
    await assert.rejects(s.p.provision(A, UID, grantAgent(), 5000), host, m);
  }
  assert.throws(() => provisioner({ run: async () => ({}) }), (e) => e instanceof FleetError && e.code === "bad_form");
});
