// Host supervisor (design: agent-autonomous-host-deprovision.md r3.2 §3.6; amendment L1): the AUTHORITATIVE identity
// of each agent's provisioned trees, recorded by provisioning and compared by deprovision. One closed-shape record per
// agent in the host store:
//
//   { home:   inspect-home --tree home   (the agent directory and exactly home, var-tmp, sessions),
//     config: inspect-home --tree config, its DIRECTORY only (its entries change with every config generation) }
//
// - The values come from the trusted launcher (opened handles); they are checked here against the registry: the
//   owners are the agent's uid, and the project ids are the uid with the inherit flag on a host with quotas, or none
//   at all on a host without.
// - Recorded once. A later provisioning pass in the SAME epoch (boot and mount) must find exactly the recorded
//   identity, or it refuses (a substitute). In ANOTHER epoch (a reboot or a remount), the durable identity (fsid, ino,
//   generation, owners, modes, project ids) must match, and only then are the live fields (dev, mnt_id) rebound to the
//   new epoch: provisioning's automatic requalification. Anything else is refused, never re-recorded.

import { isId, refuse } from "../bytes.mjs";
import { DurableState, exactKeys, realIo } from "./store.mjs";
import { UID_RANGE } from "./registry.mjs";
import { checkInspected, checkObject, sameDurable } from "./deprovision-record.mjs";

const FILE = "provisioned.json";
const empty = () => ({ v: 1, agents: {} });
const isMap = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const FSID = /^[0-9a-f]{16}$/;

/** The config tree's recorded identity: inspect-home's head and its directory. */
function checkConfigDir(x) {
  return exactKeys(x, ["epoch", "fsid", "dir"]) && isMap(x.epoch) && exactKeys(x.epoch, ["boot_id", "mnt_id"]) && UUID.test(x.epoch.boot_id ?? "")
    && Number.isSafeInteger(x.epoch.mnt_id) && x.epoch.mnt_id >= 0 && typeof x.fsid === "string" && FSID.test(x.fsid) && checkObject(x.dir) && x.dir.type === "dir";
}

/** The full closed shape (refuses anything else, with bad_form). */
export function checkProvisioned(r) {
  const bad = () => refuse("bad_form", "provisioned: corrupt");
  if (!exactKeys(r, ["v", "agents"]) || r.v !== 1 || !isMap(r.agents)) bad();
  for (const [id, a] of Object.entries(r.agents)) {
    if (!isId(id) || !exactKeys(a, ["uid", "quota", "home", "config"]) || typeof a.quota !== "boolean") bad();
    if (!Number.isSafeInteger(a.uid) || a.uid < UID_RANGE[0] || a.uid > UID_RANGE[1]) bad();
    if (!checkInspected(a.home) || !checkConfigDir(a.config) || !matchesRegistry(a.home, a.config, a.uid, a.quota)) bad();
  }
  return true;
}

/**
 * Whether the trees are exactly what provisioning makes for `uid`: the agent directory root:root 0755 holding exactly
 * home, var-tmp and sessions, each the agent's, 0700, labelled (project = uid, inherit) with quotas and not labelled
 * without; the config directory root:root 0700, labelled the same way.
 */
export function matchesRegistry(home, config, uid, quota) {
  const [pid, inh] = quota ? [uid, true] : [0, false];
  const d = home.dir;
  if (d.uid !== 0 || d.gid !== 0 || d.mode !== 0o755) return false;
  const names = Object.keys(home.entries).sort();
  if (JSON.stringify(names) !== JSON.stringify(["home", "sessions", "var-tmp"])) return false;
  for (const e of Object.values(home.entries)) {
    if (e.type !== "dir" || e.uid !== uid || e.gid !== uid || e.mode !== 0o700 || e.projid !== pid || e.inherit !== inh) return false;
    if (e.mnt_id !== home.epoch.mnt_id || e.mnt_id !== d.mnt_id) return false;
  }
  const c = config.dir;
  return c.uid === 0 && c.gid === 0 && c.mode === 0o700 && c.projid === pid && c.inherit === inh && c.mnt_id === config.epoch.mnt_id
    && config.fsid === home.fsid && JSON.stringify(config.epoch) === JSON.stringify(home.epoch);
}

const sameEpoch = (a, b) => a.boot_id === b.boot_id && a.mnt_id === b.mnt_id;

export class ProvisionedRecords {
  #s;

  /** A view of the records in `dir`, under the host store's lock (host-store.mjs); it never locks by itself. */
  static attach(dir, lock, { io = realIo } = {}) {
    const p = new ProvisionedRecords();
    p.#s = DurableState.attach(dir, FILE, { check: checkProvisioned, initial: empty, io, lock });
    return p;
  }

  get poisoned() { return this.#s.poisoned; }
  reload() { this.#s.reload(); }

  /** A copy of the agent's record, or null. */
  record(agent) { const a = this.#s.get().agents[agent]; return a ? structuredClone(a) : null; }

  /**
   * Record (or re-verify, or requalify) the agent's provisioned identity from the launcher's `inspect-home` outputs
   * `home` and `configTree` (whose entries are dropped: only its directory is the config tree's identity). Returns
   * "recorded" | "unchanged" | "requalified"; refuses (bad_form) anything that isn't exactly the agent's trees or that
   * differs from the record.
   */
  adopt(agent, uid, quota, home, configTree) {
    if (!isId(agent) || typeof quota !== "boolean") refuse("bad_form", "provisioned: bad agent");
    if (!checkInspected(home) || !checkInspected(configTree)) refuse("bad_form", "provisioned: not the launcher's identity");
    const config = { epoch: configTree.epoch, fsid: configTree.fsid, dir: configTree.dir };
    if (!matchesRegistry(home, config, uid, quota)) refuse("bad_form", "provisioned: the trees aren't exactly the agent's");
    const have = this.#s.get().agents[agent];
    if (!have) {
      this.#s.commit((r) => { r.agents[agent] = { uid, quota, home: structuredClone(home), config }; });
      return "recorded";
    }
    if (have.uid !== uid || have.quota !== quota) refuse("bad_form", "provisioned: recorded for another uid or quota setting");
    if (sameEpoch(have.home.epoch, home.epoch)) {
      const same = JSON.stringify(have.home) === JSON.stringify(home) && JSON.stringify(have.config) === JSON.stringify(config);
      if (!same) refuse("bad_form", "provisioned: another object in the same epoch (a substitute)");
      return "unchanged";
    }
    // Another epoch: only the same durable objects are rebound (deprovision r3.2 §3.6 requalification).
    if (!sameDurable(have.home, home) || !sameDurable({ ...have.config, entries: {} }, { ...config, entries: {} })) {
      refuse("bad_form", "provisioned: another durable identity after a reboot or remount");
    }
    this.#s.commit((r) => { r.agents[agent] = { uid, quota, home: structuredClone(home), config }; });
    return "requalified";
  }
}
