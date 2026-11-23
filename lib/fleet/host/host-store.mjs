// Host supervisor (design: agent-autonomous-host-supervisor-freeze-r3.1.md §2.2, §3.3): the ONE owner of the host's
// root-only state. `HostStore.open(root)` takes the host's single flock on `<root>/.lock` and hands out each durable
// component as a view over that lock; components never lock by themselves. A second supervisor's open refuses with
// `in_progress`. If the lock is lost (its holder died) or the store is closed, every view refuses until a new open.

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { lockDir, realIo } from "./store.mjs";
import { Registry } from "./registry.mjs";
import { GrantState } from "./grant.mjs";
import { Profiles } from "./profiles.mjs";
import { PoolPolicy } from "./pool.mjs";

export class HostStore {
  #lock; #root; #io; #profiles = null; #pool = null;

  /** Open the host's state in `root` (created 0700). Resolves to a HostStore, or refuses `in_progress`. */
  static async open(root, { io = realIo } = {}) {
    mkdirSync(root, { recursive: true, mode: 0o700 });
    const lock = await lockDir(root);
    const h = new HostStore();
    h.#lock = lock;
    h.#root = root;
    h.#io = io;
    try {
      h.registry = Registry.attach(join(root, "registry"), lock, { io });
      h.grants = GrantState.attach(join(root, "grant"), lock, { io });
    } catch (e) { await lock.release(); throw e; }
    return h;
  }

  /**
   * The harness profile records, attached on first use (under this store's lock, refusing once it is lost or closed), so
   * opening the store does exactly the I/O it did before profiles existed.
   */
  get profiles() {
    this.#profiles ??= Profiles.attach(join(this.#root, "profiles"), this.#lock, { io: this.#io });
    return this.#profiles;
  }

  /** The host-local harness pool policy (pool.mjs), attached on first use like the profiles. */
  get pool() {
    this.#pool ??= PoolPolicy.attach(join(this.#root, "pool"), this.#lock, { io: this.#io });
    return this.#pool;
  }

  /** Whether this store still holds the host's lock. */
  get held() { return this.#lock.held(); }

  /** Release the lock; every view refuses afterwards. */
  close() { return this.#lock.release(); }
}
