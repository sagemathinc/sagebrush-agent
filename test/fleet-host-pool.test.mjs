// Host-local harness pool policy (advisor delta r3.2 §3, §0.1): the person's policy of which agents draw from which
// subscriptions, per harness. A whole new generation replaces it; anything invalid refuses the whole document and the
// generation in force stays; members must be current agents; at most POOL_CAP entries name one agent; pools compare
// as sets; it is durable, root 0600, and never needed by a grant.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "./host-linux-only.mjs";
import { FleetError, newId } from "../lib/fleet/index.mjs";
import { HostStore } from "../lib/fleet/host/host-store.mjs";
import { MAX_CAPACITY, MAX_LABEL, MAX_SUBSCRIPTIONS, POOL_CAP, checkBindings, checkPool } from "../lib/fleet/host/pool.mjs";

const refused = (fn, code = "bad_form") => assert.throws(fn, (e) => e instanceof FleetError && e.code === code, code);
const fresh = () => join(mkdtempSync(join(tmpdir(), "sb-pool-")), "state");
const disk = (root) => JSON.parse(readFileSync(join(root, "pool", "pool.json"), "utf8"));
const open = async (root) => { const h = await HostStore.open(root); const p = h.pool; p.close = () => h.close(); return p; };
const A = newId(), B = newId(), C = newId();
const agents = new Set([A, B, C]);
const isAgent = (id) => agents.has(id);
const entry = (use, o = {}) => ({ sub: newId(), label: "work", harness: "claude", provider: null, use, ...o });
const doc = (gen, subscriptions, o = {}) => ({ v: 1, gen, subscriptions, thresholds: { five_hour: 0.8, seven_day: 0.9 }, capacity: {}, ...o });

test("a new generation replaces the whole policy, durably; pools are per harness and sorted sets", async () => {
  const root = fresh();
  const p = await open(root);
  assert.equal(p.get().gen, 0);
  assert.deepEqual(p.poolOf(A, "claude"), [], "no policy yet: every pool is empty");
  const P = entry([A, B]), Q = entry([A]), X = entry([A], { harness: "codex" }), O = entry([A], { harness: "opencode", provider: "openai" });
  p.set(doc(1, [P, Q, X, O]), isAgent);
  assert.equal(disk(root).gen, 1);
  assert.equal(statSync(join(root, "pool", "pool.json")).mode & 0o777, 0o600);
  assert.deepEqual(p.poolOf(A, "claude"), [P.sub, Q.sub].sort());
  assert.deepEqual(p.poolOf(B, "claude"), [P.sub]);
  assert.deepEqual(p.poolOf(A, "codex"), [X.sub]);
  assert.deepEqual(p.poolOf(A, "opencode", "openai"), [O.sub]);
  assert.deepEqual(p.poolOf(A, "opencode", "anthropic"), []);
  assert.deepEqual(p.poolOf(C, "claude"), []);
  // Reordering is no change to any pool (canonical sets).
  p.set(doc(2, [O, X, { ...Q }, { ...P, use: [B, A] }]), isAgent);
  assert.deepEqual(p.poolOf(A, "claude"), [P.sub, Q.sub].sort());
  // The next generation drops Q: A's pool shrinks; names() still sees A while any entry names it.
  p.set(doc(3, [P]), isAgent);
  assert.deepEqual(p.poolOf(A, "claude"), [P.sub]);
  assert.equal(p.names(A), true);
  p.set(doc(4, [{ ...P, use: [B] }]), isAgent);
  assert.equal(p.names(A), false, "in no pool: deprovision's accounts step may proceed");
  await p.close();
  const again = await open(root);
  assert.equal(again.get().gen, 4);
  await again.close();
});

test("the generation must increase; a refusal changes nothing on disk", async () => {
  const root = fresh();
  const p = await open(root);
  p.set(doc(5, [entry([A])]), isAgent);
  const before = readFileSync(join(root, "pool", "pool.json"), "utf8");
  for (const g of [5, 4, 0]) refused(() => p.set(doc(g, []), isAgent));
  refused(() => p.set(doc(6, [entry([newId()])]), isAgent)); // a member that isn't an agent here
  refused(() => p.set(doc(6, [entry([A])])), "bad_form"); // no agent check given
  assert.equal(readFileSync(join(root, "pool", "pool.json"), "utf8"), before);
  assert.equal(p.get().gen, 5);
  await p.close();
});

test("a subscription's harness and provider are bound forever: changed or re-listed differently, refused", async () => {
  const root = fresh();
  const p = await open(root);
  const O = entry([A], { harness: "opencode", provider: "openai" });
  p.set(doc(1, [O]), isAgent);
  assert.deepEqual(p.bindingOf(O.sub), { harness: "opencode", provider: "openai" });
  const before = readFileSync(join(root, "pool", "pool.json"), "utf8");
  // The same sub as another provider (openai → anthropic), or as another harness: refused, nothing written.
  refused(() => p.set(doc(2, [{ ...O, provider: "anthropic" }]), isAgent));
  refused(() => p.set(doc(2, [{ ...O, harness: "pi" }]), isAgent));
  refused(() => p.set(doc(2, [{ ...O, harness: "claude", provider: null }]), isAgent));
  assert.equal(readFileSync(join(root, "pool", "pool.json"), "utf8"), before);
  // Dropped, then listed again as another provider: still refused (the binding outlives the listing).
  p.set(doc(2, []), isAgent);
  refused(() => p.set(doc(3, [{ ...O, provider: "anthropic" }]), isAgent));
  p.set(doc(3, [O]), isAgent); // its own binding again is fine
  assert.deepEqual(p.poolOf(A, "opencode", "openai"), [O.sub]);
  await p.close();
  const again = await open(root);
  assert.deepEqual(again.bindingOf(O.sub), { harness: "opencode", provider: "openai" }, "bindings are durable");
  assert.equal(again.bindingOf(newId()), null);
  await again.close();
});

test("eligible: only bound profiles of exactly the entry's harness and provider, in the agent's pool", async () => {
  const p = await open(fresh());
  const O = entry([A], { harness: "opencode", provider: "openai" }), P = entry([A, B]), Q = entry([B]);
  p.set(doc(1, [O, P, Q]), isAgent);
  const prof = (sub, o = {}) => ({ pid: newId(), harness: "claude", provider: null, auth: "subscription", sub, storage_uid: 90000, project_id: 100000, gen: 1, state: "bound", ...o });
  const good = prof(P.sub), openai = prof(O.sub, { harness: "opencode", provider: "openai", auth: "api_key" });
  const profiles = [
    good, openai,
    prof(Q.sub), // another agent's subscription
    prof(P.sub, { state: "creating" }), prof(P.sub, { state: "retiring" }), prof(P.sub, { state: "retired" }),
    // A profile whose own recorded kind differs from its sub's entry is never selectable (e.g. an old credential).
    prof(O.sub, { harness: "opencode", provider: "anthropic", auth: "api_key" }),
    prof(O.sub, { harness: "pi", provider: "openai", auth: "api_key" }),
    prof(P.sub, { harness: "codex", auth: "api_key" }),
  ];
  assert.deepEqual(p.eligible(A, "claude", null, profiles), [good]);
  assert.deepEqual(p.eligible(A, "opencode", "openai", profiles), [openai]);
  assert.deepEqual(p.eligible(A, "opencode", "anthropic", profiles), []);
  assert.deepEqual(p.eligible(C, "claude", null, profiles), []);
  assert.deepEqual(p.eligible(B, "claude", null, profiles).map((r) => r.sub).sort(), [P.sub, Q.sub].sort());
  await p.close();
});

test("bindings: anything but the exact closed shape is refused", () => {
  const S = newId();
  const ok = () => ({ v: 1, subs: { [S]: { harness: "pi", provider: "openai" }, [newId()]: { harness: "claude", provider: null } } });
  assert.equal(checkBindings(ok()), true);
  const cases = {
    "another version": (b) => { b.v = 2; },
    "an extra key": (b) => { b.x = 1; },
    "a bad sub": (b) => { b.subs.nope = { harness: "claude", provider: null }; },
    "an extra field": (b) => { b.subs[S].auth = "api_key"; },
    "an unknown harness": (b) => { b.subs[S].harness = "gemini"; },
    "no provider on pi": (b) => { b.subs[S].provider = null; },
    "an unlisted provider": (b) => { b.subs[S].provider = "claude"; },
    "a provider on claude": (b) => { b.subs[S] = { harness: "claude", provider: "anthropic" }; },
  };
  for (const [name, f] of Object.entries(cases)) { const b = ok(); f(b); assert.throws(() => checkBindings(b), (e) => e instanceof FleetError && e.code === "bad_form", name); }
});

test("the pool cap: an agent in POOL_CAP entries is accepted, in POOL_CAP + 1 refused; MAX_SUBSCRIPTIONS entries", () => {
  const many = (n, use) => Array.from({ length: n }, () => entry(use));
  assert.equal(checkPool(doc(1, many(POOL_CAP, [A]))), true);
  refused(() => checkPool(doc(1, many(POOL_CAP + 1, [A]))));
  // Other agents don't count against A's cap.
  assert.equal(checkPool(doc(1, [...many(POOL_CAP, [A]), ...many(MAX_SUBSCRIPTIONS - POOL_CAP, [B])])), true);
  refused(() => checkPool(doc(1, many(MAX_SUBSCRIPTIONS + 1, []))));
});

test("anything but the exact closed shape is refused", () => {
  const S = newId();
  const ok = () => doc(1, [entry([A, B], { sub: S }), entry([A], { harness: "pi", provider: "openai" })], { capacity: { [S]: { five_hour: 1000, seven_day: MAX_CAPACITY } } });
  assert.equal(checkPool(ok()), true);
  const cases = {
    "another version": (s) => { s.v = 2; },
    "an extra key": (s) => { s.extra = 1; },
    "a negative gen": (s) => { s.gen = -1; },
    "a fractional gen": (s) => { s.gen = 1.5; },
    "an entry with an extra key": (s) => { s.subscriptions[0].home = false; },
    "a bad sub": (s) => { s.subscriptions[0].sub = "nope"; },
    "a duplicate sub": (s) => { s.subscriptions[1].sub = S; },
    "an unknown harness": (s) => { s.subscriptions[0].harness = "gemini"; },
    "a provider on claude": (s) => { s.subscriptions[0].provider = "anthropic"; },
    "no provider on a multi-provider harness": (s) => { s.subscriptions[1].provider = null; },
    "a bad provider": (s) => { s.subscriptions[1].provider = "Open AI"; },
    "an unlisted provider": (s) => { s.subscriptions[1].provider = "mistral"; },
    "an Anthropic alias": (s) => { s.subscriptions[1].provider = "claude"; },
    "an empty label": (s) => { s.subscriptions[0].label = ""; },
    "a long label": (s) => { s.subscriptions[0].label = "x".repeat(MAX_LABEL + 1); },
    "a control character in a label": (s) => { s.subscriptions[0].label = "a\nb"; },
    "a duplicate member": (s) => { s.subscriptions[0].use = [A, A]; },
    "a bad member": (s) => { s.subscriptions[0].use = ["nope"]; },
    "use not a list": (s) => { s.subscriptions[0].use = A; },
    "a threshold of 0": (s) => { s.thresholds.five_hour = 0; },
    "a threshold above 1": (s) => { s.thresholds.seven_day = 1.01; },
    "a missing threshold": (s) => { delete s.thresholds.seven_day; },
    "an extra threshold": (s) => { s.thresholds.hourly = 0.5; },
    "a capacity hint for an unlisted sub": (s) => { s.capacity[newId()] = { five_hour: 1 }; },
    "a capacity of 0": (s) => { s.capacity[S].five_hour = 0; },
    "a capacity above the maximum": (s) => { s.capacity[S].seven_day = MAX_CAPACITY + 1; },
    "a fractional capacity": (s) => { s.capacity[S].five_hour = 1.5; },
    "an empty capacity hint": (s) => { s.capacity[S] = {}; },
    "an unknown capacity window": (s) => { s.capacity[S] = { hourly: 5 }; },
  };
  for (const [name, f] of Object.entries(cases)) { const s = ok(); f(s); assert.throws(() => checkPool(s), (e) => e instanceof FleetError && e.code === "bad_form", name); }
  // A label is the person's own text: non-ASCII is fine; a hint may give one window only (the other stays unknown).
  const s = ok(); s.subscriptions[0].label = "Arbeit – Max"; s.capacity[S] = { seven_day: 5 };
  assert.equal(checkPool(s), true);
});
