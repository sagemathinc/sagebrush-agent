"""The person's device chain (lib/fleet/core/chain.mjs; r2.3 §2, §1.7), verified entry by entry. State in, state out."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .core import check_public_key, is_id, key_id, refuse, sha256b64, unb64, verify_strict
from .envelope import body_validator, open_envelope

RANK = {"browser": 1, "native": 2}
AUTH_MS = 5 * 60_000
SAFE = 2**53 - 1


def _safe_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and abs(v) <= SAFE


@dataclass(frozen=True)
class Device:
    id: str
    raw: bytes
    key_id: str
    tier: str
    name: object
    added: int
    removed: int | None


@dataclass(frozen=True)
class Recovery:
    raw: bytes
    key_id: str


@dataclass(frozen=True)
class ServiceKey:
    id: str
    raw: bytes
    key_id: str
    seq: int


@dataclass(frozen=True)
class ChainState:
    fleet: str
    aud: str
    seq: int
    head: str
    devices: dict = field(default_factory=dict)
    recovery: Recovery | None = None
    service_keys: tuple = ()
    policy: dict = field(default_factory=lambda: {"require_native_for_widening": False})
    hashes: tuple = ()
    lease_keys: tuple = ()  # (r2.5 §1.7a)


def raw_key(k) -> bytes:
    return check_public_key(unb64(k["key"], 32))


def tier_of(state: ChainState, signer) -> str:
    return "native" if signer["kind"] == "recovery" else state.devices[signer["id"]].tier


def apply(state: ChainState | None, data: bytes, ctx):
    """One entry's bytes against `state` (None before genesis). ctx: { aud, fleet, now?, check_auth_time? }."""
    if state is not None and state.aud != ctx["aud"]:
        refuse("bad_audience", "not this chain's audience")
    if state is not None and state.fleet != ctx["fleet"]:
        refuse("bad_form", "not this chain's fleet")

    def resolve_key(signer, type_, body):
        if type_ != "sb.device-chain.v1":
            refuse("bad_form", "not a chain entry")
        if state is None:
            dev = body.get("device")
            if body.get("op") != "genesis" or signer["kind"] != "device" or not isinstance(dev, dict) or signer["id"] != dev.get("id"):
                refuse("bad_form", "a chain starts with genesis")
            body_validator("device-chain")(body)
            raw = raw_key(dev)
            if key_id("ed25519", raw) != signer["key"]:
                refuse("bad_signature")
            return raw
        if signer["kind"] == "recovery":
            if signer["id"] != state.fleet or signer["key"] != state.recovery.key_id:
                refuse("recovery_key_mismatch")
            return state.recovery.raw
        if signer["kind"] != "device":
            refuse("bad_signature")
        d = state.devices.get(signer["id"])
        if d is None or d.removed is not None or d.key_id != signer["key"]:
            refuse("device_unknown")
        return d.raw

    env = open_envelope(data, {"aud": ctx["aud"], "fleet": ctx["fleet"], "resolve_key": resolve_key})
    body, signer = env["body"], env["signer"]
    body_validator("device-chain")(body)
    if ctx.get("check_auth_time"):
        now = ctx["now"]
        if not (now - body["auth_time_ms"] <= AUTH_MS and body["auth_time_ms"] <= now + AUTH_MS):
            refuse("stale_auth")

    seq = state.seq + 1 if state is not None else 0
    if state is not None and body["op"] == "genesis":
        refuse("bad_form", "one genesis")
    if body.get("seq") != seq or not _safe_int(body.get("seq")) or body.get("prev") != (state.head if state is not None else ""):
        refuse("chain_fork", "not the next entry")

    devices = dict(state.devices) if state is not None else {}
    recovery = state.recovery if state is not None else None
    service_keys = list(state.service_keys) if state is not None else []
    lease_keys = list(state.lease_keys) if state is not None else []
    policy = state.policy if state is not None else {"require_native_for_widening": False}

    def enroll(dev):
        if dev["id"] in devices:
            refuse("bad_form", "a device id twice")  # (never reused, even after removal)
        raw = raw_key(dev)
        devices[dev["id"]] = Device(dev["id"], raw, key_id("ed25519", raw), dev["tier"], dev.get("name"), seq, None)

    def set_recovery(rk):
        nonlocal recovery
        raw = raw_key(rk)
        kid = key_id("ed25519", raw)
        if recovery is not None and recovery.key_id == kid:
            refuse("bad_form", "the same recovery key")
        recovery = Recovery(raw, kid)

    def pinned(k, what):
        # (a service or lease key: an id unique across both lists, and key material never shared between them, §1.7a)
        raw = raw_key(k)
        if not is_id(k.get("id")) or any(x.id == k["id"] for x in service_keys + lease_keys):
            refuse("bad_form", f"a {what} key id twice")
        other = lease_keys if what == "service" else service_keys
        if any(x.raw == raw for x in other):
            refuse("bad_form", f"a {what} key that is also a {'lease' if what == 'service' else 'service'} key")
        return ServiceKey(k["id"], raw, key_id("ed25519", raw), seq)

    def device_signer():
        if signer["kind"] != "device":
            refuse("device_unknown")

    def need_native():
        if tier_of(state, signer) != "native":
            refuse("device_tier")

    regrants = None
    op = body["op"]
    if op == "genesis":
        enroll(body["device"])
        set_recovery(body["recovery_key"])
    elif op == "add":
        device_signer()
        if RANK[tier_of(state, signer)] < RANK[body["device"]["tier"]]:
            refuse("device_tier")
        enroll(body["device"])
        if not verify_strict(devices[body["device"]["id"]].raw, env["signed"], env["sig2"]):
            refuse("bad_signature", "the new device's countersignature")
    elif op == "remove":
        device_signer()
        t = devices.get(body["remove"])
        if t is None or t.removed is not None:
            refuse("device_unknown")
        if body["remove"] == signer["id"]:
            refuse("bad_form", "a device can't remove itself")
        if RANK[tier_of(state, signer)] < RANK[t.tier]:
            refuse("device_tier")
        devices[t.id] = replace(t, removed=seq)
        regrants = body.get("regrants")
    elif op == "recover":
        if signer["kind"] != "recovery":
            refuse("recovery_key_mismatch")
        enroll(body["device"])
        set_recovery(body["recovery_key"])  # (the rotation in the same entry: the old key is spent at once)
    elif op == "rotate-recovery":
        device_signer()
        need_native()
        set_recovery(body["recovery_key"])
    elif op == "service-key":
        device_signer()
        service_keys.append(pinned(body["service_key"], "service"))
    elif op == "lease-key":
        # (r2.5 §1.7a, SEC's Q4: only a native device pins or rotates the lease key)
        device_signer()
        need_native()
        lease_keys.append(pinned(body["lease_key"], "lease"))
    elif op == "policy":
        device_signer()
        if not body["policy"]["require_native_for_widening"]:
            need_native()  # (on: any device; off: native only)
        policy = dict(body["policy"])
    else:
        refuse("bad_form", "an unknown op")

    head = sha256b64(env["signed"])
    hashes = (state.hashes if state is not None else ()) + (head,)
    nxt = ChainState(ctx["fleet"] if state is None else state.fleet, ctx["aud"] if state is None else state.aud, seq, head,
                     devices, recovery, tuple(service_keys), policy, hashes, tuple(lease_keys))
    return nxt, {"op": op, "seq": seq, "signer": signer, "body": body, "regrants": regrants}


def replay(entries, ctx, pin=None) -> ChainState:
    """A whole chain from genesis; a pin ({fleet?, aud?, seq, hash}) must be on it, else chain_fork (§2.4)."""
    if pin and (("fleet" in pin and pin["fleet"] != ctx["fleet"]) or ("aud" in pin and pin["aud"] != ctx["aud"])):
        refuse("chain_fork", "a pin of another chain")
    state = None
    for data in entries:
        state = apply(state, data, ctx)[0]
    if state is None:
        refuse("bad_form", "an empty chain")
    if pin and (pin["seq"] > state.seq or pin["seq"] < 0 or state.hashes[pin["seq"]] != pin["hash"]):
        refuse("chain_fork")
    return state


def device_key(state: ChainState, signer, chain_seq) -> Device:
    """The device behind a signature naming chain_seq: enrolled at chain_seq and still enrolled at the head (§2.3)."""
    if signer["kind"] != "device":
        refuse("bad_signature")
    if not _safe_int(chain_seq) or chain_seq < 0 or chain_seq > state.seq:
        refuse("device_unknown", "fetch the chain first")
    d = state.devices.get(signer["id"])
    if d is None or d.key_id != signer["key"] or d.added > chain_seq:
        refuse("device_unknown")
    if d.removed is not None:
        refuse("device_unknown" if d.removed <= chain_seq else "device_removed")
    return d


def require_tier(state: ChainState, device: Device, widening: bool):
    if widening and state.policy.get("require_native_for_widening") and device.tier != "native":
        refuse("device_tier")


def service_key_at(state: ChainState, signer, chain_seq) -> bytes:
    """The service key in force at chain_seq (§1.7): the latest service-key entry at or before it."""
    return _key_at(state, state.service_keys, "service", signer, chain_seq)


def lease_key_at(state: ChainState, signer, chain_seq) -> bytes:
    """The lease key in force at chain_seq (r2.5 §1.7a): the same rule over the lease-key entries alone."""
    return _key_at(state, state.lease_keys, "lease", signer, chain_seq)


def _key_at(state: ChainState, keys, kind, signer, chain_seq) -> bytes:
    if signer["kind"] != kind:
        refuse("bad_signature")
    if not _safe_int(chain_seq) or chain_seq < 0 or chain_seq > state.seq:
        refuse("device_unknown", "fetch the chain first")
    k = None
    for s in keys:
        if s.seq <= chain_seq:
            k = s
    if k is None or k.id != signer["id"] or k.key_id != signer["key"]:
        refuse("bad_signature")
    return k.raw
