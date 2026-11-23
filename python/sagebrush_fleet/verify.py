"""The reference verifiers for objects outside the device chain (lib/fleet/core/verify.mjs; r2.3 §3, §4).

Each takes the envelope's bytes and the verifier's own state and returns the verified body, or raises a FleetError
whose code is in schema/fleet/reasons.json. Recording a use (an op_id, an approval) is the caller's.
"""

from __future__ import annotations

import math
import re

from .chain import device_key, require_tier
from .core import b64, canon_text, check_public_key, concat, enc, refuse, sha256, sha256b64, unb64
from .envelope import body_validator, open_envelope

B32 = "abcdefghijklmnopqrstuvwxyz234567"
TEN_MIN = 10 * 60_000
AUTH_MS = 5 * 60_000


def host_fingerprint(host: str, sign_raw: bytes, enc_raw: bytes) -> bytes:
    return sha256(concat("sagebrush.fp.v1\nhost\n", host, "\n", sign_raw, enc_raw))


def device_fingerprint(fleet: str, device: str, raw: bytes) -> bytes:
    return sha256(concat("sagebrush.fp.v1\ndevice\n", fleet, "\n", device, "\n", raw))


def show_fingerprint(full: bytes) -> str:
    """The first 100 bits, 20 base32 characters in groups of 4."""
    acc = int.from_bytes(full[:13], "big") >> (13 * 8 - 100)
    s = "".join(B32[(acc >> (5 * i)) & 31] for i in range(19, -1, -1))
    return "-".join(s[i:i + 4] for i in range(0, 20, 4))


# ---- shared steps

def open_by_device(data: bytes, ctx, type_: str, schema: str, allow_removed: bool = False):
    """Open a device-signed object: the signer counts at the body's chain_seq and at the pinned head (§2.3)."""
    found = {}

    def resolve_key(signer, t, body):
        if t != type_:
            refuse("bad_form", "another type")
        body_validator(schema)(body)
        try:
            found["device"] = device_key(ctx["chain"], signer, body.get("chain_seq"))
        except Exception as e:  # noqa: BLE001 (re-raised unless it is the one allowed refusal)
            # (a revocation from a since-removed device still holds: obeying one only narrows, §2.3)
            if not (allow_removed and getattr(e, "code", None) == "device_removed"):
                raise
            found["device"] = ctx["chain"].devices[signer["id"]]
        return found["device"].raw

    env = open_envelope(data, {"aud": ctx["aud"], "fleet": ctx["fleet"], "resolve_key": resolve_key})
    env["device"] = found["device"]
    return env


def in_force(body, now):
    if "not_before_ms" in body and now < body["not_before_ms"]:
        refuse("grant_expired", "not yet in force")
    if body.get("not_after_ms") is not None and now >= body["not_after_ms"]:
        refuse("grant_expired")


def fresh_auth(ctx, body):
    if ctx.get("check_auth_time") and not (ctx["now"] - body["auth_time_ms"] <= AUTH_MS and body["auth_time_ms"] <= ctx["now"] + AUTH_MS):
        refuse("stale_auth")


# ---- host certificates (§3.1)

def verify_host_cert(data: bytes, ctx):
    env = open_by_device(data, ctx, "sb.host-cert.v1", "host-cert")
    b = env["body"]
    sign_raw = check_public_key(unb64(b["sign_key"], 32))
    enc_raw = unb64(b["enc_key"], 32)
    if not any(enc_raw):
        refuse("bad_form", "an X25519 key of zero")
    if b64(host_fingerprint(b["host"], sign_raw, enc_raw)) != b["fingerprint"]:
        refuse("bad_form", "the fingerprint isn't this host's")
    return {"body": b, "sign_raw": sign_raw, "enc_raw": enc_raw, "hash": sha256b64(env["signed"]), "device": env["device"]}


# ---- host grants (§3.2)

AGENTS = "/.agents"
MAX_PATH, MAX_DEPTH, MAX_NAME = 1024, 32, 255
CONTROL = re.compile("[\u0000-\u001f\u007f]")


def _u16len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def under_agents(p: str) -> bool:
    return p == AGENTS or p.startswith(AGENTS + "/")


def canonical_path(p) -> bool:
    """The endpoint's path rules: absolute, "/"-separated, no empty, "." or ".." names, no control characters, at most
    1024 characters (UTF-16 units, as JavaScript counts), 32 folders deep and 255 per name."""
    if not isinstance(p, str) or not p.startswith("/") or _u16len(p) > MAX_PATH:
        return False
    if p == "/":
        return True
    names = p[1:].split("/")
    if len(names) > MAX_DEPTH:
        return False
    return all(n not in ("", ".", "..") and _u16len(n) <= MAX_NAME and CONTROL.search(n) is None for n in names)


def narrows_only(prev, nxt) -> bool:
    """Whether `nxt` only narrows `prev` (both grant bodies): anything else widens (§2.1's native rule)."""
    if not prev:
        return False

    def sub(a, b):
        return all(x in b for x in a)

    pa = {a["agent"]: a for a in prev["agents"]}
    for a in nxt["agents"]:
        p = pa.get(a["agent"])
        if p is None or a["client"] != p["client"] or (a.get("root") and not p.get("root")) or not sub(a["tags"], p["tags"]) or not sub(a["broker"], p["broker"]):
            return False
        if a["spend_cap_cents"] > p["spend_cap_cents"] or canon_text(a.get("config")) != canon_text(p.get("config")):
            return False
        for s in a["workspace"]:
            if not any(q["path"] == s["path"] and (q["access"] == "write" or s["access"] == "read") for q in p["workspace"]):
                return False
    if not sub([t["tag"] for t in nxt["tags"]], [t["tag"] for t in prev["tags"]]):
        return False
    ps = {s["sub"]: s for s in prev["subscriptions"]}
    for s in nxt["subscriptions"]:
        p = ps.get(s["sub"])
        if p is None or s["provider"] != p["provider"] or (s.get("home") and not p.get("home")) or not sub(s["use"], p["use"]):
            return False

    def end(g):
        return math.inf if g["not_after_ms"] is None else g["not_after_ms"]

    if end(nxt) > end(prev) or nxt["not_before_ms"] < prev["not_before_ms"]:
        return False
    if nxt["offline"]["horizon_s"] > prev["offline"]["horizon_s"] or nxt["offline"]["revocation_check_s"] > prev["offline"]["revocation_check_s"]:
        return False
    return True


def verify_grant(data: bytes, ctx):
    """ctx: { aud, fleet, chain, cert, current: { gen, bytes, body } | None, now, check_auth_time? }."""
    env = open_by_device(data, ctx, "sb.host-grant.v1", "host-grant")
    g = env["body"]
    fresh_auth(ctx, g)
    if g["host"] != ctx["cert"]["body"]["host"] or g["cert"] != ctx["cert"]["hash"]:
        refuse("not_granted", "another host or certificate")
    cur = ctx.get("current")
    reapply = False
    if cur:
        if g["gen"] < cur["gen"]:
            refuse("stale_generation")
        if g["gen"] == cur["gen"]:
            if bytes(data) != bytes(cur["bytes"]):
                refuse("stale_generation", "the same generation, other bytes")
            reapply = True
    if (g["not_after_ms"] is None) != (g.get("no_expiry_ack") is True):
        refuse("bad_form", "no_expiry_ack exactly when not_after_ms is null")
    if g["not_after_ms"] is not None and g["not_after_ms"] <= g["not_before_ms"]:
        refuse("bad_form", "an empty lifetime")
    in_force(g, ctx["now"])
    tags = set()
    for t in g["tags"]:
        if t["tag"] in tags:
            refuse("bad_form", "a tag twice")
        tags.add(t["tag"])
    agents = set()
    for a in g["agents"]:
        if a["agent"] in agents:
            refuse("bad_form", "an agent twice")
        agents.add(a["agent"])
        for t in a["tags"]:
            if t not in tags:
                refuse("bad_form", "an agent's tag isn't in the grant")
        paths = set()
        for s in a["workspace"]:
            if not canonical_path(s["path"]):
                refuse("bad_form", "a workspace path that isn't canonical")
            if under_agents(s["path"]):
                refuse("not_granted", "/.agents is never a workspace scope")
            if s["path"] in paths:
                refuse("bad_form", "a path twice")
            paths.add(s["path"])
    subs = set()
    for s in g["subscriptions"]:
        if s["sub"] in subs:
            refuse("bad_form", "a subscription twice")
        subs.add(s["sub"])
        for a in s["use"]:
            if a not in agents:
                refuse("bad_form", "a subscription used by an agent not in the grant")
        if s.get("home") and s["provider"] != "codex":
            refuse("bad_form", "only a codex subscription has a home")
    widens = not narrows_only(cur["body"] if cur else None, g)
    if not reapply:
        require_tier(ctx["chain"], env["device"], widens)
    return {"body": g, "reapply": reapply, "widens": widens, "hash": sha256b64(env["signed"])}


# ---- the host's acknowledgement (§3.3)

def verify_grant_ack(data: bytes, ctx):
    def resolve_key(signer, t, body):
        if t != "sb.grant-ack.v1":
            refuse("bad_form", "another type")
        body_validator("grant-ack")(body)
        if signer["kind"] != "host" or signer["id"] != ctx["cert"]["body"]["host"] or body["host"] != signer["id"]:
            refuse("bad_signature")
        return ctx["cert"]["sign_raw"]

    env = open_envelope(data, {"aud": ctx["aud"], "fleet": ctx["fleet"], "resolve_key": resolve_key})
    if env["body"]["gen"] > ctx["current_gen"]:
        refuse("stale_generation", "an ack ahead of the grant")
    return env["body"]


# ---- person-signed host operations (§3.4)

WIDENING_OPS = {"resume", "delete"}


def verify_host_op(data: bytes, ctx):
    """ctx: { aud, fleet, chain, host, current_gen, now, seen_op(op_id) -> bool, check_auth_time? }."""
    env = open_by_device(data, ctx, "sb.host-op.v1", "host-op")
    o = env["body"]
    if o["host"] != ctx["host"]:
        refuse("not_granted", "another host")
    if o["gen"] != ctx["current_gen"]:
        refuse("stale_generation")
    if o["not_after_ms"] - o["at_ms"] > TEN_MIN or o["not_after_ms"] <= o["at_ms"]:
        refuse("bad_form", "an op lives at most 10 minutes")
    if ctx["now"] < o["at_ms"] - 5 * 60_000 or ctx["now"] >= o["not_after_ms"]:
        refuse("grant_expired")
    if o["op"] in WIDENING_OPS and ctx.get("check_auth_time"):
        fresh_auth(ctx, {"auth_time_ms": ctx["session_auth_time_ms"]})
    if ctx["seen_op"](o["op_id"]):
        refuse("replay", "this op_id has run")
    require_tier(ctx["chain"], env["device"], o["op"] in WIDENING_OPS)
    return o


# ---- revocations (§3.5): obeyed even when their signer has since been removed

def verify_revocation(data: bytes, ctx):
    return open_by_device(data, ctx, "sb.revocation.v1", "revocation", allow_removed=True)["body"]


# ---- typed approvals (§4)

def verify_approval(data: bytes, ctx):
    """ctx: { aud, fleet, chain, now, expect: { kind, subject, requester }, current: { gen, life } | None, used(a) }."""
    env = open_by_device(data, ctx, "sb.approval.v1", "approval")
    a = env["body"]
    if a["kind"] == "host-pair":
        fresh_auth(ctx, a)
    if a["subject_hash"] != sha256b64(enc(canon_text(a["subject"]))):
        refuse("approval_mismatch", "the subject's hash")
    want = ctx["expect"]
    if a["kind"] != want["kind"] or canon_text(a["requester"]) != canon_text(want["requester"]) or a["subject_hash"] != sha256b64(enc(canon_text(want["subject"]))):
        refuse("approval_mismatch")
    if a["not_after_ms"] - a["at_ms"] > TEN_MIN or a["not_after_ms"] <= a["at_ms"]:
        refuse("bad_form", "an approval lives at most 10 minutes")
    if ctx["now"] < a["at_ms"] - 5 * 60_000 or ctx["now"] >= a["not_after_ms"]:
        refuse("approval_stale", "expired")
    cur = ctx.get("current")
    if "host" in a["requester"] and (not cur or a.get("gen") != cur.get("gen") or a.get("life") != cur.get("life")):
        refuse("approval_stale")
    if ctx["used"](a["approval"]):
        refuse("approval_used")
    require_tier(ctx["chain"], env["device"], True)  # (every approval counts as widening under the native policy)
    return a


def preimage_hash(preimage) -> str:
    """The hash a question's preimage must produce for its subject (§4)."""
    return sha256b64(enc(canon_text(preimage, 640 * 1024)))
