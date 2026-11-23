"""The signed envelope (lib/fleet/core/envelope.mjs; r2.3 §1.3).

  { v: 1, type, signer: { kind, id, alg: "ed25519", key }, body, sig }
  signed bytes = "sagebrush.sig.v1\\n" + type + "\\n" + canon(signer) + "\\n" + canon(body)
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from .core import SIGNED_MAX, canon_text, is_id, parse_canonical, refuse, unb64, verify_strict
from .schema import Schemas

AUDIENCES = ("https://sagebrush.space", "https://dev.sagebrush.space")

TYPES = {
    "sb.device-chain.v1": ("device", "recovery"),
    "sb.host-cert.v1": ("device",),
    "sb.host-grant.v1": ("device",),
    "sb.grant-ack.v1": ("host",),
    "sb.host-op.v1": ("device",),
    "sb.revocation.v1": ("device",),
    "sb.approval.v1": ("device",),
    "sb.sealed-package.v1": ("device",),
    "sb.browser-session.v1": ("device",),
    "sb.audit-event.v1": ("host",),
    "sb.audit-checkpoint.v1": ("host",),
    "sb.audit-continuity.v1": ("host",),
    "sb.audit-ack.v1": ("service",),
}
KINDS = {"device", "host", "recovery", "service"}


@lru_cache(maxsize=1)
def schemas() -> Schemas:
    """The repository's frozen schema set (schema/fleet beside python/)."""
    return Schemas(Path(__file__).resolve().parents[2] / "schema" / "fleet")


def body_validator(name):
    return schemas().body(name)


def exact_keys(o, keys) -> bool:
    return isinstance(o, dict) and len(o) == len(keys) and all(k in o for k in keys)


def signed_bytes(type_: str, signer, body) -> bytes:
    return f"sagebrush.sig.v1\n{type_}\n{canon_text(signer)}\n{canon_text(body)}".encode("utf-8")


def check_signer(type_, signer):
    if type_ not in TYPES:
        refuse("bad_form", "an unknown type")
    if not exact_keys(signer, ["kind", "id", "alg", "key"]):
        refuse("bad_form", "a signer is {kind, id, alg, key}")
    # (a str before any set or dict lookup: a list or object there must be a refusal, never a TypeError)
    if not isinstance(signer["kind"], str) or signer["kind"] not in KINDS or not is_id(signer["id"]) or signer["alg"] != "ed25519":
        refuse("bad_form", "a bad signer")
    unb64(signer["key"], 16)
    if signer["kind"] not in TYPES[type_]:
        refuse("bad_signature", "this type isn't signed by that kind of signer")


class Parsed:
    __slots__ = ("env", "signed", "sig", "add")

    def __init__(self, env, signed, sig, add):
        self.env, self.signed, self.sig, self.add = env, signed, sig, add


def parse_envelope(data: bytes, ctx) -> Parsed:
    env = parse_canonical(data, SIGNED_MAX)
    body = env.get("body") if isinstance(env, dict) else None
    add = isinstance(env, dict) and env.get("type") == "sb.device-chain.v1" and isinstance(body, dict) and body.get("op") == "add"
    keys = ["v", "type", "signer", "body", "sig", "sig2"] if add else ["v", "type", "signer", "body", "sig"]
    if not exact_keys(env, keys) or not (env["v"] == 1 and type(env["v"]) is int):
        refuse("bad_form", "not an envelope")
    if not isinstance(env["type"], str) or env["type"] not in TYPES:
        refuse("bad_form", "an unknown type")
    check_signer(env["type"], env["signer"])
    body = env["body"]
    if not isinstance(body, dict):
        refuse("bad_form", "a body is an object")
    if body.get("aud") != ctx["aud"] or body.get("aud") not in AUDIENCES:
        refuse("bad_audience")
    if body.get("fleet") != ctx["fleet"] or not is_id(body.get("fleet")):
        refuse("bad_form", "another fleet")
    sig = unb64(env["sig"], 64)
    return Parsed(env, signed_bytes(env["type"], env["signer"], body), sig, add)


def opened(p: Parsed):
    r = {"type": p.env["type"], "signer": p.env["signer"], "body": p.env["body"], "signed": p.signed}
    if p.add:
        r["sig2"] = unb64(p.env["sig2"], 64)
    return r


def open_envelope(data: bytes, ctx):
    """ctx: { aud, fleet, resolve_key(signer, type, body) -> 32-byte raw key (raises FleetError to refuse) }."""
    p = parse_envelope(data, ctx)
    raw = ctx["resolve_key"](p.env["signer"], p.env["type"], p.env["body"])
    if not verify_strict(raw, p.signed, p.sig):
        refuse("bad_signature")
    return opened(p)
