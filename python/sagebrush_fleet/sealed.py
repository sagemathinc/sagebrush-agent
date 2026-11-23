"""What is sealed to a host's X25519 key (lib/fleet/core/sealed.mjs; r2.3 §7, §5.2): the host's side only.

  - sealed packages (sb.sealed-package.v1): info = "sagebrush.seal.v1\\n" + canon(body without enc and ct), aad empty;
  - the capability mint's response { cap, not_after_ms, enc, ct }: info = "sagebrush.cap.v1\\n" +
    canon({ fleet, aud, host, agent, cap, gen }).
"""

from __future__ import annotations

from .core import b64, canon_text, is_id, key_id, parse_canonical, refuse, unb64
from .envelope import body_validator
from .hpke import open_
from .verify import open_by_device

PLAINTEXT_MAX = 16 * 1024
CAP_PLAINTEXT_MAX = 1024
SEVEN_DAYS = 7 * 24 * 3600_000
# (no Claude purpose: a Claude login is never sealed or passed through the service)
PURPOSES = {"codex": ("codex-refresh-home", "codex-access-token")}
SAFE = 2**53 - 1


def enc_key_id(raw: bytes) -> str:
    return key_id("x25519", raw)


def _package_info(header) -> bytes:
    return ("sagebrush.seal.v1\n" + canon_text(header)).encode("utf-8")


def _cap_info(fleet, aud, host, agent, cap, gen) -> bytes:
    return ("sagebrush.cap.v1\n" + canon_text({"fleet": fleet, "aud": aud, "host": host, "agent": agent, "cap": cap, "gen": gen})).encode("utf-8")


def _lifetime(b):
    if b["not_after_ms"] <= b["at_ms"] or b["not_after_ms"] - b["at_ms"] > SEVEN_DAYS:
        refuse("bad_form", "a package lives at most 7 days")


def _purpose_of(provider, purpose):
    if purpose not in PURPOSES.get(provider, ()):
        refuse("bad_form", "a purpose of another provider")


def verify_package(data: bytes, ctx):
    """The host's checks and the opening (§7), in the design's order. ctx: { aud, fleet, chain, cert, host_revoked(cert),
    enc_key (a KeyPair), current_gen, grant, now, revoked(package), opened(package) }. Returns { body, plaintext }."""
    env = open_by_device(data, ctx, "sb.sealed-package.v1", "sealed-package")
    b = env["body"]
    cert = ctx["cert"]
    if b["host"] != cert["body"]["host"] or b["fingerprint"] != cert["body"]["fingerprint"]:
        refuse("not_granted", "a package for another host")
    if b["enc_key"] != enc_key_id(cert["enc_raw"]) or b64(ctx["enc_key"].raw) != b64(cert["enc_raw"]):
        refuse("not_granted", "a package for another key")
    if ctx["host_revoked"](cert) is not False:
        refuse("host_revoked", "this host's certificate is revoked")
    _lifetime(b)
    if b["gen"] != ctx["current_gen"] or ctx["now"] >= b["not_after_ms"]:
        refuse("package_stale", "another generation, or expired")
    if ctx["revoked"](b["package"]):
        refuse("package_stale", "revoked")
    _purpose_of(b["provider"], b["purpose"])
    grant = ctx["grant"]
    s = next((x for x in grant["subscriptions"] if x["sub"] == b["sub"]), None) if grant["host"] == b["host"] else None
    if s is None or s["provider"] != b["provider"]:
        refuse("not_granted", "the subscription isn't in the current grant")
    if b["purpose"] == "codex-refresh-home" and s.get("home") is not True:
        refuse("not_granted", "codex-refresh-home needs home: true")
    if ctx["opened"](b["package"]):
        refuse("package_stale", "already opened")
    header = {k: v for k, v in b.items() if k not in ("enc", "ct")}
    ct = unb64(b["ct"])
    if len(ct) > PLAINTEXT_MAX + 16:
        refuse("limit", "a sealed plaintext over 16 KiB")
    pt = open_(ctx["enc_key"], unb64(b["enc"], 32), _package_info(header), b"", ct)
    plaintext = parse_canonical(pt, PLAINTEXT_MAX)
    body_validator("package_plaintext")(plaintext)
    if plaintext["provider"] != b["provider"] or plaintext["purpose"] != b["purpose"]:
        refuse("bad_form", "the plaintext's provider or purpose isn't the header's")
    return {"body": b, "plaintext": plaintext}


def open_cap(response, ctx):
    """The host's side of a mint response for ctx's agent at its generation. ctx: { fleet, aud, host, agent, gen,
    enc_key, now }. Returns the plaintext { v, token, cap, agent, gen, not_after_ms }."""
    na = response.get("not_after_ms") if isinstance(response, dict) else None
    if not isinstance(response, dict) or not is_id(response.get("cap")) or not (isinstance(na, int) and not isinstance(na, bool) and abs(na) <= SAFE):
        refuse("bad_form", "not a mint response")
    ct = unb64(response.get("ct"))
    if len(ct) > CAP_PLAINTEXT_MAX + 16:
        refuse("limit", "a sealed capability over 1 KiB")
    info = _cap_info(ctx.get("fleet"), ctx.get("aud"), ctx.get("host"), ctx.get("agent"), response["cap"], ctx.get("gen"))
    pt = open_(ctx["enc_key"], unb64(response.get("enc"), 32), info, b"", ct)
    p = parse_canonical(pt, CAP_PLAINTEXT_MAX)
    body_validator("cap_plaintext")(p)
    if p["cap"] != response["cap"] or p["agent"] != ctx["agent"] or p["gen"] != ctx["gen"] or p["not_after_ms"] != response["not_after_ms"]:
        refuse("bad_form", "the sealed capability isn't this response's")
    if ctx["now"] >= p["not_after_ms"]:
        refuse("cap_invalid", "expired")
    return p
