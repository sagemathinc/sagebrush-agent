"""The fleet protocol's shared rules in Python (design agent-autonomous-schemas.md r2.3 §1): the error type, ids,
canonical base64url, strict UTF-8, SHA-256, canonical JSON (lib/fleet/core/canon.mjs and canonical.mjs, byte for
byte), and strict Ed25519 (lib/fleet/core/ed25519.mjs). The reference verifier mirrors the JavaScript core rule for
rule; both must pass every case of the shared fixtures with the same result.
"""

from __future__ import annotations

import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class FleetError(Exception):
    """A refusal; `code` is a name in schema/fleet/reasons.json. The message never echoes an untrusted value."""

    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or code)
        self.code = code


def refuse(code: str, message: str | None = None):
    raise FleetError(code, message)


# ---- ids (§1.1): 26 lowercase base32 characters, 128 random bits and 2 zero bits

ID = re.compile(r"[a-z2-7]{25}[aeimquy4]")
B32 = "abcdefghijklmnopqrstuvwxyz234567"


def is_id(v) -> bool:
    return isinstance(v, str) and len(v) == 26 and ID.fullmatch(v) is not None


def id_of_bytes(b: bytes) -> str:
    if len(b) != 16:
        refuse("bad_form", "an id is 16 bytes")
    n = int.from_bytes(b, "big") << 2  # (130 bits: the last 2 zero)
    return "".join(B32[(n >> (5 * i)) & 31] for i in range(25, -1, -1))


# ---- base64url, canonical (§1.2): no padding, the unused low bits of the last character zero, exact lengths

B64 = re.compile(r"[A-Za-z0-9_-]*")
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
VALUE = {c: i for i, c in enumerate(ALPHA)}
B64LEN = {16: 22, 32: 43, 64: 86}


def b64(data: bytes) -> str:
    out = []
    n = len(data)
    i = 0
    while i + 3 <= n:
        v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
        out.append(ALPHA[v >> 18] + ALPHA[(v >> 12) & 63] + ALPHA[(v >> 6) & 63] + ALPHA[v & 63])
        i += 3
    if n - i == 1:
        v = data[i]
        out.append(ALPHA[v >> 2] + ALPHA[(v & 3) << 4])
    elif n - i == 2:
        v = (data[i] << 8) | data[i + 1]
        out.append(ALPHA[v >> 10] + ALPHA[(v >> 4) & 63] + ALPHA[(v & 15) << 2])
    return "".join(out)


def unb64(s, length: int | None = None) -> bytes:
    """Decode base64url only if it is the one canonical spelling of `length` bytes (when given)."""
    if not isinstance(s, str) or B64.fullmatch(s) is None or len(s) % 4 == 1:
        refuse("bad_form", "not base64url")
    if length is not None and len(s) != B64LEN.get(length, -1):
        refuse("bad_form", "a binary value of the wrong length")
    acc = bits = 0
    out = bytearray()
    for c in s:
        acc = ((acc << 6) | VALUE[c]) & 0xFFFF
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 255)
    b = bytes(out)
    if b64(b) != s:
        refuse("bad_form", "a non-canonical base64url value")  # (non-zero pad bits)
    return b


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256b64(data: bytes) -> str:
    return b64(sha256(data))


def enc(s: str) -> bytes:
    return s.encode("utf-8")


def utf8(data: bytes) -> str:
    """Received bytes as text, refusing invalid UTF-8 and a byte-order mark."""
    try:
        s = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        refuse("bad_form", "not UTF-8")
    if s.startswith("\ufeff"):
        refuse("bad_form", "a byte-order mark")
    return s


def concat(*parts) -> bytes:
    return b"".join(p.encode("utf-8") if isinstance(p, str) else bytes(p) for p in parts)


# ---- canonical JSON (canon.mjs): safe integers, sorted keys by UTF-16 code units, ES2019 string escapes

SAFE = 2**53 - 1
CANON_DEPTH = 32
SIGNED_MAX = 64 * 1024


class _Refused(Exception):
    pass


def _lone(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _string(s: str) -> str:
    out = ['"']
    for c in s:
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append({8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}.get(o, "\\u%04x" % o))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)  # (a lone surrogate, as JSON.stringify writes it)
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def _utf16_key(k: str) -> bytes:
    return k.encode("utf-16-be", "surrogatepass")


def canon(value, max_bytes: int):
    """(text, None) or (None, reason): canon.mjs's encoder, with its reasons ("too large" or another)."""

    def walk(v, depth):
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, str):
            return _string(v)
        if isinstance(v, int):
            if abs(v) > SAFE:
                raise _Refused("a number that isn't a safe integer")
            return str(v)
        if isinstance(v, float):
            raise _Refused("a number that isn't a safe integer")
        if depth >= CANON_DEPTH:
            raise _Refused("nested too deeply")
        if isinstance(v, list):
            return "[" + ",".join(walk(x, depth + 1) for x in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v.keys(), key=_utf16_key)
            return "{" + ",".join(_string(k) + ":" + walk(v[k], depth + 1) for k in keys) + "}"
        raise _Refused("a value of another kind")

    try:
        text = walk(value, 0)
    except _Refused as e:
        return None, str(e)
    except RecursionError:
        return None, "nested too deeply"
    if len(text.encode("utf-8", "surrogatepass")) > max_bytes:
        return None, "too large"
    return text, None


def _has_lone(v) -> bool:
    if isinstance(v, str):
        return _lone(v)
    if isinstance(v, list):
        return any(_has_lone(x) for x in v)
    if isinstance(v, dict):
        return any(_lone(k) or _has_lone(x) for k, x in v.items())
    return False


def canon_text(value, max_bytes: int = SIGNED_MAX) -> str:
    """The canonical text of a value for signing, or a bad_form / limit refusal (canonical.mjs's canonText)."""
    text, reason = canon(value, max_bytes)
    if text is None:
        refuse("limit" if reason == "too large" else "bad_form", reason)
    if _has_lone(value):
        refuse("bad_form", "a lone surrogate")
    return text


def canon_bytes(value, max_bytes: int = SIGNED_MAX) -> bytes:
    return canon_text(value, max_bytes).encode("utf-8")


def _no_constants(name):
    raise ValueError(name)


def parse_canonical(data: bytes, max_bytes: int = SIGNED_MAX):
    """Received bytes that must be canonical: UTF-8, JSON, and byte-identical to canon of what they parse to."""
    if len(data) > max_bytes:
        refuse("limit", "too large")
    text = utf8(data)
    try:
        v = json.loads(text, parse_constant=_no_constants)
    except (ValueError, RecursionError):
        refuse("bad_form", "not JSON")
    if canon_text(v, max_bytes) != text:
        refuse("bad_form", "not canonical")
    return v


# ---- strict Ed25519 (§1.4): checked here before the library is asked, never left to it

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def _le(b: bytes) -> int:
    return int.from_bytes(b, "little")


SMALL_Y = {
    1,  # order 1
    P - 1,  # order 2
    0,  # order 4
    _le(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")),  # order 8
    _le(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")),  # order 8
}


def _y_of(point: bytes):
    b = bytearray(point)
    sign = b[31] >> 7
    b[31] &= 0x7F
    return _le(bytes(b)), sign


def canonical_point(point: bytes) -> bool:
    if len(point) != 32:
        return False
    y, sign = _y_of(point)
    if y >= P:
        return False
    if sign and (y == 1 or y == P - 1):
        return False
    return True


def small_order(point: bytes) -> bool:
    return (_y_of(point)[0] % P) in SMALL_Y


def check_public_key(raw: bytes) -> bytes:
    if not canonical_point(raw) or small_order(raw):
        refuse("bad_signature", "an unacceptable public key")
    return raw


def key_id_input(alg: str, raw: bytes) -> bytes:
    return concat(f"sagebrush.key.v1\n{alg}\n", raw)


def key_id(alg: str, raw: bytes) -> str:
    return b64(sha256(key_id_input(alg, raw))[:16])


def strict_shape(raw: bytes, sig: bytes) -> bool:
    if raw is None or sig is None or len(raw) != 32 or len(sig) != 64:
        return False
    if not canonical_point(raw) or small_order(raw):
        return False
    if not canonical_point(sig[:32]):
        return False
    return _le(sig[32:]) < L


def verify_strict(raw: bytes, msg: bytes, sig: bytes) -> bool:
    """Strict verification: the rules above, then the library's own check. True or false; never raises on bytes."""
    if not strict_shape(raw, sig):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes(raw)).verify(bytes(sig), bytes(msg))
        return True
    except (InvalidSignature, ValueError):
        return False
