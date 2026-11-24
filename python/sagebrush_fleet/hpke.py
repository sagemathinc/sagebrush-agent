"""HPKE (RFC 9180) base mode, with Export (§5.3), with r2.3 §7's one suite (lib/fleet/core/hpke.mjs): DHKEM(X25519, HKDF-SHA256) 0x0020,
HKDF-SHA256 0x0001, AES-256-GCM 0x0002. The labels, the key schedule and every check are here; X25519, HMAC-SHA256
and AES-256-GCM are the `cryptography` package's. Python can't zero its immutable bytes, so unlike the JavaScript this
module doesn't try to.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .core import refuse

KEM = b"KEM\x00\x20"
SUITE = b"HPKE\x00\x20\x00\x01\x00\x02"
V1 = b"HPKE-v1"
NH, NK, NN, NT = 32, 32, 12, 16
SEQ_MAX = 2**53 - 1


def _hmac(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return _hmac(salt if salt else bytes(NH), ikm)


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = _hmac(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:length]


def _labeled_extract(suite: bytes, salt: bytes, label: str, ikm: bytes) -> bytes:
    return _extract(salt, V1 + suite + label.encode() + ikm)


def _labeled_expand(suite: bytes, prk: bytes, label: str, info: bytes, length: int) -> bytes:
    return _expand(prk, length.to_bytes(2, "big") + V1 + suite + label.encode() + info, length)


class KeyPair:
    """An X25519 pair: `raw` is the public key's 32 bytes."""

    def __init__(self, private: X25519PrivateKey):
        self._private = private
        self.raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @classmethod
    def from_private(cls, sk: bytes) -> "KeyPair":
        return cls(X25519PrivateKey.from_private_bytes(sk))

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(X25519PrivateKey.generate())

    def dh(self, peer: bytes) -> bytes:
        """The shared secret; an all-zero one (a small-order peer key) is refused, whatever the library did (§7.1.4)."""
        try:
            z = self._private.exchange(X25519PublicKey.from_public_bytes(bytes(peer)))
        except ValueError:
            refuse("bad_form", "an X25519 key that gives no shared secret")
        if len(z) != 32 or not any(z):
            refuse("bad_form", "an X25519 key that gives no shared secret")
        return z


def _shared_secret(z: bytes, encapsulated: bytes, pk_r: bytes) -> bytes:
    prk = _labeled_extract(KEM, b"", "eae_prk", z)
    return _labeled_expand(KEM, prk, "shared_secret", encapsulated + pk_r, 32)


def derive_key_pair(ikm: bytes) -> KeyPair:
    """RFC 9180 §7.1.3 DeriveKeyPair for X25519."""
    prk = _labeled_extract(KEM, b"", "dkp_prk", ikm)
    return KeyPair.from_private(_labeled_expand(KEM, prk, "sk", b"", 32))


def _key_schedule(shared: bytes, info: bytes):
    psk_id_hash = _labeled_extract(SUITE, b"", "psk_id_hash", b"")
    info_hash = _labeled_extract(SUITE, b"", "info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(SUITE, shared, "secret", b"")
    return (
        _labeled_expand(SUITE, secret, "key", context, NK),
        _labeled_expand(SUITE, secret, "base_nonce", context, NN),
        _labeled_expand(SUITE, secret, "exp", context, NH),
    )


EXPORT_MAX = 255 * NH


def _export(exporter_secret: bytes, exporter_context: bytes, length: int) -> bytes:
    """Export (§5.3): `length` bytes, 1 to 255 * Nh, bound to the context and `exporter_context`; no sequence."""
    if not isinstance(exporter_context, (bytes, bytearray)):
        refuse("bad_form", "an exporter context is bytes")
    if isinstance(length, bool) or not isinstance(length, int) or not 1 <= length <= EXPORT_MAX:
        refuse("bad_form", f"an exported secret is 1 to {EXPORT_MAX} bytes")
    return _labeled_expand(SUITE, exporter_secret, "sec", bytes(exporter_context), length)


def _nonce_at(base: bytes, seq: int) -> bytes:
    return (int.from_bytes(base, "big") ^ seq).to_bytes(NN, "big")


class Sender:
    """A sender's context (§5.1.1): seals only. The sequence advances after each seal; an exact counter."""

    def __init__(self, pk_r: bytes, info: bytes, ephemeral: KeyPair | None = None, start: int = 0):
        if pk_r is None or len(pk_r) != 32:
            refuse("bad_form", "an X25519 key is 32 bytes")
        e = ephemeral or KeyPair.generate()
        z = e.dh(pk_r)
        self.enc = e.raw
        self._key, self._base, self._exp = _key_schedule(_shared_secret(z, e.raw, bytes(pk_r)), info)
        self._seq = start

    def seal(self, aad: bytes, pt: bytes) -> bytes:
        if self._seq >= SEQ_MAX:
            refuse("limit", "this context's sequence is used up")
        ct = AESGCM(self._key).encrypt(_nonce_at(self._base, self._seq), bytes(pt), bytes(aad))
        self._seq += 1
        return ct

    def export(self, exporter_context: bytes, length: int) -> bytes:
        return _export(self._exp, exporter_context, length)


class Recipient:
    """A recipient's context: opens only. A refused ciphertext leaves the sequence where it was."""

    def __init__(self, own: KeyPair, encapsulated: bytes, info: bytes, start: int = 0):
        if encapsulated is None or len(encapsulated) != 32:
            refuse("bad_form", "enc is 32 bytes")
        z = own.dh(encapsulated)
        self._key, self._base, self._exp = _key_schedule(_shared_secret(z, bytes(encapsulated), own.raw), info)
        self._seq = start

    def open(self, aad: bytes, ct: bytes) -> bytes:
        if self._seq >= SEQ_MAX:
            refuse("limit", "this context's sequence is used up")
        if len(ct) < NT:
            refuse("bad_form", "a ciphertext shorter than its tag")
        try:
            pt = AESGCM(self._key).decrypt(_nonce_at(self._base, self._seq), bytes(ct), bytes(aad))
        except InvalidTag:
            refuse("bad_form", "the ciphertext doesn't open under this key and header")
        self._seq += 1
        return pt

    def export(self, exporter_context: bytes, length: int) -> bytes:
        return _export(self._exp, exporter_context, length)


def seal(pk_r: bytes, info: bytes, aad: bytes, pt: bytes, ephemeral: KeyPair | None = None):
    s = Sender(pk_r, info, ephemeral)
    return s.enc, s.seal(aad, pt)


def open_(own: KeyPair, encapsulated: bytes, info: bytes, aad: bytes, ct: bytes) -> bytes:
    return Recipient(own, encapsulated, info).open(aad, ct)


def send_export(pk_r: bytes, info: bytes, exporter_context: bytes, length: int, ephemeral: KeyPair | None = None):
    s = Sender(pk_r, info, ephemeral)
    return s.enc, s.export(exporter_context, length)


def receive_export(own: KeyPair, encapsulated: bytes, info: bytes, exporter_context: bytes, length: int) -> bytes:
    return Recipient(own, encapsulated, info).export(exporter_context, length)
