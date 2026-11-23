"""Rules the shared fixtures don't reach on their own, each with a control row that passes and a row that must be
refused. Variants of the fixtures' objects are re-signed with the fixtures' mock seeds (test-only signing: the verifier
itself never signs). Some checks are also made by a later step (cryptography's own Ed25519 checks, the schema's provider
enum, a capability's HPKE info); those are tested here directly on the function that states the rule.

Run from anywhere: python -I python/tests/test_rules.py -v
"""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from sagebrush_fleet import (  # noqa: E402
    FleetError, apply_chain_entry, device_key, open_cap, open_envelope, replay, verify_approval, verify_grant, verify_grant_ack,
    verify_host_cert, verify_host_op, verify_package, verify_revocation,
)
from sagebrush_fleet.hpke import derive_key_pair  # noqa: E402
from sagebrush_fleet.core import L, P, b64, canon_bytes, canon_text, canonical_point, parse_canonical, strict_shape, unb64, utf8  # noqa: E402
from sagebrush_fleet.sealed import _purpose_of  # noqa: E402
from sagebrush_fleet.envelope import parse_envelope, signed_bytes  # noqa: E402
from sagebrush_fleet.schema import compile_schema  # noqa: E402
from sagebrush_fleet.verify import narrows_only  # noqa: E402

F = json.loads((ROOT / "test" / "fixtures" / "fleet-fixtures.json").read_text(encoding="utf-8"))
CTX = {"aud": F["aud"], "fleet": F["ids"]["fleet"]}
O = F["objects"]
SEEDS = {v["key_id"]: bytes.fromhex(v["seed"]) for v in F["keys"].values()}


def code(fn):
    try:
        fn()
        return "ok"
    except FleetError as e:
        return e.code


def enc(s):
    return s.encode("utf-8")


def sign(type_, signer, body, seed=None, **extra):
    """An envelope's bytes, signed with the mock seed behind signer.key (or `seed`)."""
    sk = Ed25519PrivateKey.from_private_bytes(seed or SEEDS[signer["key"]])
    return canon_bytes({"v": 1, "type": type_, "signer": signer, "body": body, "sig": b64(sk.sign(signed_bytes(type_, signer, body))), **extra})


def resign(text, edit):
    """A fixture envelope with its body edited, signed again by the same signer."""
    e = json.loads(text)
    body = copy.deepcopy(e["body"])
    edit(body)
    return sign(e["type"], e["signer"], body)


def device_signer(name):
    k = F["keys"][name]
    dev = next(d for d in CHAIN.devices.values() if d.key_id == k["key_id"])
    return {"kind": "device", "id": dev.id, "alg": "ed25519", "key": k["key_id"]}


def fresh_key(n):
    """A test-only Ed25519 public key (not a fixture key), as { alg, key }."""
    raw = Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"alg": "ed25519", "key": b64(raw)}


CHAIN = replay([enc(x) for x in O["chain"]], CTX)


def next_entry(state, signer, body):
    base = {"at_ms": F["now_ms"], "aud": CTX["aud"], "auth_time_ms": F["now_ms"], "fleet": CTX["fleet"], "seq": state.seq + 1, "prev": state.head}
    return sign("sb.device-chain.v1", signer, {**base, **body})


class Ed25519Shape(unittest.TestCase):
    """The strict rules, on the shape check that states them (the library repeats some of them)."""

    def test_signatures(self):
        c = next(x for x in F["ed25519"] if x["expect"] is True)
        raw, sig = unb64(c["public"], 32), unb64(c["sig"], 64)
        self.assertTrue(strict_shape(raw, sig), "control")
        s = int.from_bytes(sig[32:], "little")
        self.assertFalse(strict_shape(raw, sig[:32] + (s + L).to_bytes(32, "little")), "S + L")
        self.assertFalse(strict_shape(raw, P.to_bytes(32, "little") + sig[32:]), "an R with y = p")

    def test_points(self):
        self.assertTrue(canonical_point((P - 2).to_bytes(32, "little")))
        self.assertFalse(canonical_point(P.to_bytes(32, "little")), "y = p")
        self.assertFalse(canonical_point((P + 1).to_bytes(32, "little")), "y = p + 1")
        one = bytearray((1).to_bytes(32, "little"))
        self.assertTrue(canonical_point(bytes(one)))
        one[31] |= 0x80
        self.assertFalse(canonical_point(bytes(one)), "y = 1 with the sign bit")


class Canon(unittest.TestCase):
    def test_depth(self):
        self.assertEqual(code(lambda: parse_canonical(b"[" * 32 + b"]" * 32)), "ok", "32 deep")
        self.assertEqual(code(lambda: parse_canonical(b"[" * 33 + b"]" * 33)), "bad_form", "33 deep")

    def test_size(self):
        v = {"a": "x" * 40}
        n = len(canon_text(v).encode())
        self.assertEqual(code(lambda: canon_text(v, n)), "ok", "at the bound")
        self.assertEqual(code(lambda: canon_text(v, n - 1)), "limit", "one past it")


    def test_utf8(self):
        self.assertEqual(code(lambda: utf8(b"{}")), "ok")
        self.assertEqual(code(lambda: utf8(b"\xef\xbb\xbf{}")), "bad_form", "a byte-order mark")
        self.assertEqual(code(lambda: utf8(b"\xc0\xaf")), "bad_form", "an overlong encoding")


class Purposes(unittest.TestCase):
    def test_purpose_of_its_provider(self):
        self.assertEqual(code(lambda: _purpose_of("codex", "codex-access-token")), "ok")
        self.assertEqual(code(lambda: _purpose_of("claude", "codex-access-token")), "bad_form", "a codex purpose under another provider")
        self.assertEqual(code(lambda: _purpose_of("codex", "claude-setup-token")), "bad_form", "no Claude purpose")


class Envelopes(unittest.TestCase):
    def test_sig2_only_on_add(self):
        add = json.loads(O["chain"][2])
        self.assertEqual(add["body"]["op"], "add")
        other = json.loads(O["chain"][3])
        with_sig2 = canon_bytes({**other, "sig2": other["sig"]})
        self.assertEqual(code(lambda: parse_envelope(enc(O["chain"][3]), CTX)), "ok", "control")
        self.assertEqual(code(lambda: parse_envelope(with_sig2, CTX)), "bad_form", "sig2 on a service-key entry")

    def test_signer_kind(self):
        e = json.loads(O["host_ops"][0]["bytes"])
        e["signer"]["kind"] = "host"
        self.assertEqual(code(lambda: parse_envelope(canon_bytes(e), CTX)), "bad_signature", "a host-op signed by a host")

    def test_malformed_signer_kind(self):
        """through the public open: a list or object as signer.kind is bad_form, as in JavaScript (never a TypeError)"""
        e = json.loads(O["host_ops"][0]["bytes"])
        resolve = lambda s, t, b: device_key(CHAIN, s, b.get("chain_seq")).raw  # noqa: E731
        self.assertEqual(code(lambda: open_envelope(enc(O["host_ops"][0]["bytes"]), {**CTX, "resolve_key": resolve})), "ok", "control")
        for kind in ([], {}, ["device"], {"device": 1}, None, 1, True):
            with self.subTest(kind=kind):
                e["signer"]["kind"] = kind
                self.assertEqual(code(lambda: open_envelope(canon_bytes(e), {**CTX, "resolve_key": resolve})), "bad_form")

    def test_fleet(self):
        other = {**CTX, "fleet": F["ids"]["host"]}
        self.assertEqual(code(lambda: parse_envelope(enc(O["host_ops"][0]["bytes"]), other)), "bad_form", "another fleet")


class Chain(unittest.TestCase):
    def test_prev(self):
        native = device_signer("device-native")
        good = next_entry(CHAIN, native, {"op": "rotate-recovery", "recovery_key": fresh_key(7)})
        self.assertEqual(code(lambda: apply_chain_entry(CHAIN, good, CTX)), "ok", "control")
        bad = json.loads(good)
        bad["body"]["prev"] = CHAIN.hashes[0]
        self.assertEqual(code(lambda: apply_chain_entry(CHAIN, sign(bad["type"], bad["signer"], bad["body"]), CTX)), "chain_fork")

    def test_same_recovery_key(self):
        native = device_signer("device-native")
        same = {"alg": "ed25519", "key": b64(CHAIN.recovery.raw)}
        self.assertEqual(code(lambda: apply_chain_entry(CHAIN, next_entry(CHAIN, native, {"op": "rotate-recovery", "recovery_key": same}), CTX)), "bad_form")

    def test_countersignature(self):
        e = json.loads(O["chain"][2])
        e["sig2"] = e["sig"]  # (the enrolling device's signature, not the new device's)
        st = replay([enc(x) for x in O["chain"][:2]], CTX)
        self.assertEqual(code(lambda: apply_chain_entry(st, enc(O["chain"][2]), CTX)), "ok", "control")
        self.assertEqual(code(lambda: apply_chain_entry(st, canon_bytes(e), CTX)), "bad_signature")

    def test_removed_device(self):
        native, native2 = device_signer("device-native"), device_signer("device-native-2")
        removal = next_entry(CHAIN, native, {"op": "remove", "remove": native2["id"], "regrants": []})
        st, _ = apply_chain_entry(CHAIN, removal, CTX)
        later = next_entry(st, native2, {"op": "rotate-recovery", "recovery_key": fresh_key(8)})
        self.assertEqual(code(lambda: apply_chain_entry(st, later, CTX)), "device_unknown", "a removed device signs")
        self.assertEqual(code(lambda: device_key(st, native2, 5)), "device_removed", "signed before its removal")
        self.assertEqual(code(lambda: device_key(st, native2, 6)), "device_unknown", "signed at its removal")

    def test_pin(self):
        ok = {"seq": 2, "hash": CHAIN.hashes[2]}
        self.assertEqual(code(lambda: replay([enc(x) for x in O["chain"]], CTX, ok)), "ok", "control")
        self.assertEqual(code(lambda: replay([enc(x) for x in O["chain"]], CTX, {"seq": 2, "hash": CHAIN.hashes[3]})), "chain_fork")


class Verifiers(unittest.TestCase):
    def test_cert_fingerprint(self):
        ctx = {**CTX, "chain": CHAIN}
        self.assertEqual(code(lambda: verify_host_cert(resign(O["host_cert"], lambda b: None), ctx)), "ok", "control")
        bad = resign(O["host_cert"], lambda b: b.update(fingerprint=b64(bytes(32))))
        self.assertEqual(code(lambda: verify_host_cert(bad, ctx)), "bad_form")

    def test_host_op_window(self):
        c = next(x for x in O["host_ops"] if x["expect"] == "ok")
        now = F["now_ms"]
        ctx = {**CTX, "chain": CHAIN, "host": F["ids"]["host"], "current_gen": c["current_gen"], "now": now, "seen_op": lambda _: False}

        def at(t):
            return resign(c["bytes"], lambda b: b.update(at_ms=t, not_after_ms=t + 5 * 60_000))

        self.assertEqual(code(lambda: verify_host_op(at(now + 5 * 60_000), ctx)), "ok", "5 minutes early: in the window")
        self.assertEqual(code(lambda: verify_host_op(at(now + 5 * 60_000 + 1), ctx)), "grant_expired", "one past it")

    def test_narrowing(self):
        g = json.loads(next(x for x in O["grants"] if x["expect"] == "ok")["bytes"])["body"]
        self.assertTrue(narrows_only(g, copy.deepcopy(g)), "the same grant")
        later = copy.deepcopy(g)
        later["not_after_ms"] = None if g["not_after_ms"] is not None else 1
        if g["not_after_ms"] is not None:
            self.assertFalse(narrows_only(g, later), "no expiry widens")
        later = copy.deepcopy(g)
        if g["not_after_ms"] is not None:
            later["not_after_ms"] += 1
            self.assertFalse(narrows_only(g, later), "a later expiry widens")


class Schema(unittest.TestCase):
    def check(self, schema, value):
        return code(lambda: compile_schema(schema)(value))

    def test_pattern_end(self):
        s = {"type": "string", "pattern": "^a$"}
        self.assertEqual(self.check(s, "a"), "ok")
        self.assertEqual(self.check(s, "a\n"), "bad_form", "JavaScript's $ doesn't match before a final newline")

    def test_required(self):
        s = {"type": "object", "required": ["x"]}
        self.assertEqual(self.check(s, {"x": 1}), "ok")
        self.assertEqual(self.check(s, {}), "bad_form")

    def test_one_of(self):
        s = {"oneOf": [{"type": "integer"}, {"minimum": 0}]}
        self.assertEqual(self.check(s, -1), "ok", "one matches")
        self.assertEqual(self.check(s, 5), "bad_form", "both match")
        self.assertEqual(self.check(s, "x"), "ok", "a string: only the minimum (which ignores strings) matches")

    def test_max_length(self):
        s = {"type": "string", "maxLength": 2}
        self.assertEqual(self.check(s, "a\U0001F600"), "ok", "2 code points (3 UTF-16 units)")
        self.assertEqual(self.check(s, "abc"), "bad_form")

    def test_portable_patterns_only(self):
        for p in ["^\\d$", "(?=a)", "a$b"]:
            with self.subTest(pattern=p):
                with self.assertRaises(ValueError):
                    compile_schema({"pattern": p})


HOST = {"kind": "host", "id": F["ids"]["host"], "alg": "ed25519", "key": F["keys"]["host"]["key_id"]}
CERT = verify_host_cert(enc(O["host_cert"]), {**CTX, "chain": CHAIN})


class GrantAcks(unittest.TestCase):
    def ack(self, gen, signer=HOST, seed=None, host=None):
        body = {"at_ms": F["now_ms"], "aud": CTX["aud"], "fleet": CTX["fleet"], "gen": gen, "host": host or signer["id"], "narrowed": False, "restarted": []}
        return sign("sb.grant-ack.v1", signer, body, seed=seed)

    def verify(self, data, current_gen=3):
        return code(lambda: verify_grant_ack(data, {**CTX, "cert": CERT, "current_gen": current_gen}))

    def test_acks(self):
        self.assertEqual(self.verify(self.ack(3)), "ok", "the current generation")
        self.assertEqual(self.verify(self.ack(2)), "ok", "an older one")
        self.assertEqual(self.verify(self.ack(4)), "stale_generation", "ahead of the grant")
        self.assertEqual(self.verify(self.ack(3, seed=bytes.fromhex(F["keys"]["x1"]["seed"]))), "bad_signature", "another key under the host's name")
        other = {**HOST, "id": F["ids"]["agent"]}
        self.assertEqual(self.verify(self.ack(3, signer=other)), "bad_signature", "another host")
        self.assertEqual(self.verify(self.ack(3, host=F["ids"]["agent"])), "bad_signature", "a body for another host")
        device = device_signer("device-native")
        self.assertEqual(self.verify(self.ack(3, signer=device, host=F["ids"]["host"])), "bad_signature", "signed by a device")


class Revocations(unittest.TestCase):
    def revocation(self, signer, chain_seq, seed=None):
        body = {"at_ms": F["now_ms"], "aud": CTX["aud"], "fleet": CTX["fleet"], "chain_seq": chain_seq, "gen": 3, "host": F["ids"]["host"], "id": F["ids"]["agent"], "what": "agent"}
        return sign("sb.revocation.v1", signer, body, seed=seed)

    def test_revocations(self):
        native, native2 = device_signer("device-native"), device_signer("device-native-2")
        ctx = {**CTX, "chain": CHAIN}
        self.assertEqual(code(lambda: verify_revocation(self.revocation(native, 5), ctx)), "ok")
        self.assertEqual(code(lambda: verify_revocation(self.revocation(native, 5, seed=SEEDS[native2["key"]]), ctx)), "bad_signature", "another device's key")
        self.assertEqual(code(lambda: verify_revocation(self.revocation(native, 6), ctx)), "device_unknown", "a chain_seq past the head")
        # a removed signer: a revocation it signed before its removal still holds; one at or after it doesn't
        st, _ = apply_chain_entry(CHAIN, next_entry(CHAIN, native, {"op": "remove", "remove": native2["id"], "regrants": []}), CTX)
        ctx = {**CTX, "chain": st}
        self.assertEqual(code(lambda: verify_revocation(self.revocation(native2, 5), ctx)), "ok", "signed before its removal")
        self.assertEqual(code(lambda: verify_revocation(self.revocation(native2, 6), ctx)), "device_unknown", "signed at its removal")
        self.assertEqual(code(lambda: device_key(st, native2, 5)), "device_removed", "(where only a revocation is let through)")


class Malformed(unittest.TestCase):
    """Every node of every fixture object replaced by each kind of JSON value, one at a time, through its verifier:
    the result is a refusal or ok, never another exception. (Bytes stay canonical; the signature mostly won't hold.)"""

    KINDS = [None, True, 0, "x", [], {}, [[]], {"a": {}}]

    def variants(self, value):
        def walk(v, path):
            yield path
            if isinstance(v, dict):
                for k in v:
                    yield from walk(v[k], path + (k,))
            elif isinstance(v, list):
                for i, x in enumerate(v):
                    yield from walk(x, path + (i,))

        for path in walk(value, ()):
            if not path:
                continue
            for k in self.KINDS:
                w = copy.deepcopy(value)
                at = w
                for p in path[:-1]:
                    at = at[p]
                at[path[-1]] = copy.deepcopy(k)
                yield path, w

    def run_all(self, label, value, check, encode=True):
        n = 0
        for path, w in self.variants(value):
            data = canon_bytes(w) if encode else w
            try:
                check(data)
            except FleetError:
                pass
            except Exception as e:  # noqa: BLE001 (the finding this row exists for)
                self.fail(f"{label} at {path}: {type(e).__name__}: {e}")
            n += 1
        return n

    def test_fleet_objects(self):
        n = 0
        ctx = {**CTX, "chain": CHAIN}
        for i, x in enumerate(O["chain"]):
            st = replay([enc(y) for y in O["chain"][:i]], CTX) if i else None
            n += self.run_all(f"chain {i}", json.loads(x), lambda d: apply_chain_entry(st, d, CTX))
        n += self.run_all("host cert", json.loads(O["host_cert"]), lambda d: verify_host_cert(d, ctx))
        for c in O["grants"][:3]:
            n += self.run_all("grant", json.loads(c["bytes"]), lambda d: verify_grant(d, {**ctx, "cert": CERT, "current": None, "now": F["now_ms"]}))
        for c in O["host_ops"][:2]:
            n += self.run_all("host op", json.loads(c["bytes"]), lambda d: verify_host_op(d, {**ctx, "host": F["ids"]["host"], "current_gen": 3, "now": F["now_ms"], "seen_op": lambda _: False}))
        for c in O["approvals"][:3]:
            n += self.run_all("approval", json.loads(c["bytes"]), lambda d: verify_approval(d, {**ctx, "now": F["now_ms"], "expect": c["expect_op"], "current": c.get("current"), "used": lambda a: False}))
        ack = json.loads(GrantAcks().ack(3))
        n += self.run_all("ack", ack, lambda d: verify_grant_ack(d, {**CTX, "cert": CERT, "current_gen": 3}))
        rev = json.loads(Revocations().revocation(device_signer("device-native"), 5))
        n += self.run_all("revocation", rev, lambda d: verify_revocation(d, ctx))
        self.assertGreater(n, 1000)

    def test_hpke_objects(self):
        H = json.loads((ROOT / "test" / "fixtures" / "fleet-hpke-fixtures.json").read_text(encoding="utf-8"))
        hctx = {"aud": H["aud"], "fleet": H["ids"]["fleet"]}
        chain = replay([enc(x) for x in H["chain"]], hctx)
        cert = verify_host_cert(enc(H["host_cert"]), {**hctx, "chain": chain})
        ek = derive_key_pair(bytes.fromhex(H["host_enc_ikm"]))
        n = 0
        for c in H["packages"][:2]:
            x = c["ctx"]
            v = {**hctx, "chain": chain, "cert": cert, "host_revoked": lambda _: False, "enc_key": ek, "current_gen": x["current_gen"], "grant": H["grant"], "now": x["now_ms"], "revoked": lambda p: False, "opened": lambda p: False}
            n += self.run_all("package", json.loads(c["bytes"]), lambda d: verify_package(d, v))
        for c in H["caps"][:2]:
            n += self.run_all("cap", c["response"], lambda r: open_cap(r, {**c["ctx"], "now": c["ctx"]["now_ms"], "enc_key": ek}), encode=False)
            for bad in (None, [], "x", 1):
                try:
                    open_cap(bad, {**c["ctx"], "now": c["ctx"]["now_ms"], "enc_key": ek})
                except FleetError:
                    pass
        self.assertGreater(n, 100)


if __name__ == "__main__":
    unittest.main()
