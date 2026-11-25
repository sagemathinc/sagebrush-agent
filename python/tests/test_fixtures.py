"""Every case of the shared fleet fixtures through the Python verifier, as test/fleet-fixture-cases.mjs runs them
through the JavaScript core: the same inputs, and the same result ("ok" or the refusal's code) for each.

Run from anywhere: python -I python/tests/test_fixtures.py -v
"""

import hmac as std_hmac
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from sagebrush_fleet import (  # noqa: E402
    FleetError, apply_chain_entry, canon_text, derive_key_pair, device_key, is_id, key_id, open_cap, open_envelope,
    parse_canonical, replay, service_key_at, unb64, verify_approval, verify_grant, verify_grant_ack, verify_host_cert, verify_host_op,
    verify_package, verify_strict, verify_transfer_receipt, check_transfer_for_host,
)
from sagebrush_fleet.hpke import Recipient, Sender, receive_export, send_export  # noqa: E402

FIXTURES = ROOT / "test" / "fixtures"
# (the JavaScript checker's case counts: a fixture file that loses cases fails here, not silently)
COUNTS = {"fleet": 130, "hpke": 34}


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def result(fn):
    try:
        fn()
        return "ok"
    except FleetError as e:
        return e.code


def enc(s):
    return s.encode("utf-8")


class Cases(unittest.TestCase):
    """Each group is one test; each case a subTest, so every mismatch is reported with its group and name."""

    ran = {}

    def each(self, group, cases):
        n = 0
        for name, got, expect in cases:
            n += 1
            with self.subTest(group=group, case=name):
                self.assertEqual(got, expect)
        self.assertGreater(n, 0, f"{group}: no cases")
        Cases.ran[group] = n
        return n


class FleetFixtures(Cases):
    @classmethod
    def setUpClass(cls):
        cls.F = load("fleet-fixtures.json")
        cls.ctx = {"aud": cls.F["aud"], "fleet": cls.F["ids"]["fleet"]}

    def test_canonical(self):
        self.each("canonical", ((c["name"], result(lambda: parse_canonical(unb64(c["bytes_b64"]))), c["expect"]) for c in self.F["canonical"]))

    def test_base64url(self):
        self.each("base64url", ((c["name"], result(lambda: unb64(c["value"], c.get("len"))), c["expect"]) for c in self.F["base64url"]))

    def test_ids(self):
        self.each("ids", ((c["value"], "ok" if is_id(c["value"]) else "bad_form", c["expect"]) for c in self.F["ids_cases"]))

    def test_ed25519(self):
        self.each("ed25519", ((c["name"], verify_strict(unb64(c["public"], 32), unb64(c["msg_b64"]), unb64(c["sig"], 64)), c["expect"]) for c in self.F["ed25519"]))

    def test_chain(self):
        def run(c):
            def go():
                st = replay([enc(x) for x in c["entries"]], self.ctx, c.get("pin"))
                if c.get("append"):
                    apply_chain_entry(st, enc(c["append"]), self.ctx)
            return result(go)

        self.each("chain", ((c["name"], run(c), c["expect"]) for c in self.F["chain"]["cases"]))

    def test_service_keys(self):
        sk = replay([enc(x) for x in self.F["service_keys"]["chain"]], self.ctx)
        self.each("service_keys", ((c["name"], result(lambda: service_key_at(sk, c["signer"], c["chain_seq"])), c["expect"]) for c in self.F["service_keys"]["cases"]))

    def objects(self):
        O = self.F["objects"]
        st = replay([enc(x) for x in O["chain"]], self.ctx)
        cert = verify_host_cert(enc(O["host_cert"]), {**self.ctx, "chain": st})
        return O, st, cert

    def test_envelopes(self):
        O, st, _ = self.objects()
        resolve = lambda s, t, b: device_key(st, s, b.get("chain_seq")).raw  # noqa: E731
        self.each("envelopes", ((c["name"], result(lambda: open_envelope(enc(c["bytes"]), {**(c.get("ctx") or self.ctx), "resolve_key": resolve})), c["expect"]) for c in O["envelopes"]))

    def test_grants(self):
        O, st, cert = self.objects()

        def run(c):
            cur = c.get("current")
            current = cur and {"gen": cur["gen"], "bytes": enc(cur["bytes"]), "body": json.loads(cur["bytes"])["body"]}
            return result(lambda: verify_grant(enc(c["bytes"]), {**self.ctx, "chain": st, "cert": cert, "current": current, "now": self.F["now_ms"]}))

        self.each("grants", ((c["name"], run(c), c["expect"]) for c in O["grants"]))

    def test_grant_acks(self):
        O, _, cert = self.objects()
        self.each("grant_acks", ((c["name"], result(lambda: verify_grant_ack(enc(c["bytes"]), {**self.ctx, "cert": cert, "current_gen": c["current_gen"]})), c["expect"]) for c in O["grant_acks"]))

    def test_host_ops(self):
        O, st, _ = self.objects()
        self.each("host_ops", ((c["name"], result(lambda: verify_host_op(enc(c["bytes"]), {
            **self.ctx, "chain": st, "host": self.F["ids"]["host"], "current_gen": c["current_gen"], "now": self.F["now_ms"], "seen_op": lambda _: False,
        })), c["expect"]) for c in O["host_ops"]))

    def test_approvals(self):
        O, st, _ = self.objects()
        self.each("approvals", ((c["name"], result(lambda: verify_approval(enc(c["bytes"]), {
            **self.ctx, "chain": st, "now": self.F["now_ms"], "expect": c["expect_op"], "current": c.get("current"), "used": lambda a: a in c["used"],
        })), c["expect"]) for c in O["approvals"]))

    def test_transfer_receipts(self):
        X = self.F["transfers"]
        chains = {"honest": replay([enc(x) for x in X["chain"]], self.ctx), "removed": replay([enc(x) for x in X["chain_removed"]], self.ctx)}
        self.each("transfer_receipts", ((c["name"], result(lambda: verify_transfer_receipt(
            {"transfer": enc(c["transfer"]), "receipt": enc(c["receipt"])}, {**self.ctx, "chain": chains[c.get("chain", "honest")]})), c["expect"]) for c in X["receipts"]))

    def test_transfer_hosts(self):
        def host_of(r):
            return {
                "id": r["id"], "fingerprint": r["fingerprint"],
                "grant_hash_at": lambda g: (r["grants"].get(str(g)) or {}).get("hash"),
                "grant_lists_agent": lambda g, a: a in (r["grants"].get(str(g)) or {}).get("agents", []),
                "listed_since": lambda a: r["listed_since"].get(a), "entry_gen": lambda a: r["entry_gen"].get(a),
                "accepted_transfer": lambda a: r["accepted"].get(a), "nonce_seen": lambda x: r["nonces"].get(x),
            }

        def run(c):
            out = {}
            got = result(lambda: out.update(check_transfer_for_host({"transfer": c["pair"]["transfer"], "transfer_hash": c["pair"]["transferHash"]}, host_of(c["host"]))))
            return f"ok first={str(out['first']).lower()}" if got == "ok" else got

        self.each("transfer_hosts", ((c["name"], run(c), f"ok first={str(c['first']).lower()}" if c["expect"] == "ok" else c["expect"]) for c in self.F["transfers"]["hosts"]))

    def test_zz_every_case_ran(self):
        """(named to run last in the class) the JavaScript checker's count of cases, all of them run here"""
        groups = ["canonical", "base64url", "ids", "ed25519", "chain", "service_keys", "envelopes", "grants", "grant_acks", "host_ops", "approvals",
                  "transfer_receipts", "transfer_hosts"]
        missing = [g for g in groups if g not in Cases.ran]
        if missing:
            self.skipTest(f"run alone: {missing} not run")
        self.assertEqual(sum(Cases.ran[g] for g in groups), COUNTS["fleet"])


class HpkeVector(unittest.TestCase):
    """RFC 9180's known-answer vector for this suite: both key pairs, enc, and every encryption in sequence."""

    def test_vector(self):
        V = load("hpke-x25519-sha256-aes256gcm.json")["vector"]
        h = bytes.fromhex
        E, R = derive_key_pair(h(V["ikmE"])), derive_key_pair(h(V["ikmR"]))
        self.assertEqual(E.raw.hex(), V["pkEm"])
        self.assertEqual(R.raw.hex(), V["pkRm"])
        S, O = Sender(R.raw, h(V["info"]), E), Recipient(R, h(V["enc"]), h(V["info"]))
        self.assertEqual(S.enc.hex(), V["enc"])
        self.assertEqual(len(V["encryptions"]), 257)
        for i, e in enumerate(V["encryptions"]):
            with self.subTest(encryption=i):
                self.assertEqual(S.seal(h(e["aad"]), h(e["pt"])).hex(), e["ct"])
                self.assertEqual(O.open(h(e["aad"]), h(e["ct"])).hex(), e["pt"])
        # (a refused open leaves the sequence where it was)
        e0, e1 = V["encryptions"][0], V["encryptions"][1]
        O2 = Recipient(R, h(V["enc"]), h(V["info"]))
        self.assertEqual(O2.open(h(e0["aad"]), h(e0["ct"])).hex(), e0["pt"])
        self.assertEqual(result(lambda: O2.open(h(e0["aad"]), h(e0["ct"]))), "bad_form")
        self.assertEqual(O2.open(h(e1["aad"]), h(e1["ct"])).hex(), e1["pt"])
        # every exported secret, from both sides and single-shot
        self.assertEqual(len(V["exports"]), 3)
        for i, x in enumerate(V["exports"]):
            with self.subTest(export=i):
                c = h(x["exporter_context"])
                self.assertEqual(S.export(c, x["L"]).hex(), x["exported_value"])
                self.assertEqual(O.export(c, x["L"]).hex(), x["exported_value"])
                self.assertEqual(send_export(R.raw, h(V["info"]), c, x["L"], E), (h(V["enc"]), h(x["exported_value"])))
                self.assertEqual(receive_export(R, h(V["enc"]), h(V["info"]), c, x["L"]).hex(), x["exported_value"])
        # every block of long outputs, against HKDF-Expand written out here over the standard library's HMAC
        # (independent of the module's own expand), from the vector's exporter_secret; the last block on its own too
        def expected(ctx, L):
            info = L.to_bytes(2, "big") + b"HPKE-v1HPKE" + bytes([0, 0x20, 0, 1, 0, 2]) + b"sec" + ctx
            t, out = b"", b""
            for i in range(1, (L + 31) // 32 + 1):
                t = std_hmac.digest(h(V["exporter_secret"]), t + info + bytes([i]), "sha256")
                out += t
            return out[:L]

        n = 0
        for L in (1, 31, 32, 33, 63, 64, 65, 8159, 8160):
            for c in (b"", b"TestContext", bytes([0xA5]) * 300):
                want = expected(c, L)
                for side, got in (("sender", S.export(c, L)), ("recipient", O.export(c, L)),
                                  ("send_export", send_export(R.raw, h(V["info"]), c, L, E)[1]),
                                  ("receive_export", receive_export(R, h(V["enc"]), h(V["info"]), c, L))):
                    with self.subTest(side=side, L=L, context=len(c)):
                        self.assertEqual(got, want)
                        self.assertEqual(got[-32:], want[-32:])
                    n += 1
        self.assertEqual(n, 9 * 3 * 4)
        for bad in (0, -1, 8161, 1.5, True, "32", None):
            self.assertEqual(result(lambda: S.export(b"", bad)), "bad_form", bad)
        self.assertEqual(result(lambda: O.export("pop", 32)), "bad_form")


class HpkeFixtures(Cases):
    @classmethod
    def setUpClass(cls):
        F = cls.F = load("fleet-hpke-fixtures.json")
        cls.ctx = {"aud": F["aud"], "fleet": F["ids"]["fleet"]}
        cls.chain = replay([enc(x) for x in F["chain"]], cls.ctx)
        cls.cert = verify_host_cert(enc(F["host_cert"]), {**cls.ctx, "chain": cls.chain})
        cls.enc_key = derive_key_pair(bytes.fromhex(F["host_enc_ikm"]))

    def test_key_ids(self):
        self.each("key_ids", ((c["name"], key_id(c["alg"], unb64(c["raw"], 32)), c["key_id"]) for c in self.F["key_ids"]))

    def test_packages(self):
        def run(c):
            x, out = c["ctx"], {}
            v = {
                **self.ctx, "chain": self.chain, "cert": self.cert, "host_revoked": lambda _: x["host_revoked"], "enc_key": self.enc_key,
                "current_gen": x["current_gen"], "grant": self.F["grant"], "now": x["now_ms"],
                "revoked": lambda p: p in x["revoked"], "opened": lambda p: p in x["opened"],
            }
            got = result(lambda: out.setdefault("r", verify_package(enc(c["bytes"]), v)))
            rows = [(c["name"], got, c["expect"])]
            if c.get("plaintext"):
                rows.append((c["name"] + ": its plaintext", out.get("r") and canon_text(out["r"]["plaintext"]), canon_text(c["plaintext"])))
            return rows

        self.each("packages", (row for c in self.F["packages"] for row in run(c)))

    def test_caps(self):
        def run(c):
            out = {}
            got = result(lambda: out.setdefault("p", open_cap(c["response"], {**c["ctx"], "now": c["ctx"]["now_ms"], "enc_key": self.enc_key})))
            rows = [(c["name"], got, c["expect"])]
            if c.get("token"):
                rows.append((c["name"] + ": its token", (out.get("p") or {}).get("token"), c["token"]))
            return rows

        self.each("caps", (row for c in self.F["caps"] for row in run(c)))

    def test_zz_every_case_ran(self):
        groups = ["key_ids", "packages", "caps"]
        missing = [g for g in groups if g not in Cases.ran]
        if missing:
            self.skipTest(f"run alone: {missing} not run")
        self.assertEqual(sum(Cases.ran[g] for g in groups), COUNTS["hpke"])


if __name__ == "__main__":
    unittest.main()
