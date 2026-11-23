# The fleet protocol's Python reference verifier

A second implementation of the verifying side of the fleet protocol, design r2.3 §9. The first is the JavaScript core in `lib/fleet/core`. Each Python module mirrors one JavaScript module, rule for rule and in the same order, so a disagreement shows up as a fixture case with another result.

| Python | JavaScript | What it checks |
| --- | --- | --- |
| `core.py` | `bytes.mjs`, `canon.mjs`, `canonical.mjs`, `ed25519.mjs` | ids, canonical base64url, strict UTF-8, canonical JSON (keys sorted by UTF-16 code units), strict Ed25519 |
| `schema.py` | `schema.mjs`, `schemas.mjs` | the closed JSON Schema subset; the frozen `schema/fleet` set |
| `envelope.py` | `envelope.mjs` | the signed envelope |
| `chain.py` | `chain.mjs` | the device chain, pins, device and service keys |
| `verify.py` | `verify.mjs` | host certificates, grants, acks, host operations, revocations, approvals |
| `hpke.py` | `hpke.mjs` | RFC 9180 base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM |
| `sealed.py` | `sealed.mjs` | the host's side of sealed packages and capability mints |

It verifies and opens only. Nothing here signs or seals for real use. The rule tests sign variants with the fixtures' mock seeds, and the RFC 9180 vector seals with its own fixed keys.

## The dependency

There is one dependency, `cryptography`, pinned by hash in `requirements.txt` together with its own requirements (`cffi`, `pycparser`). It is used only for Ed25519 verification, X25519, HMAC-SHA256 and AES-256-GCM. The strict Ed25519 rules are checked in Python before the library is asked:
- a canonical point;
- no small-order key;
- a canonical R;
- S < L.

All-zero X25519 output is refused whatever the library does. The canonical JSON, the schemas, the key schedule and every protocol rule are this package's own code.

```sh
python -m pip install --require-hashes --no-deps -r python/requirements.txt
python -I python/tests/test_fixtures.py -v
python -I python/tests/test_rules.py -v
```

## The tests

- **`test_fixtures.py`** runs every case of `test/fixtures/fleet-fixtures.json` and `test/fixtures/fleet-hpke-fixtures.json` as `test/fleet-fixture-cases.mjs` does. It expects the same result for each: `ok`, or the refusal's reason code. It also checks that the JavaScript checker's case counts all ran, and checks the RFC 9180 known-answer vector.
- **`test_rules.py`** covers rules the shared fixtures don't reach on their own, each with a passing control row:
  - strict Ed25519 shapes, canonical JSON depth and size;
  - `sig2`, signer kinds and fleets on envelopes;
  - the chain's `prev`, countersignature, removals, pins and recovery-key rotation;
  - a certificate's fingerprint, a host operation's early window, grant narrowing;
  - the schema subset's pattern end, required, `oneOf` and lengths.

## Differences from the JavaScript

- The API is synchronous, and contexts are dictionaries with snake_case keys (`current_gen`, `seen_op`, `resolve_key`).
- Python can't zero its immutable `bytes`, so keys and plaintexts aren't wiped as the JavaScript wipes them.
- A schema `pattern` must be in a subset that JavaScript's unicode-mode `RegExp` and Python's `re` read the same way: no escapes but `\.`, no groups that start with `?`, and `$` only at the end, translated to `\Z`. Any other pattern refuses the schema at load time, as an unknown keyword does.
- HPKE contexts don't have the JavaScript's in-flight guard against overlapping calls, which matters only for its asynchronous API.
