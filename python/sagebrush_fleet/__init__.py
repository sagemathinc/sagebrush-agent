"""The fleet protocol's reference verifier in Python (design agent-autonomous-schemas.md r2.3 §9).

A second, independent implementation of the JavaScript core's verifying side (lib/fleet/core): canonical JSON, strict
Ed25519, the envelope, the device chain, the object verifiers, the closed schema validator, HPKE and the host's side of
sealed packages and capability mints. It signs and seals nothing for real use. It must give every case of
test/fixtures/fleet-fixtures.json and test/fixtures/fleet-hpke-fixtures.json the JavaScript checker's result.
"""

from .chain import device_key, replay, require_tier, service_key_at
from .chain import apply as apply_chain_entry
from .core import FleetError, b64, canon_text, is_id, key_id, parse_canonical, unb64, verify_strict
from .envelope import open_envelope
from .hpke import derive_key_pair
from .sealed import open_cap, verify_package
from .verify import verify_approval, verify_grant, verify_grant_ack, verify_host_cert, verify_host_op, verify_revocation

__all__ = [
    "FleetError", "apply_chain_entry", "b64", "canon_text", "derive_key_pair", "device_key", "is_id", "key_id",
    "open_cap", "open_envelope", "parse_canonical", "replay", "require_tier", "service_key_at", "unb64",
    "verify_approval", "verify_grant", "verify_grant_ack", "verify_host_cert", "verify_host_op", "verify_package",
    "verify_revocation", "verify_strict",
]
