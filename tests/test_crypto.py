# SPDX-License-Identifier: Apache-2.0
import base64
import copy

import pytest

from acs_guardian_toolgate.crypto import KeyRing, SignatureError, decode_secret, hkdf_sha256, jcs
from acs_guardian_toolgate.client import envelope


def test_spec_section_10_hkdf_vector():
    key = hkdf_sha256(bytes(range(32)), b"6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36")
    assert key.hex() == "80f0dc8c611279bfc2af2d5f374c5cb685888192ce1af5c3e0673d8fa748e8a4"


def test_rfc5869_case_3():
    assert hkdf_sha256(b"\x0b" * 22, b"", 42).hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")


def test_session_id_used_as_sent():
    sid = "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"
    assert hkdf_sha256(bytes(range(32)), sid.upper().encode()) != hkdf_sha256(bytes(range(32)), sid.encode())


def test_jcs_is_rfc8785():
    assert jcs({"b": 1, "a": [1.0, "é", None]}) == '{"a":[1,"é",null],"b":1}'.encode()


def test_secret_rules():
    with pytest.raises(ValueError):
        decode_secret(base64.b64encode(b"short").decode())
    with pytest.raises(ValueError):
        decode_secret("not base64!!")
    assert len(decode_secret("  " + base64.b64encode(bytes(32)).decode() + "\n")) == 32


def _ring(*ids):
    r = KeyRing()
    for i, k in enumerate(ids):
        r.add(k, base64.b64encode(bytes([i + 1]) * 32).decode())
    return r


def test_sign_verify_roundtrip_and_tamper():
    ring = _ring("a")
    env = ring.sign_request(envelope("steps/toolCallRequest", {"x": 1}, session_id="s-1"), "a")
    assert ring.verify_request(env) == "a"
    bad = copy.deepcopy(env)
    bad["params"]["payload"]["x"] = 2
    with pytest.raises(SignatureError):
        ring.verify_request(bad)
    bad = copy.deepcopy(env)
    bad["method"] = "steps/toolCallResult"
    with pytest.raises(SignatureError):
        ring.verify_request(bad)


def test_unknown_key_id_no_fallback():
    signer, verifier = _ring("a"), _ring("b")
    env = signer.sign_request(envelope("steps/x", {}, session_id="s"), "a")
    with pytest.raises(SignatureError, match="unknown key_id"):
        verifier.verify_request(env)


def test_rotation_two_keys_at_once():
    ring = _ring("2026-09", "2026-10")
    for kid in ("2026-09", "2026-10"):
        assert ring.verify_request(ring.sign_request(envelope("steps/x", {}, session_id="s"), kid)) == kid


def test_response_signature_uses_request_key_and_session():
    ring = _ring("a")
    resp = {"jsonrpc": "2.0", "id": "1", "result": {"type": "final", "decision": "allow"}}
    ring.sign_response(resp, "a", "sess")
    assert ring.verify_response(resp, "sess")
    assert not ring.verify_response(resp, "other-session")


def test_keyring_repr_has_no_secret():
    ring = _ring("a")
    assert "a" in repr(ring) and "AQEB" not in repr(ring)
