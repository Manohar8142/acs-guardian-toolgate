# SPDX-License-Identifier: Apache-2.0
from acs_guardian_toolgate import validation
from acs_guardian_toolgate.client import client_hello, envelope, tool_call


def test_payload_schema_lookup():
    assert validation.payload_schema_for("steps/toolCallRequest") == "hooks/tool-call-request.json"
    assert validation.payload_schema_for("steps/toolCallRequest", True) == "hooks/tool-call-request.acs-provenance.json"
    assert validation.payload_schema_for("steps/sessionEnd") == "hooks/session-end.json"
    assert validation.payload_schema_for("system/ping") == "hooks/system-ping.json"
    assert validation.payload_schema_for("steps/nope") is None
    assert {"steps/toolCallRequest", "steps/toolCallResult", "steps/sessionStart"} <= validation.known_step_methods()


def test_request_validation():
    good = envelope("steps/toolCallRequest", tool_call("x", a=1), session_id="6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36")
    assert validation.request_errors(good) == []
    bad = envelope("steps/toolCallRequest", {}, session_id="6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36")
    assert any("tool" in e for e in validation.request_errors(bad))
    not_uuid = envelope("steps/toolCallRequest", tool_call("x"), session_id="not-a-uuid")
    assert validation.request_errors(not_uuid)


def test_provenance_profile_requires_provenance():
    e = envelope("steps/toolCallRequest", tool_call("x", a=1), session_id="6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36")
    assert validation.request_errors(e, provenance_profile=False) == []
    assert validation.request_errors(e, provenance_profile=True)


def test_client_hello_and_payload_gating():
    h = envelope("handshake/hello", client_hello(), session_id="6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36")
    assert validation.request_errors(h) == []
    e = envelope("steps/sessionEnd", {}, session_id="6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36")
    assert validation.request_errors(e)                       # session-end payload requires 'reason'
    assert validation.request_errors(e, payload_methods=[]) == []
