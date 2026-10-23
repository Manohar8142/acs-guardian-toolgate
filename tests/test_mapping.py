# SPDX-License-Identifier: Apache-2.0
import pytest
from toolgate import Decision

from acs_guardian_toolgate import validation
from acs_guardian_toolgate.mapping import PolicyIdentity, decision_fields

POL = PolicyIdentity("toolgate", "abc123", "default.yaml")
APPROVER = {"type": "human", "id": "operator"}


def _fields(action, rule="r", **kw):
    args = dict(tool="t.x", policy=POL, session_tainted=False, taint_source=None, approver=APPROVER,
                ask_timeout_seconds=60, ask_incapable=False, ask_incapable_substitute="deny")
    args.update(kw)
    return decision_fields(Decision(action, rule, "because"), **args)


def _valid(fields):
    result = {"type": "final", "acs_version": "0.1.0", "request_id": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36", **fields}
    return validation.response_errors({"jsonrpc": "2.0", "id": 1, "result": result})


@pytest.mark.parametrize("action,acs", [("allow", "allow"), ("deny", "deny"), ("require_approval", "ask")])
def test_core_mapping(action, acs):
    f, sub = _fields(action)
    assert f["decision"] == acs and sub is None
    assert f["reasoning"].startswith("toolgate: ")
    assert f["policy_references"][0] == {"policy_id": "toolgate", "policy_version": "abc123",
                                         "policy_name": "default.yaml", "rule_id": "r"}
    assert f["policy_data"]["toolgate"]["action"] == action
    assert _valid(f) == []


def test_default_applied_has_no_rule_id():
    f, _ = _fields("allow", rule=None)
    assert "rule_id" not in f["policy_references"][0]
    assert f["reason_codes"] == ["toolgate_default_applied"]


def test_ask_details_shape():
    f, _ = _fields("require_approval")
    assert validation.errors("ask-details.json", f["ask_details"]) == []
    assert f["ask_details"]["timeout_disposition"] == "deny"


def test_taint_reason_code():
    f, _ = _fields("require_approval", session_tainted=True, taint_source="web.fetch")
    assert "untrusted_into_consequential" in f["reason_codes"]


def test_ask_incapable_substitutes_deny():
    f, sub = _fields("require_approval", ask_incapable=True)
    assert f["decision"] == "deny" and "approver_unavailable" in f["reason_codes"] and "ask_details" not in f
    assert sub == {"intended": "ask", "substituted": "deny", "rule": "r"}
    assert _valid(f) == []


def test_ask_incapable_substitutes_defer():
    f, sub = _fields("require_approval", ask_incapable=True, ask_incapable_substitute="defer")
    assert f["decision"] == "defer" and f["defer_details"]["timeout_decision"] == "deny"
    assert validation.errors("defer-details.json", f["defer_details"]) == []
    assert _valid(f) == []
