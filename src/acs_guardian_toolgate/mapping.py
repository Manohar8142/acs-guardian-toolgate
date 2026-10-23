# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""Tool-gate decision -> ACS v0.1.0 decision fields.

| Tool-gate          | ACS decision | Required ACS fields carried                     |
|--------------------|--------------|-------------------------------------------------|
| allow              | allow        | reasoning (RECOMMENDED), policy_references       |
| deny               | deny         | reasoning, reason_codes, policy_references       |
| require_approval   | ask          | reasoning, ask_details{approver,question,...}    |
| require_approval * | deny / defer | §9.2 substitution for ASK-incapable agent_ids    |

Tool-gate has no MODIFY verdict, so this Guardian never emits ``modify``.
"""

from __future__ import annotations

from dataclasses import dataclass

from toolgate import ALLOW, DENY, REQUIRE_APPROVAL, Decision

_ACS = {ALLOW: "allow", DENY: "deny", REQUIRE_APPROVAL: "ask"}


@dataclass
class PolicyIdentity:
    policy_id: str
    policy_version: str   # sha256 prefix of the policy file bytes
    policy_name: str


def acs_decision_for(decision: Decision) -> str:
    return _ACS[decision.action]


def decision_fields(
    decision: Decision,
    *,
    tool: str,
    policy: PolicyIdentity,
    session_tainted: bool,
    taint_source: str | None,
    approver: dict,
    ask_timeout_seconds: int,
    ask_incapable: bool,
    ask_incapable_substitute: str,
) -> tuple[dict, dict | None]:
    """Return (acs result fields, substitution audit record or None)."""
    acs = acs_decision_for(decision)
    rule_fired = decision.rule is not None
    reason_codes = ["toolgate_rule_fired" if rule_fired else "toolgate_default_applied"]
    if session_tainted and acs != "allow":
        reason_codes.append("untrusted_into_consequential")
    ref = {"policy_id": policy.policy_id, "policy_version": policy.policy_version, "policy_name": policy.policy_name}
    if rule_fired:
        ref["rule_id"] = decision.rule
    fields: dict = {
        "decision": acs,
        "reasoning": f"toolgate: {decision.reason}",
        "reason_codes": reason_codes,
        "policy_references": [ref],
        "policy_data": {
            "toolgate": {
                "action": decision.action,
                "rule": decision.rule,
                "tool": tool,
                "session_tainted": session_tainted,
                "taint_source": taint_source,
            }
        },
    }
    substitution = None
    if acs == "ask":
        if ask_incapable:
            # §9.2: never return ASK to a client that cannot route it.
            if ask_incapable_substitute == "defer":
                fields["decision"] = "defer"
                fields["defer_details"] = {
                    "reason": "pending_dependency",
                    "resolution_method": "human_approval",
                    "resolution_timeout_ms": ask_timeout_seconds * 1000,
                    "timeout_decision": "deny",
                }
                fields["reason_codes"] = reason_codes + ["approver_unavailable"]
            else:
                fields["decision"] = "deny"
                fields["reason_codes"] = reason_codes + ["approver_unavailable"]
                fields["reasoning"] += " (approval required, but this agent cannot route an ASK)"
            substitution = {"intended": "ask", "substituted": fields["decision"], "rule": decision.rule}
        else:
            fields["ask_details"] = {
                "approver": approver,
                "question": f"Allow the agent to call '{tool}'? {decision.reason}",
                "context": f"Tool-gate rule '{decision.rule}' requires approval",
                "options": ["approve", "reject"],
                "timeout_seconds": ask_timeout_seconds,
                "timeout_disposition": "deny",
            }
    return fields, substitution
