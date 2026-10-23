# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""The transport-independent ACS Guardian processor backed by Tool-gate.

``Guardian.handle_bytes(body, transport)`` takes one raw JSON-RPC message (or
batch) and returns the raw response. HTTP and stdio transports are thin
wrappers around it. Processing order for one request:

1. parse -> JSON-RPC shape -> ``request-envelope.json`` + hook payload schema
   (a schema-invalid ``steps/*`` envelope is an honoured ``deny``, never an error)
2. dispatch (``method_not_dispatched`` for methods this Guardian does not evaluate)
3. ``system/ping`` short-circuits: always ``allow``, unsigned, no chain entry
4. under the session lock: signature (§10) -> timestamp skew and replay (§10.3)
5. ``handshake/hello`` -> ServerHello, or ``steps/*`` -> Tool-gate evaluation
6. ContextEntry appended, ``chain_hash`` published, response signed with the
   request's ``key_id``, response checked against ``response-envelope.json``
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from fnmatch import fnmatch
from hashlib import sha256
from pathlib import Path

from toolgate import Engine, Policy, ToolCall

from acs_guardian_toolgate import errors as E
from acs_guardian_toolgate import validation
from acs_guardian_toolgate.audit import AuditLog
from acs_guardian_toolgate.config import GuardianConfig
from acs_guardian_toolgate.crypto import SignatureError, jcs, sha256_hex
from acs_guardian_toolgate.mapping import PolicyIdentity, decision_fields
from acs_guardian_toolgate.storage import STORAGE_PROVIDERS, Negotiated, SessionState

__all__ = ["Guardian", "DISPATCHED_STEPS", "SUPPORTED_VERSIONS"]

SUPPORTED_VERSIONS = ["0.1.0"]
DISPATCHED_STEPS = ["steps/toolCallRequest", "steps/toolCallResult"]
CONTROL_METHODS = ["handshake/hello", "system/ping"]
GUARDIAN_PROFILES = ["acs-core", "acs-audit", "acs-provenance"]

try:
    from importlib.metadata import version as _pkg_version

    _VERSION = _pkg_version("acs-guardian-toolgate")
except Exception:  # pragma: no cover - running from a source tree
    _VERSION = "0.1.0"
try:
    from importlib.metadata import version as _v

    _TOOLGATE_VERSION = _v("toolgate")
except Exception:  # pragma: no cover
    _TOOLGATE_VERSION = "unknown"

EVALUATOR_VERSION = f"acs-guardian-toolgate/{_VERSION} toolgate/{_TOOLGATE_VERSION}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _is_uuid(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _parse_ts(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _version_ok(v: str) -> bool:
    parts = v.split(".")
    return len(parts) == 3 and parts[0] == "0" and parts[1] == "1"


class Guardian:
    def __init__(self, config: GuardianConfig, *, engine: Engine | None = None, storage=None):
        self.config = config
        policy_bytes = Path(config.policy_path).read_bytes() if engine is None else b""
        self.engine = engine or Engine(Policy.from_yaml(config.policy_path))
        self.policy = PolicyIdentity(
            policy_id=config.policy_id,
            policy_version=sha256(policy_bytes).hexdigest()[:16] if policy_bytes else "embedded",
            policy_name=Path(config.policy_path).name if engine is None else "embedded",
        )
        self.storage = storage or STORAGE_PROVIDERS[config.storage](max_sessions=config.max_sessions)
        self.audit = AuditLog(config.audit_log, config.audit_log_max_bytes, config.audit_log_archive_dir)
        self._slots = threading.BoundedSemaphore(config.max_concurrent_requests)
        self.response_schema_failures: list[list[str]] = []
        if config.require_signatures and not config.keyring:
            raise ValueError(
                "require_signatures is on (ACS-Core §10) but no HMAC keys are configured; set keys_file or "
                "ACS_HMAC_KEYS, or explicitly set require_signatures: false for a lab run"
            )

    # ------------------------------------------------------------------ entry points
    def handle_bytes(self, body: bytes, transport: str = "http") -> bytes | None:
        try:
            message = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._dump(self._error(None, E.PARSE_ERROR, "Parse error"))
        if isinstance(message, list):
            if not message or not self.config.batching:
                return self._dump(self._error(None, E.INVALID_REQUEST, "Invalid Request: empty or unsupported batch"))
            # §3: each request in a batch is evaluated independently, in declared order.
            return self._dump([self.handle_message(m, transport) for m in message])
        return self._dump(self.handle_message(message, transport))

    def handle_message(self, message, transport: str = "http") -> dict:
        if not self._slots.acquire(blocking=False):
            return self._overloaded(message)
        try:
            return self._handle(message, transport)
        except Exception as exc:  # nothing escapes: an unhandled error must still be a decision
            print(f"acs-guardian: internal error: {type(exc).__name__}", file=sys.stderr)
            if isinstance(message, dict) and str(message.get("method", "")).startswith("steps/"):
                deny = self._deny_unaddressed(message, "evaluation_failed", "the Guardian failed while evaluating this step")
                if deny is not None:
                    return deny
            mid = message.get("id") if isinstance(message, dict) else None
            return self._error(mid, E.INTERNAL_ERROR, "Internal error")
        finally:
            self._slots.release()

    # ------------------------------------------------------------------ core
    def _handle(self, msg, transport: str) -> dict:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            mid = msg.get("id") if isinstance(msg, dict) and isinstance(msg.get("id"), (str, int, float)) else None
            return self._error(mid, E.INVALID_REQUEST, "Invalid Request")
        method = msg["method"]
        mid = msg.get("id")
        if not isinstance(mid, (str, int, float)) or isinstance(mid, bool):
            return self._error(None, E.INVALID_REQUEST, "Invalid Request: id is required")

        if method == "system/ping":
            return self._ping(msg)

        session_for_profile = None
        params = msg.get("params")
        if isinstance(params, dict) and isinstance(params.get("metadata"), dict):
            sid = params["metadata"].get("session_id")
            if isinstance(sid, str):
                session_for_profile = self.storage.get(sid)
        provenance_profile = bool(
            session_for_profile
            and session_for_profile.negotiated
            and "acs-provenance" in session_for_profile.negotiated.profiles_accepted
        )
        errs = validation.request_errors(
            msg, provenance_profile=provenance_profile, payload_methods=DISPATCHED_STEPS + ["handshake/hello"]
        )
        if errs:
            if method.startswith("steps/"):
                return self._deny_unaddressed(
                    msg, "envelope_invalid", "request failed ACS v0.1.0 schema validation: " + "; ".join(errs[:5])
                ) or self._error(None, E.INVALID_REQUEST, "Invalid Request")
            return self._error(mid, E.INVALID_PARAMS, "Invalid params", errors=errs[:20])

        if method != "handshake/hello" and method not in DISPATCHED_STEPS:
            return self._error(
                mid, E.METHOD_NOT_DISPATCHED, f"method {method!r} is not dispatched by this Guardian",
                methods_evaluated=DISPATCHED_STEPS,
            )

        params = msg["params"]
        if not _version_ok(params["acs_version"]):
            return self._error(mid, E.UNSUPPORTED_VERSION, "unsupported acs_version", supported_versions=SUPPORTED_VERSIONS)

        session = self.storage.get_or_create(params["metadata"]["session_id"])
        with session.lock:
            # §10 signature, then §10.3 freshness and replay
            key_id = None
            if self.config.require_signatures or "signature" in params:
                try:
                    key_id = self.config.keyring.verify_request(msg)
                except SignatureError as exc:
                    self.audit.write("signature_invalid", session_id=session.session_id, request_id=params["request_id"],
                                     method=method, detail=str(exc))
                    return self._error(mid, E.SIGNATURE_INVALID, f"SIGNATURE_INVALID: {exc}")
            ts = _parse_ts(params["timestamp"])
            skew = abs((_now() - ts).total_seconds() * 1000) if ts else float("inf")
            if skew > self.config.skew_window_ms:
                return self._error(mid, E.TIMESTAMP_OUT_OF_WINDOW, "timestamp outside the skew window",
                                   skew_window_ms=self.config.skew_window_ms)
            rid = params["request_id"]
            if rid in session.seen_request_ids:
                self.audit.write("replay_rejected", session_id=session.session_id, request_id=rid, method=method)
                return self._error(mid, E.REPLAY_DETECTED, "duplicate request_id in this session")
            nonce = params.get("nonce")
            if nonce is not None and nonce in session.seen_nonces:
                return self._error(mid, E.REPLAY_DETECTED, "duplicate nonce in this session")
            session.seen_request_ids.add(rid)
            if nonce is not None:
                session.seen_nonces[nonce] = time.time()
                while len(session.seen_nonces) > self.config.nonce_window:
                    session.seen_nonces.popitem(last=False)

            if method == "handshake/hello":
                return self._handshake(msg, session, transport)
            return self._step(msg, session, key_id)

    # ------------------------------------------------------------------ handshake
    def _handshake(self, msg: dict, session: SessionState, transport: str) -> dict:
        mid, params = msg["id"], msg["params"]
        hello = params["payload"]
        offered = [v for v in hello["acs_versions_supported"] if _version_ok(v)]
        if not offered:
            return self._error(mid, E.UNSUPPORTED_VERSION, "no common acs_version", supported_versions=SUPPORTED_VERSIONS)
        if hello["provenance_producer"] == "none" and self.config.policy_requires_provenance:
            return self._error(mid, E.PROVENANCE_REQUIRED, "this Guardian's policy requires provenance")
        transports = hello["transports_supported"]
        if transport == "stdio":
            selected = "stdio" if "stdio" in transports else None
        else:
            selected = "http" if "http" in transports else ("https" if "https" in transports else None)
        if selected is None:
            return self._error(mid, E.SESSION_REFUSED, f"client does not support this Guardian's transport ({transport})")
        client_profiles = hello.get("profiles_supported") or ["acs-core"]
        profiles = [p for p in GUARDIAN_PROFILES if p in client_profiles]
        if "acs-provenance" in profiles and hello["provenance_producer"] != "deterministic":
            profiles.remove("acs-provenance")
        if "acs-core" not in profiles:
            profiles.insert(0, "acs-core")
        methods = [m for m in DISPATCHED_STEPS if m in hello["methods_implemented"]]
        session.negotiated = Negotiated(
            version=SUPPORTED_VERSIONS[0], methods_evaluated=methods, profiles_accepted=profiles,
            transport=selected, agent_id=params["metadata"]["agent_id"],
        )
        timeout = {"default_ms": self.config.default_timeout_ms}
        if self.config.per_method_timeout_ms:
            timeout["per_method_ms"] = dict(self.config.per_method_timeout_ms)
        server_hello = {
            "negotiated_version": SUPPORTED_VERSIONS[0],
            "methods_evaluated": methods,
            "selected_transport": selected,
            "signature_algorithms_supported": ["HMAC-SHA256"] if self.config.keyring else [],
            "timeout_config": timeout,
            "skew_window_ms": self.config.skew_window_ms,
            "on_decision_failure": self.config.on_decision_failure,
            "approver_types_supported": [self.config.approver_type],
            "policy_requires_provenance": self.config.policy_requires_provenance,
            "trace_emission": {"otel_enabled": False, "ocsf_enabled": False},
            "profiles_accepted": profiles,
        }
        self.audit.write("handshake", session_id=session.session_id, agent_id=params["metadata"]["agent_id"],
                         server_hello=server_hello)
        return self._checked({"jsonrpc": "2.0", "id": mid, "result": server_hello})

    # ------------------------------------------------------------------ steps
    def _step(self, msg: dict, session: SessionState, key_id: str | None) -> dict:
        params, method = msg["params"], msg["method"]
        started = time.perf_counter()
        neg = session.negotiated
        substitution = None
        findings: list[str] = []

        client_head = (params["metadata"].get("session_state") or {}).get("chain_hash")
        if neg is None and self.config.require_handshake:
            fields = self._guardian_deny("capability_not_negotiated",
                                         "no handshake/hello for this session; ACS §4 requires it before hook traffic")
        elif neg is not None and method not in neg.methods_evaluated:
            return self._error(msg["id"], E.CAPABILITY_NOT_NEGOTIATED,
                               f"{method} was not negotiated for this session", method=method)
        elif client_head is not None and client_head != session.chain.head:
            fields = self._guardian_deny("chain_mismatch", "submitted chain_hash does not match the Guardian's chain head")
        elif method == "steps/toolCallRequest":
            fields, substitution = self._tool_call_request(params, session)
        else:
            fields, findings = self._tool_call_result(params, session)

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        limit = min(self.config.evaluation_time_limit_ms,
                    int(self.config.per_method_timeout_ms.get(method, self.config.default_timeout_ms)))
        if elapsed_ms > limit:
            fields = self._guardian_deny("evaluation_time_limit_exceeded",
                                         f"evaluation took {elapsed_ms} ms, above the {limit} ms limit")

        entry = session.chain.append(
            step_id=params["request_id"], step_type=method,
            request_hash=sha256_hex(jcs(params)), timestamp=_iso(_now()),
        )
        ok = self.audit.write(
            "decision", session_id=session.session_id, request_id=params["request_id"], method=method,
            agent_id=params["metadata"]["agent_id"], decision=fields["decision"],
            reason_codes=fields.get("reason_codes"), rule=(fields.get("policy_data") or {}).get("toolgate", {}).get("rule"),
            findings=findings, context_entry=entry,
        )
        if substitution:
            ok = self.audit.write("ask_substituted", session_id=session.session_id, request_id=params["request_id"],
                                  **substitution) and ok
        if not ok:
            # Bounded logging: never lose an audit record; deny instead.
            fields = self._guardian_deny("audit_unavailable", "the audit log could not be written")

        result = {
            "type": "final",
            "acs_version": SUPPORTED_VERSIONS[0],
            "request_id": params["request_id"],
            **fields,
            "chain_hash": entry["entry_hash"],
            "metadata": {
                "evaluator": "deterministic",
                "evaluator_version": EVALUATOR_VERSION,
                "evaluation_duration_ms": elapsed_ms,
            },
        }
        response = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
        if key_id is not None:
            self.config.keyring.sign_response(response, key_id, params["metadata"]["session_id"])
        return self._checked(response)

    def _tool_call_request(self, params: dict, session: SessionState) -> tuple[dict, dict | None]:
        payload = params["payload"]
        tool = payload["tool"]["name"]
        args = {k: (v.get("value") if isinstance(v, dict) else v) for k, v in payload["arguments"].items()}
        if payload.get("raw_command") and "raw_command" not in args:
            args["raw_command"] = payload["raw_command"]
        call = ToolCall(tool=tool, args=args, agent_id=params["metadata"]["agent_id"])
        decision = self.engine.check(call, session.toolgate)
        agent_id = params["metadata"]["agent_id"]
        approver = {"type": self.config.approver_type, "id": self.config.approver_id}
        if self.config.approver_endpoint:
            approver["endpoint"] = self.config.approver_endpoint
        fields, substitution = decision_fields(
            decision, tool=tool, policy=self.policy,
            session_tainted=session.toolgate.tainted, taint_source=session.toolgate.taint_source,
            approver=approver, ask_timeout_seconds=self.config.ask_timeout_seconds,
            ask_incapable=any(fnmatch(agent_id, p) for p in self.config.ask_incapable_agents),
            ask_incapable_substitute=self.config.ask_incapable_substitute,
        )
        # Tool-gate's own adapter convention: a call that may run (allow / ask) enters
        # history, and a taint source taints the session; a denied call never ran.
        if fields["decision"] != "deny":
            self.engine.record(call, session.toolgate)
        session.tool_requests[params["request_id"]] = {"tool": tool, "decision": fields["decision"]}
        return fields, substitution

    def _tool_call_result(self, params: dict, session: SessionState) -> tuple[dict, list[str]]:
        payload = params["payload"]
        tool = payload["tool"]["name"]
        ref = payload.get("request_id_ref")
        origin = session.tool_requests.get(ref) if ref else None
        findings: list[str] = []
        if any(fnmatch(tool, p) for p in self.engine.policy.taint_sources) and payload["exit_status"] == "success":
            session.toolgate.mark_tainted(tool)
        base_ref = {"policy_id": self.policy.policy_id, "policy_version": self.policy.policy_version,
                    "policy_name": self.policy.policy_name}
        data = {"toolgate": {"tool": tool, "session_tainted": session.toolgate.tainted,
                             "taint_source": session.toolgate.taint_source,
                             "request_id_ref": ref, "request_id_ref_resolved": origin is not None}}
        if ref and origin is None:
            findings.append("request_id_ref_unresolved")  # hooks.md: MUST be recorded
            if self.config.deny_unresolved_result_refs:
                return ({"decision": "deny", "reasoning": "toolgate: result references no toolCallRequest in this session",
                         "reason_codes": ["request_id_ref_unresolved"], "policy_references": [base_ref],
                         "policy_data": data}, findings)
        if origin and origin["decision"] == "deny" and payload["exit_status"] != "blocked":
            return ({"decision": "deny",
                     "reasoning": f"toolgate: '{tool}' was denied at toolCallRequest but a result arrived; "
                                  "the denied call's output must not reach the agent",
                     "reason_codes": ["result_for_denied_request"], "policy_references": [base_ref],
                     "policy_data": data}, findings)
        codes = ["toolgate_no_result_rules"] + findings
        return ({"decision": "allow",
                 "reasoning": "toolgate: result recorded; Tool-gate evaluates calls before execution and defines no result-gate rules",
                 "reason_codes": codes, "policy_references": [base_ref], "policy_data": data}, findings)

    # ------------------------------------------------------------------ helpers
    def _guardian_deny(self, code: str, reasoning: str) -> dict:
        return {"decision": "deny", "reasoning": reasoning, "reason_codes": [code], "policy_references": []}

    def _ping(self, msg: dict) -> dict:
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        payload = params.get("payload") if isinstance(params.get("payload"), dict) else {}
        rid = params.get("request_id") if _is_uuid(params.get("request_id")) else str(uuid.uuid4())
        out = {"status": "ok", "server_timestamp": _iso(_now())}
        if isinstance(payload.get("echo"), str):
            out["echo"] = payload["echo"][:256]
        return self._checked({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "type": "final", "acs_version": SUPPORTED_VERSIONS[0], "request_id": rid,
            "decision": "allow", "payload": out}})

    def _deny_unaddressed(self, msg, code: str, reasoning: str) -> dict | None:
        """An honoured deny for a steps/* message we could not process normally (unsigned: no usable session key)."""
        if not isinstance(msg, dict):
            return None
        mid = msg.get("id")
        if not isinstance(mid, (str, int, float)) or isinstance(mid, bool):
            return None
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        rid = params.get("request_id")
        if not _is_uuid(rid):
            rid = mid if _is_uuid(mid) else str(uuid.uuid4())
        self.audit.write("deny_unaddressed", reason_code=code, request_id=rid, method=msg.get("method"))
        return self._checked({"jsonrpc": "2.0", "id": mid, "result": {
            "type": "final", "acs_version": SUPPORTED_VERSIONS[0], "request_id": rid,
            **self._guardian_deny(code, reasoning)}})

    def _overloaded(self, msg) -> dict:
        if isinstance(msg, dict) and str(msg.get("method", "")).startswith("steps/"):
            deny = self._deny_unaddressed(msg, "guardian_overloaded", "concurrent request limit reached")
            if deny is not None:
                return deny
        mid = msg.get("id") if isinstance(msg, dict) else None
        return self._error(mid, E.INTERNAL_ERROR, "Guardian overloaded")

    def _error(self, mid, code: int, message: str, **data) -> dict:
        err = {"code": code, "message": message, "data": {"reason": E.NAMES.get(code, "error"), "message": message, **data}}
        return self._checked({"jsonrpc": "2.0", "id": mid if isinstance(mid, (str, int, float)) else None, "error": err})

    def _checked(self, response: dict) -> dict:
        errs = validation.response_errors(response)
        if errs:
            self.response_schema_failures.append(errs)
            print("acs-guardian: outgoing response failed response-envelope.json: " + "; ".join(errs[:3]), file=sys.stderr)
        return response

    @staticmethod
    def _dump(obj) -> bytes:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
