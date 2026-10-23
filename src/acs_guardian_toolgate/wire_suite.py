# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""Black-box ACS-Core wire checks against a live Guardian over HTTP.

ACS v0.1.0 ships no language-independent contract suite yet (issue #311), so
this module drives the ACS-Core requirements in ``docs/spec/conformance.md``
over the wire, one check per requirement, and prints PASS/FAIL per check. It
needs the shared HMAC secret because ACS-Core requests are signed.

Policy-dependent probes assume Tool-gate's ``policies/default.yaml``.
"""

from __future__ import annotations

import copy
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from acs_guardian_toolgate import validation
from acs_guardian_toolgate.client import AcsClient, client_hello, tool_call, tool_result
from acs_guardian_toolgate.crypto import KeyRing, hkdf_sha256

HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class Check:
    id: str
    spec: str
    title: str
    passed: bool = False
    detail: str = ""


def run(url: str, keyring: KeyRing, key_id: str) -> list[Check]:
    results: list[Check] = []
    all_responses: list = []

    def mk(**kw) -> AcsClient:
        return AcsClient(url, keyring, key_id, **kw)

    def post(c: AcsClient, body):
        r = c.post_raw(body)
        all_responses.extend(r if isinstance(r, list) else [r])
        return r

    def call(c, method, payload, **kw):
        return post(c, c.build(method, payload, **kw))

    def check(cid, spec, title):
        def deco(fn):
            ch = Check(cid, spec, title)
            try:
                out = fn()
                ch.passed = out is True or (isinstance(out, tuple) and out[0])
                ch.detail = "" if out is True else (out[1] if isinstance(out, tuple) else repr(out))
            except Exception as exc:  # a failing probe is a FAIL, not a crash
                ch.passed, ch.detail = False, f"{type(exc).__name__}: {exc}"
            results.append(ch)
            return fn
        return deco

    def ready() -> AcsClient:
        c = mk()
        r = call(c, "handshake/hello", client_hello())
        assert "result" in r, r
        return c

    @check("HS-1", "§4", "handshake/hello returns a schema-valid ServerHello")
    def _():
        c = mk()
        r = call(c, "handshake/hello", client_hello())
        sh = r.get("result", {})
        errs = validation.errors("handshake.json#/$defs/ServerHello", sh)
        ok = (not errs and sh.get("negotiated_version") == "0.1.0"
              and set(sh.get("methods_evaluated", [])) <= set(client_hello()["methods_implemented"])
              and sh.get("on_decision_failure") in ("proceed", "deny") and "acs-core" in sh.get("profiles_accepted", []))
        return ok, json.dumps(sh)[:300]

    @check("HS-2", "§4, §17.1", "no common version -> UNSUPPORTED_VERSION (-32001) with supported_versions")
    def _():
        c = mk()
        hello = client_hello()
        hello["acs_versions_supported"] = ["9.0.0"]
        r = call(c, "handshake/hello", hello)
        e = r.get("error", {})
        return e.get("code") == -32001 and "supported_versions" in e.get("data", {}), json.dumps(r)[:200]

    @check("HS-3", "§4", "ClientHello missing required fields is rejected (no ServerHello)")
    def _():
        c = mk()
        r = call(c, "handshake/hello", {"acs_versions_supported": ["0.1.0"]})
        return "error" in r and "result" not in r, json.dumps(r)[:200]

    @check("HS-4", "§4", "hook traffic before handshake is not allowed through")
    def _():
        c = mk()
        r = call(c, "steps/toolCallRequest", tool_call("weather.get", city="x"))
        res = r.get("result", {})
        return res.get("decision") == "deny" or r.get("error", {}).get("code") == -32003, json.dumps(r)[:200]

    @check("HS-5", "§17.1", "method not negotiated -> CAPABILITY_NOT_NEGOTIATED (-32003)")
    def _():
        c = mk()
        call(c, "handshake/hello", client_hello(methods=["steps/toolCallRequest"]))
        r = call(c, "steps/toolCallResult", tool_result("weather.get", None))
        return r.get("error", {}).get("code") == -32003, json.dumps(r)[:200]

    @check("DISP-ALLOW", "§6, §6.1", "allow decision, schema-valid, with chain_hash and signature")
    def _():
        c = ready()
        r = call(c, "steps/toolCallRequest", tool_call("weather.get", city="Hyderabad"))
        res = r.get("result", {})
        ok = (res.get("decision") == "allow" and HEX64.match(res.get("chain_hash", "")) is not None
              and keyring.verify_response(r, c.session_id) and not validation.response_errors(r))
        return ok, json.dumps(res)[:300]

    @check("DISP-DENY", "§6", "deny decision carries reasoning (Tool-gate deny)")
    def _():
        c = ready()
        r = call(c, "steps/toolCallRequest", tool_call("db.query", sql="DROP TABLE users;"))
        res = r.get("result", {})
        return res.get("decision") == "deny" and bool(res.get("reasoning")), json.dumps(res)[:300]

    @check("DISP-ASK", "§6, §9", "ask decision carries reasoning + schema-valid ask_details (Tool-gate require_approval)")
    def _():
        c = ready()
        r = call(c, "steps/toolCallRequest", tool_call("deploy.prod", service="api"))
        res = r.get("result", {})
        ok = (res.get("decision") == "ask" and bool(res.get("reasoning"))
              and not validation.errors("ask-details.json", res.get("ask_details")))
        return ok, json.dumps(res)[:300]

    @check("DISP-TAINT", "§6.1", "taint flow: web.fetch then email.send -> ask, reason_codes name it")
    def _():
        c = ready()
        call(c, "steps/toolCallRequest", tool_call("web.fetch", url="https://example.com"))
        r = call(c, "steps/toolCallRequest", tool_call("email.send", to="a@b.c", body="hi"))
        res = r.get("result", {})
        return res.get("decision") == "ask" and "untrusted_into_consequential" in res.get("reason_codes", []), \
            json.dumps(res)[:300]

    @check("RES-1", "hooks.md toolCallResult", "unresolvable request_id_ref is recorded (reason code) and decided")
    def _():
        c = ready()
        r = call(c, "steps/toolCallResult", tool_result("weather.get", str(uuid.uuid4())))
        res = r.get("result", {})
        return res.get("decision") in ("allow", "deny") and "request_id_ref_unresolved" in res.get("reason_codes", []), \
            json.dumps(res)[:300]

    @check("RES-2", "§6.4", "result for a denied request is denied")
    def _():
        c = ready()
        req = c.build("steps/toolCallRequest", tool_call("db.query", sql="DROP TABLE x;"))
        post(c, req)
        r = call(c, "steps/toolCallResult", tool_result("db.query", req["params"]["request_id"]))
        return r.get("result", {}).get("decision") == "deny", json.dumps(r)[:300]

    @check("SIG-1", "§10", "unsigned hook request -> SIGNATURE_INVALID (-32004)")
    def _():
        c = ready()
        r = call(c, "steps/toolCallRequest", tool_call("weather.get"), sign=False)
        return r.get("error", {}).get("code") == -32004, json.dumps(r)[:200]

    @check("SIG-2", "§10 key_id", "unknown key_id -> SIGNATURE_INVALID, no fallback")
    def _():
        c = ready()
        other = KeyRing()
        other.add("not-configured", __import__("base64").b64encode(bytes(range(32))).decode())
        env = other.sign_request(c.build("steps/toolCallRequest", tool_call("weather.get"), sign=False), "not-configured")
        r = post(c, env)
        return r.get("error", {}).get("code") == -32004, json.dumps(r)[:200]

    @check("SIG-3", "§10 signed input", "tampered envelope (payload changed after signing) -> SIGNATURE_INVALID")
    def _():
        c = ready()
        env = c.build("steps/toolCallRequest", tool_call("weather.get", city="a"))
        env["params"]["payload"]["arguments"]["city"]["value"] = "b"
        r = post(c, env)
        return r.get("error", {}).get("code") == -32004, json.dumps(r)[:200]

    @check("SIG-4", "§10", "re-wrapping a signature under another session_id -> SIGNATURE_INVALID")
    def _():
        c = ready()
        env = c.build("steps/toolCallRequest", tool_call("weather.get"))
        c2 = ready()
        env2 = copy.deepcopy(env)
        env2["params"]["metadata"]["session_id"] = c2.session_id
        r = post(c2, env2)
        return r.get("error", {}).get("code") == -32004, json.dumps(r)[:200]

    @check("SIG-5", "§10 HKDF", "HKDF known-answer vector from §10 reproduces")
    def _():
        key = hkdf_sha256(bytes(range(32)), b"6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36")
        return key.hex() == "80f0dc8c611279bfc2af2d5f374c5cb685888192ce1af5c3e0673d8fa748e8a4"

    @check("RP-1", "§10.3", "duplicate request_id in a session -> REPLAY_DETECTED (-32005)")
    def _():
        c = ready()
        env = c.build("steps/toolCallRequest", tool_call("weather.get"))
        post(c, env)
        r = post(c, env)
        return r.get("error", {}).get("code") == -32005, json.dumps(r)[:200]

    @check("RP-2", "§10.3", "duplicate nonce -> REPLAY_DETECTED")
    def _():
        c = ready()
        post(c, c.build("steps/toolCallRequest", tool_call("weather.get"), nonce="n" * 24))
        r = post(c, c.build("steps/toolCallRequest", tool_call("weather.get"), nonce="n" * 24))
        return r.get("error", {}).get("code") == -32005, json.dumps(r)[:200]

    @check("RP-3", "§10.3", "timestamp outside skew window -> TIMESTAMP_OUT_OF_WINDOW (-32006) with skew_window_ms")
    def _():
        c = ready()
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        r = post(c, c.build("steps/toolCallRequest", tool_call("weather.get"), timestamp=old))
        e = r.get("error", {})
        return e.get("code") == -32006 and "skew_window_ms" in e.get("data", {}), json.dumps(r)[:200]

    @check("CH-1", "§8.6", "chain head published on every content-bearing step and advances")
    def _():
        c = ready()
        heads = [call(c, "steps/toolCallRequest", tool_call("weather.get", i=i))["result"].get("chain_hash") for i in range(3)]
        return all(h and HEX64.match(h) for h in heads) and len(set(heads)) == 3, str(heads)

    @check("CH-2", "§8.6", "submitted chain_hash that disagrees with the head -> deny chain_mismatch")
    def _():
        c = ready()
        call(c, "steps/toolCallRequest", tool_call("weather.get"))
        env = c.build("steps/toolCallRequest", tool_call("weather.get"), sign=False)
        env["params"]["metadata"]["session_state"] = {"chain_hash": "0" * 64}
        r = post(c, keyring.sign_request(env, key_id))
        res = r.get("result", {})
        return res.get("decision") == "deny" and "chain_mismatch" in res.get("reason_codes", []), json.dumps(res)[:200]

    @check("FC-1", "§6.4 / refimpl README", "schema-invalid steps/* envelope (no metadata) -> honoured deny")
    def _():
        c = mk()
        rid = str(uuid.uuid4())
        body = {"jsonrpc": "2.0", "id": rid, "method": "steps/toolCallRequest",
                "params": {"acs_version": "0.1.0", "request_id": rid, "timestamp": "2026-01-01T00:00:00Z", "payload": {}}}
        r = post(c, body)
        return r.get("result", {}).get("decision") == "deny", json.dumps(r)[:200]

    @check("FC-2", "§6.4", "invalid toolCallRequest payload -> honoured deny")
    def _():
        c = ready()
        r = call(c, "steps/toolCallRequest", {})
        return r.get("result", {}).get("decision") == "deny", json.dumps(r)[:200]

    @check("PING-1", "§13", "system/ping unsigned -> allow, payload status/echo/server_timestamp, no chain_hash")
    def _():
        c = mk()
        r = call(c, "system/ping", {"echo": "hello"}, sign=False)
        res = r.get("result", {})
        p = res.get("payload", {})
        return (res.get("decision") == "allow" and p.get("status") == "ok" and p.get("echo") == "hello"
                and "server_timestamp" in p and "chain_hash" not in res), json.dumps(res)[:200]

    @check("RPC-1", "§3", "batch of two -> two correlated responses in order")
    def _():
        c = ready()
        a = c.build("steps/toolCallRequest", tool_call("weather.get"))
        b = c.build("system/ping", {}, sign=False)
        r = post(c, [a, b])
        return isinstance(r, list) and [x.get("id") for x in r] == [a["id"], b["id"]], json.dumps(r)[:200]

    @check("RPC-2", "§3, §17", "empty batch -> -32600; unparseable body -> -32700 with id null")
    def _():
        c = mk()
        r1 = post(c, b"[]")
        r2 = post(c, b"{not json")
        return r1.get("error", {}).get("code") == -32600 and r2.get("error", {}).get("code") == -32700 \
            and r2.get("id") is None, json.dumps([r1, r2])[:200]

    @check("RPC-3", "§17", "unknown method -> JSON-RPC error, never a decision")
    def _():
        c = mk()
        r = call(c, "steps/doesNotExist", {}, sign=False)
        return "error" in r and "result" not in r, json.dumps(r)[:200]

    @check("SCHEMA-ALL", "§3", "every response received in this run validates against response-envelope.json")
    def _():
        bad = [(i, validation.response_errors(r)) for i, r in enumerate(all_responses) if validation.response_errors(r)]
        return not bad, f"{len(all_responses)} responses checked; failures: {bad[:3]}"

    return results


def render(results: list[Check]) -> str:
    lines = [f"{'PASS' if c.passed else 'FAIL'}  {c.id:<11} {c.spec:<24} {c.title}" +
             ("" if c.passed else f"\n      -> {c.detail}") for c in results]
    passed = sum(c.passed for c in results)
    lines.append(f"\n{passed} passed, {len(results) - passed} failed, {len(results)} total")
    return "\n".join(lines)
