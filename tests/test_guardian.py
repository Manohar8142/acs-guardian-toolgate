# SPDX-License-Identifier: Apache-2.0
import json
import threading
import time
import uuid

import pytest

from acs_guardian_toolgate import DISPATCHED_STEPS, Guardian, GuardianConfig
from acs_guardian_toolgate.chain import verify_chain
from acs_guardian_toolgate.client import client_hello, tool_call, tool_result
from acs_guardian_toolgate import validation

from conftest import POLICY, Session


def test_requires_keys_unless_explicitly_insecure(tmp_path):
    with pytest.raises(ValueError, match="no HMAC keys"):
        Guardian(GuardianConfig.load(None, policy_path=POLICY, audit_log=None))
    Guardian(GuardianConfig.load(None, policy_path=POLICY, audit_log=None, require_signatures=False))


def test_server_hello(guardian, new_session):
    s = new_session(guardian)
    r = s.hello(methods=["steps/toolCallRequest", "steps/sessionStart"], profiles=["acs-core", "acs-audit", "acs-trace"])
    sh = r["result"]
    assert validation.errors("handshake.json#/$defs/ServerHello", sh) == []
    assert sh["methods_evaluated"] == ["steps/toolCallRequest"]
    assert sh["profiles_accepted"] == ["acs-core", "acs-audit"]
    assert sh["on_decision_failure"] == "deny" and sh["signature_algorithms_supported"] == ["HMAC-SHA256"]
    assert "signature" not in sh  # ServerHello has no signature slot in v0.1.0


def test_provenance_required_refuses_none_producer(make_guardian, new_session):
    g = make_guardian(policy_requires_provenance=True)
    r = new_session(g).hello(producer="none")
    assert r["error"]["code"] == -32002


def test_provenance_profile_switches_to_strict_schema(guardian, new_session):
    s = new_session(guardian)
    sh = s.hello(producer="deterministic", profiles=["acs-core", "acs-provenance"])["result"]
    assert "acs-provenance" in sh["profiles_accepted"]
    r = s.call("steps/toolCallRequest", tool_call("weather.get", city="x"))  # no provenance on the argument
    assert r["result"]["decision"] == "deny" and r["result"]["reason_codes"] == ["envelope_invalid"]


def test_transport_refusal(guardian, new_session):
    r = new_session(guardian).hello(transports=["stdio"])
    assert r["error"]["code"] == -32000


def test_allow_response_is_signed_chained_and_valid(guardian, session):
    r = session.call("steps/toolCallRequest", tool_call("weather.get", city="Hyderabad"))
    res = r["result"]
    assert res["decision"] == "allow" and len(res["chain_hash"]) == 64
    assert guardian.config.keyring.verify_response(r, session.sid)
    assert res["signature"]["key_id"] == "test-2026-10"
    assert validation.response_errors(r) == [] and guardian.response_schema_failures == []


def test_deny_and_result_for_denied_call(session):
    req = session.env("steps/toolCallRequest", tool_call("db.query", sql="DROP TABLE users;"))
    r = session.send(req)
    assert r["result"]["decision"] == "deny"
    assert r["result"]["policy_references"][0]["rule_id"] == "block-destructive-sql"
    res = session.call("steps/toolCallResult", tool_result("db.query", req["params"]["request_id"]))
    assert res["result"]["decision"] == "deny" and res["result"]["reason_codes"] == ["result_for_denied_request"]
    blocked = session.call("steps/toolCallResult", tool_result("db.query", req["params"]["request_id"], exit_status="blocked"))
    assert blocked["result"]["decision"] == "allow"


def test_taint_then_sink_asks(session):
    assert session.call("steps/toolCallRequest", tool_call("web.fetch", url="https://evil.example"))["result"]["decision"] == "allow"
    r = session.call("steps/toolCallRequest", tool_call("email.send", to="x@y.z"))["result"]
    assert r["decision"] == "ask" and "untrusted_into_consequential" in r["reason_codes"]
    assert r["policy_data"]["toolgate"]["taint_source"] == "web.fetch"


def test_taint_from_result_only_host(guardian, new_session):
    s = new_session(guardian)
    s.hello()
    s.call("steps/toolCallResult", tool_result("web.fetch", None))
    assert s.call("steps/toolCallRequest", tool_call("http.post", url="u"))["result"]["decision"] == "ask"


def test_rate_limit_rule(session):
    decisions = [session.call("steps/toolCallRequest", tool_call("db.query", sql=f"select {i}"))["result"]["decision"]
                 for i in range(7)]
    assert decisions[:5] == ["allow"] * 5 and decisions[5] == "ask"


def test_raw_command_reaches_args_regex(session):
    p = {"tool": {"name": "shell.exec"}, "arguments": {}, "raw_command": "cat ~/.aws/credentials"}
    assert session.call("steps/toolCallRequest", p)["result"]["decision"] == "deny"


def test_ask_incapable_agent_gets_substitution(make_guardian, tmp_path):
    g = make_guardian(ask_incapable_agents=["ide-*"])
    s = Session(g, agent_id="ide-plugin")
    s.hello()
    r = s.call("steps/toolCallRequest", tool_call("deploy.prod"))["result"]
    assert r["decision"] == "deny" and "approver_unavailable" in r["reason_codes"]
    events = [json.loads(l)["event"] for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert "ask_substituted" in events


def test_unresolved_ref_recorded(session, tmp_path):
    ref = str(uuid.uuid4())
    r = session.call("steps/toolCallResult", tool_result("weather.get", ref))["result"]
    assert r["decision"] == "allow" and "request_id_ref_unresolved" in r["reason_codes"]
    lines = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any("request_id_ref_unresolved" in (l.get("findings") or []) for l in lines)


def test_unresolved_ref_deny_option(make_guardian):
    g = make_guardian(deny_unresolved_result_refs=True)
    s = Session(g); s.hello()
    assert s.call("steps/toolCallResult", tool_result("x", str(uuid.uuid4())))["result"]["decision"] == "deny"


def test_no_handshake_is_denied(guardian, new_session):
    r = new_session(guardian).call("steps/toolCallRequest", tool_call("weather.get"))["result"]
    assert r["decision"] == "deny" and r["reason_codes"] == ["capability_not_negotiated"]


def test_signature_errors(guardian, session):
    assert session.call("steps/toolCallRequest", tool_call("x"), sign=False)["error"]["code"] == -32004
    e = session.env("steps/toolCallRequest", tool_call("x", a=1))
    e["params"]["payload"]["arguments"]["a"]["value"] = 2
    assert session.send(e)["error"]["code"] == -32004


def test_replay_and_skew(session):
    e = session.env("steps/toolCallRequest", tool_call("x"))
    assert "result" in session.send(e)
    assert session.send(e)["error"]["code"] == -32005
    r = session.call("steps/toolCallRequest", tool_call("x"), timestamp="2020-01-01T00:00:00Z")
    assert r["error"]["code"] == -32006 and r["error"]["data"]["skew_window_ms"] == 300000


def test_ping_is_exempt(guardian, new_session):
    s = new_session(guardian)
    r = s.call("system/ping", {"echo": "e"}, sign=False)["result"]
    assert r["decision"] == "allow" and r["payload"]["echo"] == "e" and "chain_hash" not in r
    assert guardian.storage.get(s.sid) is None  # no session state, no chain entry


def test_dispatch_boundaries(guardian, new_session):
    s = new_session(guardian)
    assert s.call("steps/sessionStart", {}, sign=False)["error"]["code"] == -32011
    assert s.call("steps/doesNotExist", {}, sign=False)["error"]["code"] == -32011
    assert s.call("protocols/MCP/tools/call", {}, sign=False)["error"]["code"] == -32011
    assert DISPATCHED_STEPS == ["steps/toolCallRequest", "steps/toolCallResult"]


def test_invalid_envelopes(guardian):
    assert json.loads(guardian.handle_bytes(b"{nope"))["error"]["code"] == -32700
    assert json.loads(guardian.handle_bytes(b"[]"))["error"]["code"] == -32600
    assert json.loads(guardian.handle_bytes(b'{"jsonrpc":"2.0","method":"steps/toolCallRequest"}'))["error"]["code"] == -32600
    rid = str(uuid.uuid4())
    body = {"jsonrpc": "2.0", "id": rid, "method": "steps/toolCallResult",
            "params": {"acs_version": "0.1.0", "request_id": rid, "timestamp": "x", "payload": {}}}
    r = json.loads(guardian.handle_bytes(json.dumps(body).encode()))
    assert r["result"]["decision"] == "deny" and r["result"]["request_id"] == rid


def test_unsupported_version_on_step(session):
    e = session.env("steps/toolCallRequest", tool_call("x"), sign=False)
    e["params"]["acs_version"] = "1.0.0"
    e = session.g.config.keyring.sign_request(e, "test-2026-10")
    assert session.send(e)["error"]["code"] == -32001


def test_batch(session):
    a = session.env("steps/toolCallRequest", tool_call("x"))
    b = session.env("steps/toolCallRequest", tool_call("db.query", sql="drop table t"))
    out = json.loads(session.g.handle_bytes(json.dumps([a, b]).encode()))
    assert [o["result"]["decision"] for o in out] == ["allow", "deny"]


def test_chain_mismatch(session):
    r1 = session.call("steps/toolCallRequest", tool_call("x"))["result"]
    e = session.env("steps/toolCallRequest", tool_call("x"), sign=False)
    e["params"]["metadata"]["session_state"] = {"chain_hash": r1["chain_hash"]}
    ok = session.send(session.g.config.keyring.sign_request(e, "test-2026-10"))["result"]
    assert ok["decision"] == "allow"
    e = session.env("steps/toolCallRequest", tool_call("x"), sign=False)
    e["params"]["metadata"]["session_state"] = {"chain_hash": r1["chain_hash"]}  # stale head
    bad = session.send(session.g.config.keyring.sign_request(e, "test-2026-10"))["result"]
    assert bad["decision"] == "deny" and bad["reason_codes"] == ["chain_mismatch"]


def test_published_heads_match_chain(guardian, session):
    heads = [session.call("steps/toolCallRequest", tool_call("x", i=i))["result"]["chain_hash"] for i in range(4)]
    entries = guardian.storage.get(session.sid).chain.entries
    assert [e["entry_hash"] for e in entries] == heads and verify_chain(entries)


def test_audit_failure_denies(make_guardian, tmp_path):
    g = make_guardian()
    s = Session(g); s.hello()
    g.audit.write = lambda *a, **k: False
    r = s.call("steps/toolCallRequest", tool_call("weather.get"))["result"]
    assert r["decision"] == "deny" and r["reason_codes"] == ["audit_unavailable"]


def test_evaluation_time_limit_denies(make_guardian):
    g = make_guardian(evaluation_time_limit_ms=1)
    s = Session(g); s.hello()
    real = g.engine.check
    g.engine.check = lambda *a: (time.sleep(0.02), real(*a))[1]
    r = s.call("steps/toolCallRequest", tool_call("weather.get"))["result"]
    assert r["decision"] == "deny" and r["reason_codes"] == ["evaluation_time_limit_exceeded"]


def test_overload_denies(make_guardian):
    g = make_guardian(max_concurrent_requests=1)
    s = Session(g); s.hello()
    g._slots.acquire()
    try:
        r = s.call("steps/toolCallRequest", tool_call("weather.get"))["result"]
    finally:
        g._slots.release()
    assert r["decision"] == "deny" and r["reason_codes"] == ["guardian_overloaded"]


def test_internal_error_is_still_a_deny(make_guardian):
    g = make_guardian()
    s = Session(g); s.hello()
    def boom(*a):
        raise RuntimeError("x")
    g.engine.check = boom
    r = s.call("steps/toolCallRequest", tool_call("weather.get"))["result"]
    assert r["decision"] == "deny" and r["reason_codes"] == ["evaluation_failed"]


def test_concurrent_requests_one_session(guardian, session):
    envs = [session.env("steps/toolCallRequest", tool_call("weather.get", i=i)) for i in range(40)]
    envs += envs[:10]  # 10 replays raced against their originals
    out = [None] * len(envs)

    def run(i):
        out[i] = session.send(envs[i])

    threads = [threading.Thread(target=run, args=(i,)) for i in range(len(envs))]
    [t.start() for t in threads]
    [t.join() for t in threads]
    ok = [o for o in out if "result" in o]
    replays = [o for o in out if o.get("error", {}).get("code") == -32005]
    assert len(ok) == 40 and len(replays) == 10
    entries = guardian.storage.get(session.sid).chain.entries
    assert len(entries) == 40 and verify_chain(entries)
    assert len({e["step_id"] for e in entries}) == 40


def test_audit_log_rotates_without_dropping(make_guardian, tmp_path):
    g = make_guardian(audit_log_max_bytes=2000, audit_log_archive_dir=str(tmp_path / "archive"))
    s = Session(g); s.hello()
    for i in range(30):
        s.call("steps/toolCallRequest", tool_call("weather.get", i=i))
    live = (tmp_path / "audit.jsonl").read_text().splitlines()
    archived = [l for f in (tmp_path / "archive").iterdir() for l in f.read_text().splitlines()]
    decisions = [json.loads(l) for l in live + archived if json.loads(l)["event"] == "decision"]
    assert (tmp_path / "audit.jsonl").stat().st_size <= 2000
    assert len(decisions) == 30  # nothing dropped
