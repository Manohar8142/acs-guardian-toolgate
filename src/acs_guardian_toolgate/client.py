# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""A minimal Observed-Agent-side client: builds, signs and sends ACS envelopes.

Used by the tests, the black-box wire suite, and as a worked example for
anyone wiring a host to this Guardian.
"""

from __future__ import annotations

import json
import urllib.request
import uuid
from datetime import datetime, timezone

from acs_guardian_toolgate.crypto import KeyRing


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def envelope(method: str, payload: dict, *, session_id: str, agent_id: str = "demo-agent",
             request_id: str | None = None, timestamp: str | None = None, **extra_params) -> dict:
    rid = request_id or str(uuid.uuid4())
    params = {
        "acs_version": "0.1.0",
        "request_id": rid,
        "timestamp": timestamp or now_iso(),
        "metadata": {"agent_id": agent_id, "session_id": session_id},
        "payload": payload,
    }
    params.update(extra_params)
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def client_hello(methods=None, transports=("http",), producer="none", profiles=("acs-core",)) -> dict:
    return {
        "acs_versions_supported": ["0.1.0"],
        "methods_implemented": list(methods or ["steps/toolCallRequest", "steps/toolCallResult", "system/ping"]),
        "transports_supported": list(transports),
        "provenance_producer": producer,
        "profiles_supported": list(profiles),
    }


def tool_call(name: str, **args) -> dict:
    return {"tool": {"name": name}, "arguments": {k: {"value": v} for k, v in args.items()}}


def tool_result(name: str, request_id_ref: str | None, outputs=("ok",), exit_status="success") -> dict:
    p = {"tool": {"name": name}, "exit_status": exit_status, "outputs": [{"value": o} for o in outputs]}
    if request_id_ref:
        p["request_id_ref"] = request_id_ref
    return p


class AcsClient:
    def __init__(self, url: str, keyring: KeyRing | None = None, key_id: str | None = None,
                 agent_id: str = "demo-agent", session_id: str | None = None):
        self.url, self.keyring, self.key_id, self.agent_id = url, keyring, key_id, agent_id
        self.session_id = session_id or str(uuid.uuid4())

    def build(self, method: str, payload: dict, sign: bool = True, **kw) -> dict:
        env = envelope(method, payload, session_id=self.session_id, agent_id=self.agent_id, **kw)
        if sign and self.keyring and self.key_id:
            env = self.keyring.sign_request(env, self.key_id)
        return env

    def post_raw(self, body) -> dict | list:
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never route loopback via a proxy
        with opener.open(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def call(self, method: str, payload: dict, sign: bool = True, **kw) -> dict:
        return self.post_raw(self.build(method, payload, sign=sign, **kw))

    def hello(self, **kw) -> dict:
        return self.call("handshake/hello", client_hello(**kw))
