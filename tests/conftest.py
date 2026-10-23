# SPDX-License-Identifier: Apache-2.0
import base64
import json
import os
import secrets
import uuid
from pathlib import Path

import pytest

from acs_guardian_toolgate import Guardian, GuardianConfig
from acs_guardian_toolgate.client import client_hello, envelope

ROOT = Path(__file__).resolve().parent.parent
POLICY = str(ROOT / "policies" / "default.yaml")
KEY_ID = "test-2026-10"


@pytest.fixture
def secret_b64():
    return base64.b64encode(secrets.token_bytes(32)).decode()


@pytest.fixture
def keys_file(tmp_path, secret_b64):
    p = tmp_path / "keys.yaml"
    p.write_text(f"{KEY_ID}: {secret_b64}\n")
    return str(p)


@pytest.fixture
def make_guardian(tmp_path, keys_file):
    def _make(**overrides):
        cfg = GuardianConfig.load(None, **{"policy_path": POLICY, "keys_file": keys_file,
                                           "audit_log": str(tmp_path / "audit.jsonl"), **overrides})
        return Guardian(cfg)
    return _make


@pytest.fixture
def guardian(make_guardian):
    return make_guardian()


class Session:
    """Drives one ACS session against an in-process Guardian."""

    def __init__(self, g, agent_id="test-agent", sign=True):
        self.g, self.agent_id, self.sign = g, agent_id, sign
        self.sid = str(uuid.uuid4())

    def env(self, method, payload, sign=None, **kw):
        e = envelope(method, payload, session_id=self.sid, agent_id=self.agent_id, **kw)
        if (self.sign if sign is None else sign) and self.g.config.keyring:
            e = self.g.config.keyring.sign_request(e, KEY_ID)
        return e

    def send(self, e):
        return json.loads(self.g.handle_bytes(json.dumps(e).encode(), "http"))

    def call(self, method, payload, **kw):
        return self.send(self.env(method, payload, **kw))

    def hello(self, **kw):
        r = self.call("handshake/hello", client_hello(**kw))
        return r


@pytest.fixture
def session(guardian):
    s = Session(guardian)
    assert "result" in s.hello()
    return s


@pytest.fixture
def new_session():
    return Session
