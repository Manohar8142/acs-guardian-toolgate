# SPDX-License-Identifier: Apache-2.0
import base64
import json

import pytest

from acs_guardian_toolgate.config import GuardianConfig

from conftest import POLICY


def test_env_overrides_and_env_keys(monkeypatch):
    monkeypatch.setenv("ACS_ON_DECISION_FAILURE", "proceed")
    monkeypatch.setenv("ACS_SKEW_WINDOW_MS", "1000")
    monkeypatch.setenv("ACS_ASK_INCAPABLE_AGENTS", '["ide-*"]')
    monkeypatch.setenv("ACS_HMAC_KEYS", json.dumps({"k1": base64.b64encode(bytes(32)).decode(),
                                                    "k2": base64.b64encode(bytes([1]) * 32).decode()}))
    cfg = GuardianConfig.load(None, policy_path=POLICY)
    assert cfg.on_decision_failure == "proceed" and cfg.skew_window_ms == 1000
    assert cfg.ask_incapable_agents == ["ide-*"] and sorted(cfg.keyring.secrets) == ["k1", "k2"]


def test_rejects_bad_values(tmp_path):
    with pytest.raises(ValueError):
        GuardianConfig(on_decision_failure="maybe")
    with pytest.raises(ValueError):
        GuardianConfig(evaluation_time_limit_ms=5000, default_timeout_ms=2000)
    p = tmp_path / "c.yaml"
    p.write_text("not_a_key: 1\n")
    with pytest.raises(ValueError, match="unknown config keys"):
        GuardianConfig.load(str(p))
    k = tmp_path / "k.yaml"
    k.write_text("short: " + base64.b64encode(b"tiny").decode() + "\n")
    with pytest.raises(ValueError, match="at least 32"):
        GuardianConfig.load(None, keys_file=str(k))
