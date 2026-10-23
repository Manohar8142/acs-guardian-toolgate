# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""Guardian configuration: a YAML file, overridable by ``ACS_*`` environment variables."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml

from acs_guardian_toolgate.crypto import KeyRing


@dataclass
class GuardianConfig:
    # Tool-gate
    policy_path: str = "policies/default.yaml"
    policy_id: str = "toolgate"           # policy_references[].policy_id
    # Transport
    host: str = "127.0.0.1"
    port: int = 8787
    path: str = "/acs"
    # Handshake (ServerHello)
    on_decision_failure: str = "deny"     # "proceed" | "deny"; ServerHello declares it
    skew_window_ms: int = 300_000
    default_timeout_ms: int = 2_000
    per_method_timeout_ms: dict = field(default_factory=dict)
    policy_requires_provenance: bool = False
    require_handshake: bool = True        # steps/* before handshake/hello -> deny
    # Signatures (ACS-Core §10)
    require_signatures: bool = True
    keys_file: str | None = None          # YAML/JSON mapping key_id -> base64 secret
    # ASK (Tool-gate require_approval)
    approver_type: str = "human"
    approver_id: str = "operator"
    approver_endpoint: str | None = None
    ask_timeout_seconds: int = 300
    # §9.2: agent_ids whose host cannot route ASK -> substitute
    ask_incapable_agents: list = field(default_factory=list)
    ask_incapable_substitute: str = "deny"   # "deny" (approver_unavailable) | "defer"
    # toolCallResult
    deny_unresolved_result_refs: bool = False
    # Bounds (time / body / concurrency / sessions / logs)
    max_body_bytes: int = 1024 * 1024
    max_concurrent_requests: int = 64
    evaluation_time_limit_ms: int = 1_000   # MUST stay below default_timeout_ms
    max_sessions: int = 10_000
    nonce_window: int = 10_000
    storage: str = "memory"
    audit_log: str | None = ".acs/audit.jsonl"
    audit_log_max_bytes: int = 50 * 1024 * 1024
    audit_log_archive_dir: str | None = None   # rotated files go here; never deleted
    batching: bool = True

    keyring: KeyRing = field(default_factory=KeyRing, repr=False)

    def __post_init__(self) -> None:
        if self.on_decision_failure not in ("proceed", "deny"):
            raise ValueError("on_decision_failure must be 'proceed' or 'deny'")
        if self.ask_incapable_substitute not in ("deny", "defer"):
            raise ValueError("ask_incapable_substitute must be 'deny' or 'defer'")
        if self.evaluation_time_limit_ms >= self.default_timeout_ms:
            raise ValueError("evaluation_time_limit_ms must be below default_timeout_ms (README expectation)")

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: str | None = None, **overrides) -> "GuardianConfig":
        data: dict = {}
        if path:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        names = {f.name: f for f in fields(cls) if f.name != "keyring"}
        for name, f in names.items():
            env = os.environ.get("ACS_" + name.upper())
            if env is None:
                continue
            kind = f.type if isinstance(f.type, str) else getattr(f.type, "__name__", "")
            if kind == "bool":
                data[name] = env.lower() in ("1", "true", "yes")
            elif kind == "int":
                data[name] = int(env)
            elif kind in ("list", "dict"):
                data[name] = json.loads(env)
            else:
                data[name] = env
        data.update({k: v for k, v in overrides.items() if v is not None})
        unknown = set(data) - set(names)
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        cfg = cls(**data)
        cfg.keyring = load_keyring(cfg.keys_file)
        return cfg


def load_keyring(keys_file: str | None) -> KeyRing:
    """Keys come from ``keys_file`` and/or ``ACS_HMAC_KEYS`` (JSON object key_id -> base64).

    No key_id has a built-in default; at least two may be configured at once for rotation.
    """
    ring = KeyRing()
    sources: list[dict] = []
    if keys_file:
        sources.append(yaml.safe_load(Path(keys_file).read_text(encoding="utf-8")) or {})
    env = os.environ.get("ACS_HMAC_KEYS")
    if env:
        sources.append(json.loads(env))
    for src in sources:
        for key_id, secret in src.items():
            ring.add(str(key_id), str(secret))
    return ring
