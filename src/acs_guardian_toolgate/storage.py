# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""Session and security state behind a storage-provider interface.

The Guardian only reaches state through ``StorageProvider``. The shipped
provider is in-memory: state lives for the life of the process, is lost on
restart, and is NOT shared between Guardian instances (run one instance per
set of Observed Agents, or implement a shared provider). Each session carries
its own lock, so concurrent requests in one session are serialised and replay
checks, chain appends and Tool-gate history updates are never lost or doubled.
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field

from toolgate import Session

from acs_guardian_toolgate.chain import SessionChain


@dataclass
class Negotiated:
    version: str
    methods_evaluated: list[str]
    profiles_accepted: list[str]
    transport: str
    agent_id: str


@dataclass
class SessionState:
    session_id: str
    toolgate: Session
    chain: SessionChain
    lock: threading.RLock = field(default_factory=threading.RLock)
    seen_request_ids: set[str] = field(default_factory=set)
    seen_nonces: "OrderedDict[str, float]" = field(default_factory=OrderedDict)
    negotiated: Negotiated | None = None
    # request_id of each toolCallRequest -> {"tool": name, "decision": acs decision}
    tool_requests: dict[str, dict] = field(default_factory=dict)
    last_seen: float = field(default_factory=time.time)


class StorageProvider(ABC):
    @abstractmethod
    def get_or_create(self, session_id: str) -> SessionState: ...

    @abstractmethod
    def get(self, session_id: str) -> SessionState | None: ...

    @abstractmethod
    def drop(self, session_id: str) -> None: ...


class InMemoryStorage(StorageProvider):
    """Process-local, non-durable, single-instance. Bounded by ``max_sessions`` (LRU eviction)."""

    def __init__(self, max_sessions: int = 10_000, window_seconds: float = 300.0):
        self._sessions: "OrderedDict[str, SessionState]" = OrderedDict()
        self._lock = threading.Lock()
        self.max_sessions = max_sessions
        self.window_seconds = window_seconds

    def get_or_create(self, session_id: str) -> SessionState:
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                state = SessionState(
                    session_id=session_id,
                    toolgate=Session(session_id, window_seconds=self.window_seconds),
                    chain=SessionChain(session_id),
                )
                self._sessions[session_id] = state
                while len(self._sessions) > self.max_sessions:
                    self._sessions.popitem(last=False)
            else:
                self._sessions.move_to_end(session_id)
            state.last_seen = time.time()
            return state

    def get(self, session_id: str) -> SessionState | None:
        with self._lock:
            return self._sessions.get(session_id)

    def drop(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)


STORAGE_PROVIDERS = {"memory": InMemoryStorage}
