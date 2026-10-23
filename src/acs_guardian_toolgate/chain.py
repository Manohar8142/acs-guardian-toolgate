# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""SessionContext audit chain (Spec §8.1, §8.2, §8.6).

entry_hash = lowercase-hex(SHA-256(JCS(entry without entry_hash/previous_hash)
                                   || raw 32-byte previous_hash))
The first entry has previous_hash = null and hashes with an empty suffix.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from acs_guardian_toolgate.crypto import jcs


def compute_entry_hash(entry: dict) -> str:
    content = {k: v for k, v in entry.items() if k not in ("entry_hash", "previous_hash")}
    prev = entry.get("previous_hash")
    prev_bytes = bytes.fromhex(prev) if prev else b""
    return hashlib.sha256(jcs(content) + prev_bytes).hexdigest()


def verify_chain(entries: list[dict]) -> bool:
    prev = None
    for e in entries:
        if e.get("previous_hash") != prev:
            return False
        if compute_entry_hash(e) != e["entry_hash"]:
            return False
        prev = e["entry_hash"]
    return True


@dataclass
class SessionChain:
    session_id: str
    entries: list[dict] = field(default_factory=list)

    @property
    def head(self) -> str | None:
        return self.entries[-1]["entry_hash"] if self.entries else None

    def append(self, *, step_id: str, step_type: str, request_hash: str, timestamp: str) -> dict:
        entry = {
            "entry_id": f"{self.session_id}:{len(self.entries) + 1}",
            "step_id": step_id,
            "step_type": step_type,
            "request_hash": request_hash,
            "timestamp": timestamp,
            "previous_hash": self.head,
        }
        entry["entry_hash"] = compute_entry_hash(entry)
        self.entries.append(entry)
        return entry
