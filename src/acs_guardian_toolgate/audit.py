# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""Bounded, rotating JSONL audit log.

Every decision, every substitution (§6.5, §9.2), every unresolved
``request_id_ref`` and every chain entry is written here. When the live
file reaches ``max_bytes`` it is renamed to ``<path>.<UTC timestamp>`` in
``archive_dir`` (default: beside it) and a fresh file is started, so the live
file stays bounded and a full log never blocks a decision. Rotated files are
never deleted by the Guardian: the audit events §6.4/§6.5/§9.2 require and
the §8 chain are never dropped. Shipping archives to object storage or a
telemetry backend, and their retention, is the operator's job. If a write fails (disk full, permissions), ``write`` returns False
and the Guardian answers ``deny`` for content-bearing steps rather than lose
an audit record. Secrets and derived keys never reach this log.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | os.PathLike | None, max_bytes: int = 50 * 1024 * 1024,
                 archive_dir: str | os.PathLike | None = None):
        self.path = Path(path) if path else None
        self.max_bytes = max_bytes
        self.archive_dir = Path(archive_dir) if archive_dir else (self.path.parent if self.path else None)
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.archive_dir.mkdir(parents=True, exist_ok=True)

    def _rotate(self) -> None:
        assert self.path is not None and self.archive_dir is not None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        os.replace(self.path, self.archive_dir / f"{self.path.name}.{stamp}")

    def write(self, event: str, **fields) -> bool:
        if self.path is None:
            return True
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
        line = json.dumps(record, ensure_ascii=False, default=str, sort_keys=True) + "\n"
        try:
            with self._lock:
                if self.path.exists() and self.path.stat().st_size + len(line) > self.max_bytes:
                    self._rotate()
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
            return True
        except OSError:
            return False
