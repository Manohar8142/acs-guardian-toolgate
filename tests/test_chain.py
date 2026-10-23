# SPDX-License-Identifier: Apache-2.0
import hashlib
import json

from acs_guardian_toolgate import validation
from acs_guardian_toolgate.chain import SessionChain, compute_entry_hash, verify_chain


def test_first_entry_hash_matches_spec_rule():
    c = SessionChain("s")
    e = c.append(step_id="r1", step_type="steps/toolCallRequest", request_hash="a" * 64, timestamp="2026-10-23T00:00:00Z")
    content = {k: v for k, v in e.items() if k not in ("entry_hash", "previous_hash")}
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    assert e["previous_hash"] is None
    assert e["entry_hash"] == hashlib.sha256(canonical).hexdigest()


def test_chain_links_raw_previous_bytes_and_validates():
    c = SessionChain("s")
    e1 = c.append(step_id="r1", step_type="m", request_hash="a" * 64, timestamp="2026-10-23T00:00:00Z")
    e2 = c.append(step_id="r2", step_type="m", request_hash="b" * 64, timestamp="2026-10-23T00:00:00Z")
    content = {k: v for k, v in e2.items() if k not in ("entry_hash", "previous_hash")}
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    assert e2["entry_hash"] == hashlib.sha256(canonical + bytes.fromhex(e1["entry_hash"])).hexdigest()
    assert verify_chain(c.entries)
    for e in c.entries:
        assert validation.errors("context-entry.json", e) == []


def test_dropping_an_entry_breaks_the_chain():
    c = SessionChain("s")
    for i in range(3):
        c.append(step_id=f"r{i}", step_type="m", request_hash="c" * 64, timestamp="2026-10-23T00:00:00Z")
    assert not verify_chain([c.entries[0], c.entries[2]])
    tampered = [dict(e) for e in c.entries]
    tampered[1]["step_type"] = "steps/other"
    assert compute_entry_hash(tampered[1]) != tampered[1]["entry_hash"]
    assert not verify_chain(tampered)
