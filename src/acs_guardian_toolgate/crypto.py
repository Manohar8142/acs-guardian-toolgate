# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""ACS-Core baseline integrity: HMAC-SHA256 over the JCS-canonical envelope (Spec §10).

* Per-session key = HKDF-SHA256(secret named by ``key_id``, salt = none,
  info = UTF-8 bytes of ``metadata.session_id`` exactly as sent, L = 32).
* Signed input  = RFC 8785 (JCS) canonicalisation of the envelope with the
  ``signature`` member removed (``params.signature`` on a request,
  ``result.signature`` on a response), UTF-8 encoded.
* ``value``     = standard base64 of the 32-byte HMAC tag.

Secrets are configured as ``key_id -> base64 secret`` (RFC 4648 §4, padding,
surrounding whitespace ignored), at least 32 decoded bytes, read from a file or
an environment variable and never logged.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
from dataclasses import dataclass, field

import rfc8785

ALGORITHM = "HMAC-SHA256"
MIN_SECRET_BYTES = 32


def jcs(obj) -> bytes:
    """RFC 8785 canonical bytes."""
    return rfc8785.dumps(obj)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def session_key(secret: bytes, session_id: str) -> bytes:
    return hkdf_sha256(secret, session_id.encode("utf-8"), 32)


def decode_secret(text: str) -> bytes:
    try:
        raw = base64.b64decode("".join(text.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("secret is not valid standard base64") from exc
    if len(raw) < MIN_SECRET_BYTES:
        raise ValueError(f"secret decodes to {len(raw)} bytes; ACS §10 requires at least {MIN_SECRET_BYTES}")
    return raw


class SignatureError(Exception):
    """Missing, malformed, unknown-key, or non-verifying signature."""


@dataclass
class KeyRing:
    """key_id -> secret. Holds any number of secrets at once for zero-outage rotation."""

    secrets: dict[str, bytes] = field(default_factory=dict)

    def __repr__(self) -> str:  # never print secret material
        return f"KeyRing(key_ids={sorted(self.secrets)})"

    def __bool__(self) -> bool:
        return bool(self.secrets)

    def add(self, key_id: str, secret_b64: str) -> None:
        if not key_id:
            raise ValueError("key_id must be a non-empty label")
        self.secrets[key_id] = decode_secret(secret_b64)

    # -- requests ---------------------------------------------------------
    def verify_request(self, envelope: dict) -> str:
        """Verify ``params.signature``; return the key_id used. Raises SignatureError."""
        params = envelope.get("params") or {}
        sig = params.get("signature")
        if not isinstance(sig, dict):
            raise SignatureError("signature missing")
        if sig.get("algorithm") != ALGORITHM:
            raise SignatureError(f"unsupported signature algorithm {sig.get('algorithm')!r}")
        key_id = sig.get("key_id")
        secret = self.secrets.get(key_id) if isinstance(key_id, str) else None
        if secret is None:
            # §10: reject an unknown key_id; never fall back to another secret.
            raise SignatureError("unknown key_id")
        session_id = (params.get("metadata") or {}).get("session_id", "")
        expected = sign_bytes(session_key(secret, session_id), _request_signing_input(envelope))
        try:
            given = base64.b64decode(sig.get("value", ""), validate=True)
        except (binascii.Error, ValueError):
            raise SignatureError("signature value is not base64") from None
        if not hmac.compare_digest(given, expected):
            raise SignatureError("signature does not verify over the canonical envelope")
        return key_id

    def sign_request(self, envelope: dict, key_id: str) -> dict:
        env = copy.deepcopy(envelope)
        env["params"].pop("signature", None)
        sid = env["params"]["metadata"]["session_id"]
        tag = sign_bytes(session_key(self.secrets[key_id], sid), jcs(env))
        env["params"]["signature"] = {"algorithm": ALGORITHM, "value": base64.b64encode(tag).decode(), "key_id": key_id}
        return env

    # -- responses --------------------------------------------------------
    def sign_response(self, response: dict, key_id: str, session_id: str) -> dict:
        """Sign ``result`` in place with the key of the request it answers."""
        response["result"].pop("signature", None)
        tag = sign_bytes(session_key(self.secrets[key_id], session_id), jcs(response))
        response["result"]["signature"] = {
            "algorithm": ALGORITHM,
            "value": base64.b64encode(tag).decode(),
            "key_id": key_id,
        }
        return response

    def verify_response(self, response: dict, session_id: str) -> bool:
        sig = (response.get("result") or {}).get("signature")
        if not isinstance(sig, dict) or sig.get("key_id") not in self.secrets:
            return False
        env = copy.deepcopy(response)
        env["result"].pop("signature", None)
        expected = sign_bytes(session_key(self.secrets[sig["key_id"]], session_id), jcs(env))
        try:
            return hmac.compare_digest(base64.b64decode(sig["value"]), expected)
        except (binascii.Error, ValueError):
            return False


def _request_signing_input(envelope: dict) -> bytes:
    env = copy.deepcopy(envelope)
    env["params"].pop("signature", None)
    return jcs(env)


def sign_bytes(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()
