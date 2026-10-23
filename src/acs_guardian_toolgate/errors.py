# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""JSON-RPC / ACS error codes (Spec §17, §17.1)."""

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

SESSION_REFUSED = -32000
UNSUPPORTED_VERSION = -32001
PROVENANCE_REQUIRED = -32002
CAPABILITY_NOT_NEGOTIATED = -32003
SIGNATURE_INVALID = -32004
REPLAY_DETECTED = -32005
TIMESTAMP_OUT_OF_WINDOW = -32006
CHAIN_MISMATCH = -32007

# Implementation codes from the unused part of the ACS band, chosen to match the
# TypeScript reference Guardian so the shared harness reads the same answer.
METHOD_NOT_DISPATCHED = -32011

NAMES = {
    SESSION_REFUSED: "SESSION_REFUSED",
    UNSUPPORTED_VERSION: "UNSUPPORTED_VERSION",
    PROVENANCE_REQUIRED: "PROVENANCE_REQUIRED",
    CAPABILITY_NOT_NEGOTIATED: "CAPABILITY_NOT_NEGOTIATED",
    SIGNATURE_INVALID: "SIGNATURE_INVALID",
    REPLAY_DETECTED: "REPLAY_DETECTED",
    TIMESTAMP_OUT_OF_WINDOW: "TIMESTAMP_OUT_OF_WINDOW",
    CHAIN_MISMATCH: "CHAIN_MISMATCH",
    METHOD_NOT_DISPATCHED: "method_not_dispatched",
}


class AcsError(Exception):
    def __init__(self, code: int, message: str, **data):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = {"reason": NAMES.get(code, "error"), "message": message, **data}
