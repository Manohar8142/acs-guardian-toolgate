# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rayavarapu Manohar
"""``acs-guardian-toolgate`` command line."""

from __future__ import annotations

import argparse
import base64
import secrets
import sys

from acs_guardian_toolgate.config import GuardianConfig, load_keyring


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="acs-guardian-toolgate", description="ACS v0.1.0 Guardian backed by Tool-gate")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="serve the ACS Guardian")
    s.add_argument("--config", help="YAML config file")
    s.add_argument("--policy", dest="policy_path", help="Tool-gate policy YAML")
    s.add_argument("--keys-file", dest="keys_file", help="YAML/JSON: key_id -> base64 secret")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--stdio", action="store_true", help="serve Content-Length framed JSON-RPC on stdin/stdout")
    s.add_argument("--audit-log", dest="audit_log")
    s.add_argument("--on-decision-failure", dest="on_decision_failure", choices=["proceed", "deny"])
    s.add_argument("--insecure-no-signatures", action="store_true",
                   help="lab only: do not require ACS-Core HMAC signatures")

    k = sub.add_parser("keygen", help="print a fresh 32-byte base64 secret for a key_id")
    k.add_argument("key_id")

    c = sub.add_parser("conformance", help="run the black-box ACS-Core wire suite against a live Guardian")
    c.add_argument("--url", required=True)
    c.add_argument("--keys-file", required=True)
    c.add_argument("--key-id", required=True)

    a = ap.parse_args(argv)
    if a.cmd == "keygen":
        print(f"{a.key_id}: {base64.b64encode(secrets.token_bytes(32)).decode()}")
        return 0
    if a.cmd == "conformance":
        from acs_guardian_toolgate import wire_suite

        results = wire_suite.run(a.url, load_keyring(a.keys_file), a.key_id)
        print(wire_suite.render(results))
        return 0 if all(r.passed for r in results) else 1

    from acs_guardian_toolgate.guardian import Guardian
    from acs_guardian_toolgate.transport import make_http_server, serve_stdio

    overrides = {k: getattr(a, k) for k in ("policy_path", "keys_file", "host", "port", "audit_log", "on_decision_failure")}
    if a.insecure_no_signatures:
        overrides["require_signatures"] = False
    cfg = GuardianConfig.load(a.config, **overrides)
    guardian = Guardian(cfg)
    if a.stdio:
        print("acs-guardian-toolgate: serving stdio", file=sys.stderr)
        serve_stdio(guardian)
        return 0
    server = make_http_server(guardian)
    h, p = server.server_address[:2]
    print(f"acs-guardian-toolgate listening at http://{h}:{p}{cfg.path}", file=sys.stderr)
    print(f"policy: {cfg.policy_path} (version {guardian.policy.policy_version})  "
          f"failure posture: {cfg.on_decision_failure}  keys: {sorted(cfg.keyring.secrets)}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
