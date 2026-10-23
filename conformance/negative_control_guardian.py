# SPDX-License-Identifier: Apache-2.0
# Negative control for conformance/acs-harness-wire-leg.ts: a deliberately broken Guardian.
# Run: acs-guardian-toolgate keygen k > keys.yaml && python conformance/negative_control_guardian.py
import time
from acs_guardian_toolgate import Guardian, GuardianConfig, errors
from acs_guardian_toolgate.transport import make_http_server
errors.METHOD_NOT_DISPATCHED = -32601   # deliberately wrong: harness must catch it
g = Guardian(GuardianConfig.load(None, policy_path="policies/default.yaml", keys_file="keys.yaml", audit_log=None, port=8798))
make_http_server(g).serve_forever()
