#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs (1) the ACS reference harness's live-wire leg and (2) this package's
# black-box ACS-Core wire suite against a freshly started Python Guardian.
#
#   ACS_REPO=/path/to/agent-control-standard ./conformance/run-acs-harness.sh
#
# Needs: bun 1.3.11 (`bun install --frozen-lockfile` already run in
# $ACS_REPO/reference-implementations/agt), this package installed.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
: "${ACS_REPO:?set ACS_REPO to a clone of GenAI-Security-Project/agent-control-standard}"
PORT="${PORT:-8799}"
OUT="$HERE/results"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'kill "${GPID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

acs-guardian-toolgate keygen harness > "$WORK/keys.yaml"
acs-guardian-toolgate serve --policy "$ROOT/policies/default.yaml" --keys-file "$WORK/keys.yaml" \
  --port "$PORT" --audit-log "$WORK/audit.jsonl" 2> "$WORK/guardian.log" &
GPID=$!
for _ in $(seq 1 50); do curl -s --noproxy '*' "http://127.0.0.1:$PORT/healthz" >/dev/null && break; sleep 0.1; done

export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
set +e
( cd "$ACS_REPO/reference-implementations/agt" && \
  GUARDIAN_URL="http://127.0.0.1:$PORT/acs" bun run "$HERE/acs-harness-wire-leg.ts" ) | tee "$OUT/acs-harness-wire-leg.txt"
H=${PIPESTATUS[0]}
acs-guardian-toolgate conformance --url "http://127.0.0.1:$PORT/acs" --keys-file "$WORK/keys.yaml" \
  --key-id harness | tee "$OUT/acs-core-wire-suite.txt"
W=${PIPESTATUS[0]}
set -e
{
  echo "acs commit: $(git -C "$ACS_REPO" rev-parse HEAD)"
  echo "toolgate:   $(python -c 'import importlib.metadata as m; print(m.version("toolgate"))')"
  echo "bun:        $(bun --version)"
  echo "date:       $(python -c "import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'))")"
  echo "harness wire leg exit: $H"
  echo "ACS-Core wire suite exit: $W"
} | tee "$OUT/run-info.txt"
exit $(( H || W ))
