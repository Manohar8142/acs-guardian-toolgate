# acs-guardian-toolgate

A Python Guardian for the OWASP [Agent Control Standard (ACS)](https://github.com/GenAI-Security-Project/agent-control-standard) v0.1.0, with [Tool-gate](https://github.com/Manohar8142/Tool-gate) as its policy engine.

It serves the ACS wire contract as JSON-RPC 2.0 over HTTP (`POST /acs`) or over stdio (Content-Length framing). It reads the ClientHello and negotiates the session. It checks every request and every response against the v0.1.0 JSON Schemas. It verifies and signs messages with HMAC-SHA256 under §10's HKDF key derivation, rejects replays, keeps a SHA-256 audit chain for each session, and publishes the chain head on every decision. Tool-gate's `allow`, `deny` and `require_approval` become the ACS decisions `allow`, `deny` and `ask`.

```
Observed Agent ──JSON-RPC 2.0 (signed)──► acs-guardian-toolgate ──► Tool-gate Engine.check(call, session)
               ◄── allow | deny | ask ───        (chain_hash, signature)
```

Status: alpha. The specification is pinned to ACS commit `d1ad2943107601e3c09f8e0c8eaf57b78b38a01b` (schemas `v0.1.0`), and Tool-gate to commit `26f3711`.

## Install

Python 3.11 or later.

```bash
git clone https://github.com/Manohar8142/acs-guardian-toolgate.git
cd acs-guardian-toolgate
pip install -e ".[dev]"     # pulls Tool-gate from GitHub at the pinned commit (it is not on PyPI)
pytest -q                   # 60 tests
```

## Run

```bash
mkdir -p .acs
acs-guardian-toolgate keygen 2026-10 > .acs/keys.yaml          # 32 random bytes, base64, under key_id "2026-10"
acs-guardian-toolgate serve --policy policies/default.yaml --keys-file .acs/keys.yaml
# acs-guardian-toolgate listening at http://127.0.0.1:8787/acs

acs-guardian-toolgate serve --stdio --keys-file .acs/keys.yaml  # stdio transport
acs-guardian-toolgate serve --config examples/guardian.yaml     # every setting from a file
```

The Guardian will not start with signatures required and no key configured. Pass `--insecure-no-signatures` only for a lab run, and know that a Guardian started this way is not ACS-Core conformant.

### Drive it from Python

```python
from acs_guardian_toolgate.client import AcsClient, tool_call
from acs_guardian_toolgate.config import load_keyring

c = AcsClient("http://127.0.0.1:8787/acs", load_keyring(".acs/keys.yaml"), "2026-10")
c.hello()                                                     # handshake/hello -> ServerHello
c.call("steps/toolCallRequest", tool_call("db.query", sql="DROP TABLE users;"))["result"]["decision"]   # 'deny'
c.call("steps/toolCallRequest", tool_call("web.fetch", url="https://example.com"))                       # allow, taints session
c.call("steps/toolCallRequest", tool_call("email.send", to="x@y.z"))["result"]["decision"]              # 'ask'
```

## Methods

| Method | What it does |
|---|---|
| `handshake/hello` | Validates the ClientHello and negotiates the version (0.1.x), the transport, the profiles and the methods. Refuses with `UNSUPPORTED_VERSION`, `PROVENANCE_REQUIRED` or `SESSION_REFUSED` when it has to. Answers with a ServerHello |
| `steps/toolCallRequest` | Evaluates the call with Tool-gate `Engine.check` against the session's history and taint |
| `steps/toolCallResult` | Records the result. Resolves `request_id_ref`, taints the session when the tool is a taint source, and denies output from a call it denied |
| `system/ping` | Always `allow` and never signed. Writes nothing to the chain (§13) |
| anything else | JSON-RPC error `-32011` (`method_not_dispatched`). It is never a decision, and it is left out of `methods_evaluated` |

## Decision mapping

| Tool-gate | ACS `decision` | Fields carried |
|---|---|---|
| `allow` | `allow` | `reasoning`, `reason_codes`, `policy_references`, `policy_data.toolgate`, `chain_hash`, `metadata`, `signature` |
| `deny` | `deny` | the same fields as `allow`. `reasoning` is the Tool-gate rule's `reason` |
| `require_approval` | `ask` | the same fields, plus `ask_details` with `approver {type, id[, endpoint]}`, `question`, `context`, `options`, `timeout_seconds` and `timeout_disposition: deny` |
| `require_approval`, agent cannot route ASK (§9.2) | `deny` (default) or `defer` | `reason_codes` gains `approver_unavailable`, and the substitution is written to the audit log. A `defer` carries `defer_details {reason: pending_dependency, resolution_method: human_approval, timeout_decision: deny}` |
| (no Tool-gate verdict) | never `modify` | Tool-gate has no transform verdict |

How each Tool-gate fact lands in the response:

| Tool-gate | ACS field |
|---|---|
| `Decision.reason` | `reasoning`, prefixed `toolgate: ` |
| `Decision.rule` | `policy_references[0].rule_id`, and `policy_data.toolgate.rule` |
| policy file | `policy_references[0].policy_id` (configurable), `policy_name` (the file name), and `policy_version` (the first 16 hex characters of the SHA-256 of the file) |
| a rule fired, or the default applied | `reason_codes`: `toolgate_rule_fired` or `toolgate_default_applied` |
| the session is tainted and the decision is not `allow` | `reason_codes` gains `untrusted_into_consequential`. `policy_data.toolgate` gives `session_tainted` and `taint_source` |
| evaluator | `metadata.evaluator: deterministic`, plus `evaluator_version` and `evaluation_duration_ms` |

The request becomes a Tool-gate `ToolCall` like this: `tool.name` is the tool name, each `arguments.<k>.value` is an argument, `raw_command` (when present) becomes the argument `raw_command`, and `metadata.agent_id` is the agent. A call that comes back `allow` or `ask` is recorded in the Tool-gate session (history, rate windows, taint). A denied call is not, which is the convention Tool-gate's own Claude Code adapter follows.

Some decisions come from the Guardian itself, not from Tool-gate. Each one is a `deny` with an empty `policy_references` and one of these reason codes:

| Reason code | When |
|---|---|
| `envelope_invalid` | a `steps/*` request fails `request-envelope.json` or its hook payload schema |
| `capability_not_negotiated` | hook traffic arrives before `handshake/hello` |
| `chain_mismatch` | `metadata.session_state.chain_hash` disagrees with the Guardian's chain head |
| `evaluation_time_limit_exceeded`, `guardian_overloaded`, `evaluation_failed`, `audit_unavailable` | a configured bound was hit, or something went wrong inside the Guardian |
| `result_for_denied_request` | a `toolCallResult` arrives for a call this Guardian denied |

## Configuration

Settings come from a YAML file (`--config`) and from `ACS_<KEY>` environment variables. [`examples/guardian.yaml`](examples/guardian.yaml) lists every key with its default. These matter most:

| Key | Default | Meaning |
|---|---|---|
| `policy_path` | `policies/default.yaml` | The Tool-gate policy |
| `keys_file` / `ACS_HMAC_KEYS` | none | `key_id: base64-secret` pairs. Each secret is at least 32 bytes, in standard base64. There is no default `key_id`. Configure several at once to rotate keys |
| `require_signatures` | `true` | ACS-Core §10 |
| `on_decision_failure` | `deny` | The failure posture the ServerHello declares. The spec's default is `proceed`. This Guardian defaults to fail-closed on purpose, as §6.4 permits |
| `skew_window_ms` | `300000` | §10.3 |
| `default_timeout_ms` / `per_method_timeout_ms` | `2000` | `timeout_config` |
| `evaluation_time_limit_ms` | `1000` | Must stay below `default_timeout_ms`. A step that exceeds it is denied |
| `max_body_bytes` / `max_concurrent_requests` / `max_sessions` | 1 MiB / 64 / 10 000 | Bounds on processing |
| `ask_incapable_agents` | `[]` | `agent_id` globs that get the §9.2 substitution |
| `audit_log`, `audit_log_max_bytes`, `audit_log_archive_dir` | `.acs/audit.jsonl`, 50 MiB, beside it | A bounded JSONL audit log. When the live file reaches the cap it is moved into the archive directory, and archives are never deleted. If a write fails, the step is denied |

### Keys and rotation

Each secret is configured under a `key_id`, a label you choose that names one secret. The per-session key is `HKDF-SHA256(secret, salt=none, info=session_id, L=32)`. The signed input is the RFC 8785 (JCS) form of the whole envelope with its `signature` member removed: `params.signature` on a request, `result.signature` on a response. A response is signed with the `key_id` and session key of the request it answers. An unknown `key_id` is rejected with `SIGNATURE_INVALID`, and the Guardian never falls back to another secret. To rotate, add the new secret under a new label such as `2026-11`, move the clients over to it, then remove the old one. Secrets and derived keys never appear in responses, errors or the audit log.

### Storage and concurrency

All state goes through `StorageProvider`. The only provider shipped today is `memory`. It is held in process, is lost on restart, is not shared between instances, and is capped at `max_sessions`, evicting the least recently used session. Each session has its own lock. The signature check, the replay check, the Tool-gate evaluation and the chain append for one request all happen under that lock. `tests/test_guardian.py::test_concurrent_requests_one_session` races 50 requests in one session, 10 of them replays: exactly 40 are decided, 10 come back `REPLAY_DETECTED`, and the chain holds 40 entries that verify.

## Conformance results

ACS v0.1.0 has no language-independent contract suite yet (issue #311). The root README says that a port is done when it passes the `bun run conformance` harness, and that the harness "measures the wire, not the language behind it". Two runs were made against this Guardian, and their output is under [`conformance/results/`](conformance/results/):

1. **The ACS harness's live-wire leg.** [`conformance/acs-harness-wire-leg.ts`](conformance/acs-harness-wire-leg.ts) imports the unchanged `checkDenyFailsClosed` from `reference-implementations/agt/packages/conformance` and points it at this Guardian over HTTP. **Result: PASS.** All 3 invariant probes passed, and the deny column was measured `expressed` at all 6 mapped ACS methods: `steps/sessionStart`, `steps/sessionEnd`, `steps/userMessage`, `steps/agentResponse`, `steps/toolCallRequest` and `steps/toolCallResult`. A negative control, a copy of this Guardian with its dispatch code deliberately broken, makes the same leg **FAIL** ([`negative-control.txt`](conformance/results/negative-control.txt)). The PASS is therefore a real measurement.
   - **Not applicable (4 legs):** intervention-point round trip, verdict round trip, action identity, and the policy-input schema. These legs call the TypeScript Guardian's AGT resolver, its verdict mapping and its AGT bridge in-process. They measure AGT, not the wire. The trace-pillar rows depend only on the schemas, and are printed as they are.
   - For comparison, the full harness run against the TypeScript reference Guardian is in [`ts-reference-guardian-baseline.txt`](conformance/results/ts-reference-guardian-baseline.txt).
2. **The ACS-Core black-box wire suite** (`acs-guardian-toolgate conformance --url ... --keys-file ... --key-id ...`). It makes one or more checks per ACS-Core requirement in `docs/spec/conformance.md`: handshake, dispositions, signatures, replay, chain head, failing closed, ping, batching, errors and response-schema validity. **Result: 28 passed, 0 failed.**

Reproduce both runs:

```bash
git clone https://github.com/GenAI-Security-Project/agent-control-standard /tmp/acs
(cd /tmp/acs/reference-implementations/agt && bun install --frozen-lockfile)   # bun 1.3.11
ACS_REPO=/tmp/acs ./conformance/run-acs-harness.sh
```

## Where this Guardian stands against ACS-Core

`reference-implementations/README.md` asks each Guardian for a table like this one.

| Requirement | Status |
|---|---|
| Handshake (§4) | **Met.** The ClientHello is read and validated, and the version, transport, profiles and methods are negotiated. `PROVENANCE_REQUIRED`, `UNSUPPORTED_VERSION` and `SESSION_REFUSED` are all implemented |
| Envelope (§3) | **Met.** Requests, hook payloads and every outgoing response are validated against the vendored schemas. Batching works as §3 describes |
| Hook taxonomy | **Partial.** Only `toolCallRequest` and `toolCallResult` are evaluated, because Tool-gate governs tool calls. The other minimum-set hooks answer `method_not_dispatched` and are left out of `methods_evaluated`, so §4 has the client treat them as allow-by-default |
| Dispositions | **Partial.** ALLOW, DENY and ASK are emitted. DEFER appears only as the §9.2 substitution, because Tool-gate has no defer verdict. MODIFY is never emitted, and it is only SHOULD-support |
| SessionContext and chain (§8) | **Met.** Each session has a chain, and its head is published on every content-bearing step and covered by the signature. `request_hash` is on every entry, which is why `acs-audit` is accepted. The chain starts implicitly at the first content-bearing hook, because `sessionStart` is not dispatched. The spec allows that but discourages it. Intent is not implemented |
| Replay protection (§10.3) | **Met.** Duplicate `request_id` and `nonce` are rejected, and so is a timestamp outside the skew window |
| Baseline signature (§10) | **Met for HMAC-SHA256.** ACS-Crypto is not claimed |
| Decision honoring (§6.4) | That is the host's job. The Guardian declares `on_decision_failure` and always answers `steps/*` with a decision |
| Liveness (§13) | **Met.** `system/ping` is implemented |
| Wrapped MCP | **Not met.** `protocols/MCP/*` is not dispatched. Tool-gate's own MCP proxy is a separate path, not ACS wrapping |
| Reference-implementation rule: "policy evaluation with the AGT runtime" | **Not met, by design.** This Guardian uses Tool-gate, not AGT. Under the current `reference-implementations/README.md` it cannot be a *maintained* reference implementation. See [Placement](#placement-in-the-acs-project) |

## Gaps in the spec, and the readings this implementation chose

1. **What a response signature covers.** §10 says the signed input is "the envelope with the `signature` field removed", but a response carries its signature at `result.signature`. This implementation signs the whole JSON-RPC response, `{jsonrpc, id, result}`, with `result.signature` removed.
2. **ServerHello has no signature slot.** `handshake.json` defines none, so the handshake response is unsigned. Handshake *requests* are verified.
3. **Error responses are unsigned.** `JsonRpcError` has no `signature` member.
4. **Denies before a session key exists are unsigned.** These are envelope-invalid denies and the overload deny, where no session key is available.
5. **No code for "method not dispatched".** §17.1 has none, so this implementation mints `-32011` from the unused part of the ACS band. That is the TypeScript reference's choice, and the shared harness depends on it.
6. **Hook traffic before the handshake.** §4 says the handshake is required but names no code for skipping it. This Guardian answers with an honoured `deny` and `capability_not_negotiated`, not an error, so that the miss cannot fall into a fail-open posture. A method that was not negotiated after a handshake gets `CAPABILITY_NOT_NEGOTIATED` (`-32003`).
7. **Version matching.** "Accept X.Y.Z matching major version" is read as accepting `0.1.x`, because in 0.x semver the minor version is the breaking one.
8. **The time limit is checked after evaluation.** Python cannot pre-empt a running evaluation. Tool-gate evaluates in microseconds, so this is a backstop rather than a guarantee.
9. **No result-gate rules.** Tool-gate has none, so `toolCallResult` is `allow` unless it answers a denied call, or the result's reference cannot be resolved and `deny_unresolved_result_refs` is set.

## Placement in the ACS project

CONTRIBUTING.md lists "ports of that reference implementation to other runtimes: Python, Go, Rust, Codex" as in focus. However, `reference-implementations/README.md` requires every maintained implementation to evaluate policy with AGT's runtime, at the commit `agt.lock` pins. This package deliberately swaps the policy engine, which ACS itself scopes out ("the policy engine … is left to deployments"). So the proposal is to keep this as a **standalone repository**. It serves as a second, independent Guardian that shows the wire contract carries across policy engines, together with its conformance evidence and the black-box wire suite as input to #311. If maintainers want it in-tree, the obvious place is a new directory such as `reference-implementations/python-toolgate/` under a "community" label. That needs maintainer agreement, and an accepted issue, first.

## Layout

```
src/acs_guardian_toolgate/
  guardian.py     transport-independent processor (validation, dispatch, signature, replay, Tool-gate, chain)
  mapping.py      Tool-gate Decision -> ACS decision fields
  handshake       (in guardian.py) ClientHello -> ServerHello negotiation
  crypto.py       JCS, HKDF, HMAC-SHA256 KeyRing (sign/verify, rotation)
  chain.py        ContextEntry hashing and SessionChain (§8.2)
  validation.py   vendored v0.1.0 schema registry and validators
  storage.py      StorageProvider interface and InMemoryStorage
  audit.py        bounded JSONL audit log with archive rotation
  transport.py    HTTP (ThreadingHTTPServer) and stdio Content-Length framing
  client.py       minimal Observed-Agent client (build, sign, send)
  wire_suite.py   black-box ACS-Core wire suite
  cli.py          serve | keygen | conformance
  schemas/v0.1.0  ACS schemas, vendored unmodified (SOURCE.txt pins the commit)
policies/default.yaml          Tool-gate's default policy
examples/guardian.yaml         every config key
conformance/                   harness driver, run script, negative control, results/
tests/                         pytest suite (60 tests)
```

## Contributing

Sign every commit: `git commit -s`, which adds `Signed-off-by` under the [DCO](https://developercertificate.org/), the same rule ACS's CONTRIBUTING.md sets. New files carry an `SPDX-License-Identifier: Apache-2.0` header.

## License

Apache-2.0, the license ACS uses for code and schemas. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The vendored ACS schemas are © The OWASP GenAI Security Project and the ACS contributors, Apache-2.0.
