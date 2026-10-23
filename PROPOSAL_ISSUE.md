<!--
Issue form: .github/ISSUE_TEMPLATE/3-reference-implementation.yml ("Reference implementation work")
Labels the form applies: type:refimpl, status:needs-triage
Paste each section below into the matching form field.
-->

**Title:** `[RefImpl] Python Guardian on a second policy engine (Tool-gate): wire-level conformance evidence, and a seed for the #311 contract suite`

---

### Target runtime or language

Python 3.11+, an independent Guardian whose policy engine is [Tool-gate](https://github.com/Manohar8142/Tool-gate), not AGT.

### What this proves

The root README says the conformance harness "measures the wire, not the language behind it". I built a Python Guardian to test that claim from the other side: a different language *and* a different policy engine, with no shared code beyond the vendored v0.1.0 schemas.

**What it is.** `acs-guardian-toolgate` serves ACS v0.1.0 over JSON-RPC 2.0, on HTTP `POST /acs` and on stdio with Content-Length framing:

- It reads and validates the ClientHello. It negotiates the version, transport, profiles and `methods_evaluated`, and refuses a session with `UNSUPPORTED_VERSION`, `PROVENANCE_REQUIRED` or `SESSION_REFUSED` when it has to.
- It evaluates `steps/toolCallRequest` and `steps/toolCallResult`, and answers `system/ping`.
- It checks every request, every hook payload and every outgoing response against the v0.1.0 schemas.
- It verifies and signs with HMAC-SHA256 using the §10 HKDF derivation. The §10 known-answer vector reproduces. `key_id` comes from configuration, several keys can be active for rotation, and an unknown `key_id` is rejected with no fallback.
- It enforces §10.3: duplicate `request_id` and `nonce` are rejected, and so is a timestamp outside the skew window.
- It keeps a §8.2 chain per session, with `request_hash` on every entry, and publishes the head on every content-bearing decision.
- It applies the §9.2 ASK substitution to agents configured as ASK-incapable.
- It has bounded body size, concurrency, evaluation time and logging. Its audit log archives rotated files and never drops a record, and when it cannot write a record it denies the step.

**Mapping.**

| Tool-gate | ACS |
|---|---|
| `allow` | `allow` |
| `deny` | `deny` (`reasoning` = the rule's reason) |
| `require_approval` | `ask`, with `ask_details` (approver, question, `timeout_disposition: deny`) |
| `require_approval` for an ASK-incapable agent | `deny` + `approver_unavailable`, or `defer` (§9.2) |
| rule / policy file | `policy_references[{policy_id, policy_version = sha256 prefix, policy_name, rule_id}]` |
| session taint | `reason_codes: untrusted_into_consequential`, `policy_data.toolgate.{session_tainted, taint_source}` |

`metadata.evaluator` is `deterministic`. MODIFY is never emitted, because Tool-gate has no transform verdict.

**Conformance status, against `d1ad294`:**

- I ran the harness's live-wire leg, the unmodified `checkDenyFailsClosed` from `packages/conformance`, against the Python Guardian over HTTP. It **passes.** All 3 invariant probes pass, and the deny column is measured `expressed` at all 6 mapped methods. A negative control, the same Guardian with its dispatch error code deliberately broken, makes the leg fail. The other harness legs (intervention points, verdicts, identity, policy-input schema) call the TypeScript Guardian's AGT internals in-process, so they do not apply to a Guardian that is not AGT.
- I wrote a black-box ACS-Core wire suite, one or more checks per requirement in `conformance.md`: handshake, dispositions, signatures, replay, chain head, failing closed, ping, batching and errors. **It passes 28 of 28.**
- The pytest suite in the package passes 60 of 60. One test races 50 requests in a single session, 10 of them replays: exactly 40 are decided and the chain verifies.

**Where the implementation had to choose, which I think is useful feedback on the spec:**

1. §10 says "the envelope with the `signature` field removed", but a response's signature sits at `result.signature`. I sign `{jsonrpc, id, result}` with `result.signature` removed. It would help if the spec said this explicitly.
2. ServerHello, and `JsonRpcError`, have no signature slot, so the handshake response and every error are unsigned.
3. §17.1 has no code for "method not dispatched". I reused the reference's `-32011`, because the shared harness asserts it. Should it be registered?
4. §4 requires the handshake before hook traffic but names no error for skipping it. I answer with an honoured `deny` (`capability_not_negotiated`) so the miss cannot fall into fail-open, and I use `-32003` only for a method that was not negotiated after a handshake.
5. "Accept X.Y.Z matching major version" is ambiguous for 0.x. I accept `0.1.x`.

**Known gaps, listed as the README's expectations ask:**

- Only the two tool hooks are evaluated. The other minimum-set hooks are left out of `methods_evaluated`.
- `protocols/MCP/*` is not wrapped.
- There is no Intent or IBAC support.
- Only an in-memory storage provider exists.
- The chain starts at the first content-bearing hook, because `sessionStart` is not dispatched.

**The question I need maintainers to answer.** `reference-implementations/README.md` requires every *maintained* implementation to evaluate policy with the AGT runtime pinned in `agt.lock`. This Guardian uses Tool-gate on purpose, and CONTRIBUTING.md lists the policy engine as out of scope for ACS. So I am not asking for it to become a maintained reference implementation. I am offering it as:

1. Conformance evidence that a second, AGT-independent Guardian interoperates on the wire.
2. The black-box wire suite, written in Python and talking only over HTTP, as a possible starting point for the language-independent contract suite in #311.
3. If you want it in-tree, a PR adding it under a directory you choose (for example `reference-implementations/python-toolgate/`, labelled as a community implementation), or a PR that adds only the wire suite. Otherwise a link from the README to the standalone repo.

Code: https://github.com/Manohar8142/acs-guardian-toolgate (standalone, Apache-2.0, DCO-signed commits)
Policy engine: https://github.com/Manohar8142/Tool-gate

I'm happy to open a PR against `integration` in whichever shape you accept: the wire suite only, the Guardian under a community directory, or a conformance report. I'll follow the branch naming (`refimpl/…`), `git commit -s`, and the guards (`uv run pytest -v`, `uv run mkdocs build --strict`).

### Do you intend to implement this yourself

Yes, I want this assigned to me

### Current Priority Scope

Feeds conformance evidence
