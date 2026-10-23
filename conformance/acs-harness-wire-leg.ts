// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Rayavarapu Manohar
//
// Drives the ACS reference conformance harness's live-wire leg -- the
// unmodified `checkDenyFailsClosed` from
// reference-implementations/agt/packages/conformance -- against an EXTERNAL
// Guardian at $GUARDIAN_URL instead of the in-process TypeScript Guardian.
// The root README: "The harness measures the wire, not the language behind it."
//
// Run from reference-implementations/agt/ (mapping.yaml is read relative to it):
//   GUARDIAN_URL=http://127.0.0.1:8799/acs bun run /abs/path/acs-harness-wire-leg.ts
//
// The other harness legs (intervention-point and verdict round trips, action
// identity, policy-input schema) call the TypeScript Guardian's own AGT
// resolver, verdict mapping and AGT bridge in-process. They measure AGT, not
// the wire, so they have nothing to say about a Guardian that is not AGT and
// are reported as NOT APPLICABLE. The trace-pillar rows are derived from the
// schemas alone and are printed unchanged.
const AGT = process.cwd();
const conformance = await import(`${AGT}/packages/conformance/src/index.ts`);
const guardian = await import(`${AGT}/packages/guardian/src/index.ts`);

const url = process.env.GUARDIAN_URL;
if (!url) {
  console.error("set GUARDIAN_URL");
  process.exit(2);
}
const mapping = guardian.loadMapping("mapping.yaml");
let cells: Array<{ point: string; verdict: string; status: string; reason: string }> = [];
let failure: string | undefined;
try {
  cells = await conformance.checkDenyFailsClosed({ url, close: async () => {} }, mapping);
} catch (error) {
  failure = String(error instanceof Error ? error.message : error);
}

const lines: string[] = [];
lines.push(`=== ACS harness, live-wire leg (checkDenyFailsClosed) against ${url} ===`);
lines.push("probes: assertEvaluationFailsClosed, assertHookPayloadFailureIsUndispatchedElsewhere,");
lines.push("        assertUnmappedMethodIsUndispatched, measureDenyColumn (one probe per mapped ACS method)");
if (failure) {
  lines.push(`RESULT: FAIL -- ${failure}`);
} else {
  for (const c of cells) {
    const row = mapping.intervention_points[c.point];
    lines.push(`PASS  ${c.point.padEnd(16)} ${String(row?.acs_method).padEnd(24)} deny -> ${c.status}`);
  }
  lines.push(`RESULT: PASS -- 3 invariant probes passed, ${cells.length} deny-column cells measured expressed`);
}
lines.push("");
lines.push("=== Trace pillar rows (schema-derived; independent of the Guardian under test) ===");
lines.push(conformance.renderTraceRows(conformance.checkTracePillar()));
lines.push("");
lines.push("=== Which checks ran ===");
lines.push("deny fails closed (live Guardian under test, over the wire): RAN");
lines.push("trace pillar: RAN");
lines.push("intervention-point round trip: NOT APPLICABLE -- in-process call into the TypeScript Guardian's AGT resolver");
lines.push("verdict round trip: NOT APPLICABLE -- in-process call into the TypeScript Guardian's AGT verdict mapping");
lines.push("action identity: NOT APPLICABLE -- in-process AGT bridge evaluation");
lines.push("policy-input schema: NOT APPLICABLE -- validates AGT policy input; this Guardian does not build one");
console.log(lines.join("\n"));
process.exit(failure ? 1 : 0);
