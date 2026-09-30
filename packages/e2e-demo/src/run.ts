import { COMPARATOR_IDS, type Dataset, type FlipReport } from "../../authority-flip/src/types.js";
import { casesFromDataset } from "./cases.js";
import { datasetIdentity } from "./flip-path.js";
import {
  NON_CLAIMS,
  REPORT_SCHEMA_VERSION,
  SCORED_REASON_CODES,
  type DecisionRow,
  type DemoReport,
  type FlipMetricSummary,
  type GateCase,
  type GatePathResult,
  type GatePathStatus,
  type ObservationRow,
} from "./types.js";

const SCORED = new Set<string>(SCORED_REASON_CODES);

export interface RunDemoOptions {
  dataset: Dataset;
  runGatePath: (cases: readonly GateCase[]) => Promise<GatePathResult>;
  runFlip: (dataset: Dataset) => Promise<FlipReport>;
  now?: () => Date;
}

/**
 * Compose one demo report.
 *
 * Flip rate and ECE are copied from the authority-flip report. A fail-closed
 * gate decision does not fill those fields.
 */
export async function runDemo(options: RunDemoOptions): Promise<DemoReport> {
  const now = options.now ?? (() => new Date());
  const cases = casesFromDataset(options.dataset);
  const gateResult = await options.runGatePath(cases);
  const flip = guardFlip(await options.runFlip(options.dataset));
  const gate = reconcileGate(gateResult, cases);
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    generatedAt: now().toISOString(),
    nonClaims: NON_CLAIMS,
    dataset: datasetIdentity(options.dataset),
    gate,
    decisions: gateResult.decisions,
    observations: gateResult.observations,
    flipSummary: summarizeFlip(flip),
    flip,
  };
}

export function exitCodeForDemo(report: DemoReport): number {
  const rows = COMPARATOR_IDS.map((id) => report.flip.comparators[id]);
  if (report.gate.status === "failed" || rows.some((row) => row.status === "failed")) {
    return 1;
  }
  if (report.gate.status === "unavailable" || rows.some((row) => row.status === "unsupported")) {
    return 2;
  }
  return 0;
}

export function summarizeFlip(report: FlipReport): DemoReport["flipSummary"] {
  const summary = {} as DemoReport["flipSummary"];
  for (const id of COMPARATOR_IDS) {
    const row = report.comparators[id];
    const metric: FlipMetricSummary = {
      status: row.status,
      flipRate: row.flipRate,
      rawFlipRate: row.rawFlipRate,
      ece: row.ece,
    };
    summary[id] = metric;
  }
  return summary;
}

function reconcileGate(result: GatePathResult, cases: readonly GateCase[]): DemoReport["gate"] {
  const notes = [...result.notes];
  let status: GatePathStatus = result.status;
  if (result.decisions.length !== cases.length || result.observations.length !== cases.length) {
    status = "failed";
    notes.push(
      `gate path returned ${result.decisions.length} decisions and ${result.observations.length} observations for ${cases.length} cases`,
    );
  } else {
    const mismatch = alignmentNote(result.decisions, result.observations, cases);
    if (mismatch) {
      status = "failed";
      notes.push(mismatch);
    }
  }
  const failClosed = result.decisions.filter((row) => !SCORED.has(row.decision.reasonCode));
  if (failClosed.length > 0 && status === "ok") {
    status = "unavailable";
    notes.push("fail-closed decisions are not a scored gate path");
  }
  if (status === "ok" && cases.length === 0) {
    status = "failed";
    notes.push("gate path received no cases");
  }
  return { status, notes };
}

function alignmentNote(
  decisions: readonly DecisionRow[],
  observations: readonly ObservationRow[],
  cases: readonly GateCase[],
): string | null {
  for (let index = 0; index < cases.length; index += 1) {
    const expected = cases[index];
    const decision = decisions[index];
    const observation = observations[index];
    if (!expected || !decision || !observation) {
      return "gate path row is missing";
    }
    if (decision.pairId !== expected.pairId || decision.side !== expected.side) {
      return `decision row ${index} is not ${expected.pairId} ${expected.side}`;
    }
    if (observation.pairId !== expected.pairId || observation.side !== expected.side) {
      return `observation row ${index} is not ${expected.pairId} ${expected.side}`;
    }
    const entry = observation.entry;
    if (entry.choice !== decision.decision.choice || entry.reasonCode !== decision.decision.reasonCode) {
      return `${expected.pairId} ${expected.side} observation does not match the decision`;
    }
    if (entry.sideEffect && entry.choice !== "allow") {
      return `${expected.pairId} ${expected.side} recorded a side effect without an allow`;
    }
    if (entry.sideEffect && !entry.withinGrantedAuthority) {
      return `${expected.pairId} ${expected.side} recorded a side effect outside the fixture`;
    }
    if (entry.choice === "allow" && entry.withinGrantedAuthority && !entry.sideEffect) {
      return `${expected.pairId} ${expected.side} allow inside the fixture did not run the stub`;
    }
  }
  return null;
}

function guardFlip(report: FlipReport): FlipReport {
  for (const id of COMPARATOR_IDS) {
    const row = report.comparators[id];
    if (row.status === "ok") {
      continue;
    }
    if (row.flipRate !== null || row.rawFlipRate !== null || row.ece !== null || row.calibration !== null) {
      throw new Error(`${id} is ${row.status} and still carries flip metrics`);
    }
  }
  return report;
}
