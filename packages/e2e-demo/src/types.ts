import type { FlipReport } from "../../authority-flip/src/types.js";

export const REPORT_SCHEMA_VERSION = "e2e-demo.report.v1" as const;

/** Phrases carried on every demo report. They are also stated in the README. */
export const NON_CLAIMS = [
  "Nimble score ≠ gate held",
  "high noul ≠ safe",
  "this is not AdaptiveSandbox",
  "this is not open Jev",
] as const;

export const SCORED_REASON_CODES = ["nimble_allow", "nimble_deny", "nimble_escalate"] as const;

export type GatePathStatus = "ok" | "unavailable" | "failed";

export type SideName = "base" | "flipped";

export type GoldLabel = "allow" | "deny" | "escalate";

/** One pinned side sent to the Python gate path. */
export interface GateCase {
  pairId: string;
  side: SideName;
  tool: string;
  policy: string;
  args: Record<string, string>;
  context: string;
  gold: GoldLabel;
}

export interface GateDecisionBody {
  choice: GoldLabel;
  probs: Record<string, number>;
  reasonCode: string;
}

export interface DecisionRow {
  pairId: string;
  side: SideName;
  gold: GoldLabel;
  decision: GateDecisionBody;
}

/** Observation-log entry, schema version 1. Wrapped so pair identity stays outside that schema. */
export interface ObservationEntry {
  schemaVersion: 1;
  choice: GoldLabel;
  probs: Record<string, number>;
  reasonCode: string;
  sideEffect: boolean;
  toolName: string;
  withinGrantedAuthority: boolean;
}

export interface ObservationRow {
  pairId: string;
  side: SideName;
  entry: ObservationEntry;
}

export interface GateSection {
  status: GatePathStatus;
  notes: string[];
}

/** Internal JSON written by `python -m e2e_demo`. */
export interface GatePathResult {
  status: GatePathStatus;
  notes: string[];
  decisions: DecisionRow[];
  observations: ObservationRow[];
}

export interface FlipMetricSummary {
  status: "ok" | "unsupported" | "failed";
  flipRate: number | null;
  rawFlipRate: number | null;
  ece: number | null;
}

export interface DemoReport {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  generatedAt: string;
  nonClaims: readonly string[];
  dataset: FlipReport["dataset"];
  gate: GateSection;
  decisions: DecisionRow[];
  observations: ObservationRow[];
  /** Copied from `flip`. Not computed from gate decisions. */
  flipSummary: Record<"nimble-ollama" | "base-qwen" | "frontier-judge", FlipMetricSummary>;
  /** Full authority-flip.report.v1 document. */
  flip: FlipReport;
}
