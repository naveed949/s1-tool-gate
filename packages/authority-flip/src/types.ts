/** Allow, deny, or escalate. The harness scores this label; it does not run a tool. */
export const CHOICES = ["allow", "deny", "escalate"] as const;

export type Choice = (typeof CHOICES)[number];

export const COMPARATOR_IDS = ["nimble-ollama", "base-qwen", "frontier-judge"] as const;

export type ComparatorId = (typeof COMPARATOR_IDS)[number];

export type ComparatorStatus = "ok" | "unsupported" | "failed";

export const REPORT_SCHEMA_VERSION = "authority-flip.report.v1" as const;

export const MANIFEST_SCHEMA_VERSION = "authority-flip.manifest.v1" as const;

/** Ten equal-width bins is the ECE this package reports. */
export const ECE_BIN_COUNT = 10;

export const PINNED_PAIRS_FILE = "packages/authority-flip/data/pairs.jsonl";

export interface Side {
  policy: string;
  args: Record<string, string>;
  context: string;
  gold: Choice;
}

export interface Pair {
  id: string;
  domain: "agent-authority";
  tool: string;
  fact: string;
  flip: string;
  base: Side;
  flipped: Side;
}

/** One side of a pair, without the gold label. Comparators receive only this. */
export interface AuthorityCase {
  pairId: string;
  side: "base" | "flipped";
  tool: string;
  policy: string;
  args: Record<string, string>;
  context: string;
}

export interface ModelScore {
  choice: Choice;
  probs: Record<Choice, number>;
}

export interface Dataset {
  id: string;
  pairsFile: string;
  sha256: string;
  bytes: number;
  pairs: Pair[];
}

export interface Counts {
  pairs: number;
  items: number;
  scoredPairs: number;
  correctFlips: number;
  rawFlips: number;
  scoredItems: number;
  correctItems: number;
}

export interface CalibrationBin {
  index: number;
  lower: number;
  upper: number;
  count: number;
  accuracy: number | null;
  meanConfidence: number | null;
}

export interface Calibration {
  binCount: number;
  bins: CalibrationBin[];
}

export interface ComparatorReport {
  status: ComparatorStatus;
  flipRate: number | null;
  rawFlipRate: number | null;
  ece: number | null;
  counts: Counts;
  calibration: Calibration | null;
  notes: string[];
}

export interface FlipReport {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  generatedAt: string;
  dataset: {
    id: string;
    pairsFile: string;
    sha256: string;
    bytes: number;
    pairCount: number;
  };
  comparators: Record<ComparatorId, ComparatorReport>;
}

export type ScoreFn = (item: AuthorityCase) => Promise<ModelScore>;

export interface ReadyComparator {
  availability: "ready";
  notes: string[];
  score: ScoreFn;
}

export interface UnsupportedComparator {
  availability: "unsupported";
  notes: string[];
}

export type ResolvedComparator = ReadyComparator | UnsupportedComparator;

export interface ComparatorSource {
  id: ComparatorId;
  resolve: () => Promise<ResolvedComparator>;
}
