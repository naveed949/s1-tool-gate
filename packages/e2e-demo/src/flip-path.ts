import { createDefaultSources } from "../../authority-flip/src/comparators.js";
import { runHarness } from "../../authority-flip/src/harness.js";
import {
  COMPARATOR_IDS,
  REPORT_SCHEMA_VERSION,
  type ComparatorReport,
  type Dataset,
  type FlipReport,
} from "../../authority-flip/src/types.js";
import { envForFlip } from "./flip-env.js";

export interface FlipPathOptions {
  dataset: Dataset;
  env: NodeJS.ProcessEnv;
  fetchImpl: typeof fetch;
  now?: () => Date;
}

/** Run the authority-flip harness. Metrics stay null unless a comparator is `ok`. */
export function runFlipPath(options: FlipPathOptions): Promise<FlipReport> {
  const sources = createDefaultSources({
    env: envForFlip(options.env),
    fetchImpl: options.fetchImpl,
  });
  return runHarness({
    dataset: options.dataset,
    sources,
    ...(options.now ? { now: options.now } : {}),
  });
}

export function failedFlipReport(dataset: Dataset, note: string, now: Date): FlipReport {
  const comparators = {} as FlipReport["comparators"];
  for (const id of COMPARATOR_IDS) {
    comparators[id] = failedComparator(dataset.pairs.length, note);
  }
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    generatedAt: now.toISOString(),
    dataset: datasetIdentity(dataset),
    comparators,
  };
}

function failedComparator(pairCount: number, note: string): ComparatorReport {
  const items = pairCount * 2;
  return {
    status: "failed",
    flipRate: null,
    rawFlipRate: null,
    ece: null,
    counts: {
      pairs: pairCount,
      items,
      scoredPairs: 0,
      correctFlips: 0,
      rawFlips: 0,
      scoredItems: 0,
      correctItems: 0,
    },
    calibration: null,
    notes: [note],
  };
}

export function datasetIdentity(dataset: Dataset): FlipReport["dataset"] {
  return {
    id: dataset.id,
    pairsFile: dataset.pairsFile,
    sha256: dataset.sha256,
    bytes: dataset.bytes,
    pairCount: dataset.pairs.length,
  };
}
