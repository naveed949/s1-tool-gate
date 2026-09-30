import { expectedCalibrationError, scoreFlips, type ClassifiedItem, type ScoredPair } from "./metrics.js";
import {
  COMPARATOR_IDS,
  ECE_BIN_COUNT,
  REPORT_SCHEMA_VERSION,
  type AuthorityCase,
  type Choice,
  type ComparatorReport,
  type ComparatorSource,
  type Counts,
  type Dataset,
  type FlipReport,
  type Pair,
} from "./types.js";
import { parseChoiceFields } from "./parse.js";

export function exitCodeForReport(report: FlipReport): number {
  const rows = COMPARATOR_IDS.map((id) => report.comparators[id]);
  if (rows.some((row) => row.status === "failed")) {
    return 1;
  }
  if (rows.some((row) => row.status === "unsupported")) {
    return 2;
  }
  return 0;
}

export async function runHarness(options: {
  dataset: Dataset;
  sources: readonly ComparatorSource[];
  now?: () => Date;
}): Promise<FlipReport> {
  const byId = new Map(options.sources.map((source) => [source.id, source]));
  if (byId.size !== COMPARATOR_IDS.length || COMPARATOR_IDS.some((id) => !byId.has(id))) {
    throw new Error("runHarness requires nimble-ollama, base-qwen, and frontier-judge sources");
  }
  const now = options.now ?? (() => new Date());
  const comparators = {} as FlipReport["comparators"];
  for (const id of COMPARATOR_IDS) {
    const source = byId.get(id);
    if (!source) {
      throw new Error(`missing comparator source ${id}`);
    }
    comparators[id] = await runSource(source, options.dataset);
  }
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    generatedAt: now().toISOString(),
    dataset: {
      id: options.dataset.id,
      pairsFile: options.dataset.pairsFile,
      sha256: options.dataset.sha256,
      bytes: options.dataset.bytes,
      pairCount: options.dataset.pairs.length,
    },
    comparators,
  };
}

async function runSource(source: ComparatorSource, dataset: Dataset): Promise<ComparatorReport> {
  const counts = emptyCounts(dataset.pairs.length);
  if (dataset.pairs.length === 0) {
    return failedReport(counts, ["dataset has no pairs"]);
  }
  let resolved: Awaited<ReturnType<ComparatorSource["resolve"]>>;
  try {
    resolved = await source.resolve();
  } catch (error) {
    return failedReport(counts, [noteFrom(error)]);
  }
  if (resolved.availability === "unsupported") {
    return {
      status: "unsupported",
      flipRate: null,
      rawFlipRate: null,
      ece: null,
      counts,
      calibration: null,
      notes: resolved.notes,
    };
  }

  const scoredPairs: ScoredPair[] = [];
  const classified: ClassifiedItem[] = [];
  const notes = [...resolved.notes];
  let itemErrors = 0;

  for (const pair of dataset.pairs) {
    const base = await scoreSide(resolved.score, pair, "base", counts, notes);
    const flipped = await scoreSide(resolved.score, pair, "flipped", counts, notes);
    if (!base.ok || !flipped.ok) {
      itemErrors += (base.ok ? 0 : 1) + (flipped.ok ? 0 : 1);
      continue;
    }
    counts.scoredPairs += 1;
    if (base.score.choice !== flipped.score.choice) {
      counts.rawFlips += 1;
    }
    if (base.score.choice === pair.base.gold && flipped.score.choice === pair.flipped.gold) {
      counts.correctFlips += 1;
    }
    scoredPairs.push({
      goldBase: pair.base.gold,
      goldFlipped: pair.flipped.gold,
      predBase: base.score.choice,
      predFlipped: flipped.score.choice,
    });
    classified.push(
      { confidence: base.score.probs[base.score.choice], correct: base.score.choice === pair.base.gold },
      {
        confidence: flipped.score.probs[flipped.score.choice],
        correct: flipped.score.choice === pair.flipped.gold,
      },
    );
  }

  if (itemErrors > 0 || scoredPairs.length !== dataset.pairs.length) {
    return failedReport(counts, notes);
  }

  const flips = scoreFlips(scoredPairs);
  const calibration = expectedCalibrationError(classified);
  return {
    status: "ok",
    flipRate: flips.flipRate,
    rawFlipRate: flips.rawFlipRate,
    ece: calibration.ece,
    counts: {
      ...counts,
      correctFlips: flips.correctFlips,
      rawFlips: flips.rawFlips,
    },
    calibration: { binCount: ECE_BIN_COUNT, bins: calibration.bins },
    notes,
  };
}

async function scoreSide(
  score: (item: AuthorityCase) => Promise<{ choice: Choice; probs: Record<Choice, number> }>,
  pair: Pair,
  side: "base" | "flipped",
  counts: Counts,
  notes: string[],
): Promise<{ ok: true; score: { choice: Choice; probs: Record<Choice, number> } } | { ok: false }> {
  try {
    const raw = await score(toCase(pair, side));
    const parsed = parseChoiceFields(raw.choice, raw.probs);
    counts.scoredItems += 1;
    if (parsed.choice === pair[side].gold) {
      counts.correctItems += 1;
    }
    return { ok: true, score: parsed };
  } catch (error) {
    notes.push(`${pair.id} ${side}: ${noteFrom(error)}`);
    return { ok: false };
  }
}

function toCase(pair: Pair, side: "base" | "flipped"): AuthorityCase {
  const face = pair[side];
  return {
    pairId: pair.id,
    side,
    tool: pair.tool,
    policy: face.policy,
    args: face.args,
    context: face.context,
  };
}

function emptyCounts(pairs: number): Counts {
  return {
    pairs,
    items: pairs * 2,
    scoredPairs: 0,
    correctFlips: 0,
    rawFlips: 0,
    scoredItems: 0,
    correctItems: 0,
  };
}

function failedReport(counts: Counts, notes: string[]): ComparatorReport {
  return {
    status: "failed",
    flipRate: null,
    rawFlipRate: null,
    ece: null,
    counts,
    calibration: null,
    notes,
  };
}

function noteFrom(error: unknown): string {
  const message = error instanceof Error ? error.message : "score failed";
  return message.replace(/\s+/g, " ").trim().slice(0, 300) || "score failed";
}
