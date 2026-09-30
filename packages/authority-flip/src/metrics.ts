import { ECE_BIN_COUNT, type CalibrationBin, type Choice } from "./types.js";

export interface ClassifiedItem {
  confidence: number;
  correct: boolean;
}

export interface ScoredPair {
  goldBase: Choice;
  goldFlipped: Choice;
  predBase: Choice;
  predFlipped: Choice;
}

/**
 * Reported rates and ECE are rounded to 6 decimal places.
 * Bin counts stay integers. The ECE sum uses unrounded bin accuracy.
 */
export function roundMetric(value: number): number {
  if (!Number.isFinite(value)) {
    throw new Error("metric is not finite");
  }
  return Number(value.toFixed(6));
}

/**
 * Expected calibration error over {@link ECE_BIN_COUNT} equal-width bins on [0, 1].
 *
 * Confidence is the probability of the predicted choice, not a renormalized margin.
 * Bin i for i = 0..8 is [i/10, (i+1)/10). Bin 9 is [0.9, 1], so confidence 1 is included.
 * Empty bins add nothing. ECE = sum over bins of (count/N) * |accuracy - mean confidence|.
 */
export function expectedCalibrationError(items: readonly ClassifiedItem[]): {
  ece: number;
  bins: CalibrationBin[];
} {
  if (items.length === 0) {
    throw new Error("ECE requires at least one item");
  }
  const totals = Array.from({ length: ECE_BIN_COUNT }, () => ({
    count: 0,
    correct: 0,
    confidence: 0,
  }));
  for (const item of items) {
    if (!Number.isFinite(item.confidence) || item.confidence < 0 || item.confidence > 1) {
      throw new Error("confidence must be finite and in [0, 1]");
    }
    const index = item.confidence >= 1 ? ECE_BIN_COUNT - 1 : Math.floor(item.confidence * ECE_BIN_COUNT);
    const bin = totals[index];
    if (!bin) {
      throw new Error("confidence bin is out of range");
    }
    bin.count += 1;
    bin.confidence += item.confidence;
    if (item.correct) {
      bin.correct += 1;
    }
  }
  let ece = 0;
  const bins = totals.map((bin, index) => {
    const accuracy = bin.count === 0 ? null : bin.correct / bin.count;
    const meanConfidence = bin.count === 0 ? null : bin.confidence / bin.count;
    if (accuracy !== null && meanConfidence !== null) {
      ece += (bin.count / items.length) * Math.abs(accuracy - meanConfidence);
    }
    return {
      index,
      lower: index / ECE_BIN_COUNT,
      upper: (index + 1) / ECE_BIN_COUNT,
      count: bin.count,
      accuracy: accuracy === null ? null : roundMetric(accuracy),
      meanConfidence: meanConfidence === null ? null : roundMetric(meanConfidence),
    };
  });
  return { ece: roundMetric(ece), bins };
}

/**
 * flipRate counts pairs whose predicted labels match both gold labels.
 * Gold labels differ by one fact, so a hit changed the decision in the gold direction.
 * rawFlipRate counts pairs whose two predictions differ, whether or not they match gold.
 */
export function scoreFlips(pairs: readonly ScoredPair[]): {
  flipRate: number;
  rawFlipRate: number;
  correctFlips: number;
  rawFlips: number;
} {
  if (pairs.length === 0) {
    throw new Error("flip rate requires at least one pair");
  }
  let correctFlips = 0;
  let rawFlips = 0;
  for (const pair of pairs) {
    if (pair.predBase !== pair.predFlipped) {
      rawFlips += 1;
    }
    if (pair.predBase === pair.goldBase && pair.predFlipped === pair.goldFlipped) {
      correctFlips += 1;
    }
  }
  return {
    flipRate: roundMetric(correctFlips / pairs.length),
    rawFlipRate: roundMetric(rawFlips / pairs.length),
    correctFlips,
    rawFlips,
  };
}
