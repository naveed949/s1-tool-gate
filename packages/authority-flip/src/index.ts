export { createDefaultSources, ollamaBaseUrl, ollamaModelPresent, readTimeoutMs } from "./comparators.js";
export { parsePairs, sha256Hex, verifyPinnedDataset } from "./dataset.js";
export { exitCodeForReport, runHarness } from "./harness.js";
export { expectedCalibrationError, roundMetric, scoreFlips } from "./metrics.js";
export { parseChoiceScore, parseNimbleScore, PROB_SUM_TOLERANCE } from "./parse.js";
export { buildChatPrompt } from "./prompt.js";
export {
  CHOICES,
  COMPARATOR_IDS,
  ECE_BIN_COUNT,
  MANIFEST_SCHEMA_VERSION,
  PINNED_PAIRS_FILE,
  REPORT_SCHEMA_VERSION,
} from "./types.js";
export type {
  AuthorityCase,
  Calibration,
  CalibrationBin,
  Choice,
  ComparatorId,
  ComparatorReport,
  ComparatorSource,
  ComparatorStatus,
  Counts,
  Dataset,
  FlipReport,
  ModelScore,
  Pair,
  Side,
} from "./types.js";
