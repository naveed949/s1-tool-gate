import { describe, expect, it } from "vitest";

import { COMPARATOR_IDS, ECE_BIN_COUNT, runHarness, verifyPinnedDataset } from "./index.js";

describe("authority-flip", () => {
  it("exports the pinned dataset check and the harness", () => {
    expect(COMPARATOR_IDS).toEqual(["nimble-ollama", "base-qwen", "frontier-judge"]);
    expect(ECE_BIN_COUNT).toBe(10);
    expect(verifyPinnedDataset().ok).toBe(true);
    expect(runHarness).toBeTypeOf("function");
  });
});
