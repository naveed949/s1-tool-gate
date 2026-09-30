import { describe, expect, it } from "vitest";

import { expectedCalibrationError, scoreFlips } from "./metrics.js";

describe("flip rate", () => {
  it("counts a correct direction change and a raw change separately", () => {
    const scored = scoreFlips([
      { goldBase: "allow", goldFlipped: "deny", predBase: "allow", predFlipped: "deny" },
      { goldBase: "allow", goldFlipped: "escalate", predBase: "deny", predFlipped: "allow" },
      { goldBase: "allow", goldFlipped: "deny", predBase: "allow", predFlipped: "allow" },
    ]);
    expect(scored.correctFlips).toBe(1);
    expect(scored.rawFlips).toBe(2);
    expect(scored.flipRate).toBeCloseTo(1 / 3, 6);
    expect(scored.rawFlipRate).toBeCloseTo(2 / 3, 6);
    expect(scored.flipRate).toBe(0.333333);
    expect(scored.rawFlipRate).toBe(0.666667);
    expect(scored.correctFlips).toBeLessThanOrEqual(scored.rawFlips);
  });
});

describe("expected calibration error", () => {
  it("uses ten equal-width bins and includes confidence 1 in the last bin", () => {
    const scored = expectedCalibrationError([
      { confidence: 0.95, correct: true },
      { confidence: 0.95, correct: true },
      { confidence: 0.55, correct: false },
      { confidence: 0.15, correct: true },
    ]);
    expect(scored.bins).toHaveLength(10);
    expect(scored.bins[1]?.count).toBe(1);
    expect(scored.bins[5]?.count).toBe(1);
    expect(scored.bins[9]?.count).toBe(2);
    expect(scored.bins[0]?.count).toBe(0);
    expect(scored.bins[0]?.accuracy).toBeNull();
    expect(scored.ece).toBe(0.375);
  });

  it("puts 0 in the first bin and 1 in the last bin", () => {
    const scored = expectedCalibrationError([
      { confidence: 0, correct: false },
      { confidence: 0.1, correct: true },
      { confidence: 1, correct: true },
    ]);
    expect(scored.bins[0]?.count).toBe(1);
    expect(scored.bins[1]?.count).toBe(1);
    expect(scored.bins[9]?.count).toBe(1);
    expect(scored.bins[9]?.lower).toBe(0.9);
    expect(scored.bins[9]?.upper).toBe(1);
    expect(scored.ece).toBe(0.3);
  });

  it("is zero when every confidence matches accuracy", () => {
    const scored = expectedCalibrationError([
      { confidence: 1, correct: true },
      { confidence: 1, correct: true },
    ]);
    expect(scored.ece).toBe(0);
  });

  it("is one when every prediction is wrong at confidence 1", () => {
    const scored = expectedCalibrationError([{ confidence: 1, correct: false }]);
    expect(scored.ece).toBe(1);
    expect(scored.bins[9]?.accuracy).toBe(0);
    expect(scored.bins[9]?.meanConfidence).toBe(1);
  });
});
