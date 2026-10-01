import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { NON_CLAIMS } from "./types.js";

const REPO = path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));

interface DecisionRow {
  decision: { choice: string; reasonCode: string };
}

interface ObservationRow {
  entry: { choice: string; reasonCode: string; sideEffect: boolean };
}

interface ComparatorRow {
  status: string;
  flipRate: number | null;
  rawFlipRate: number | null;
  ece: number | null;
  calibration: unknown;
}

interface SourceReport {
  schemaVersion: string;
  generatedAt: string;
  nonClaims: string[];
  gate: { status: string; notes: string[] };
  decisions: DecisionRow[];
  observations: ObservationRow[];
  flip: { comparators: Record<string, ComparatorRow> };
}

interface NimbleRecord {
  decision: string;
  status: string;
  model: string;
  flip_rate: number | null;
  ece: number | null;
  soft_pass: boolean;
  message: string;
}

interface PortfolioRecord {
  seed: null;
  model: string;
  admit: number;
  deny: number;
  escalate: number;
  timestamp: string;
  reproduce: string;
  decision: string;
  closure: string;
  flip_rate: number | null;
  ece: number | null;
  soft_pass: boolean;
  message: string;
  nimble: NimbleRecord;
  exitCode: number;
  source: string;
  nonClaims: string[];
}

const REFUSAL = "Soft-PASS was refused";

function readJson(relativePath: string): unknown {
  return JSON.parse(readFileSync(path.join(REPO, relativePath), "utf8")) as unknown;
}

describe("checked-in fail-closed run", () => {
  const source = readJson("runs/e2e-demo-fail-closed.json") as SourceReport;
  const portfolio = readJson("runs/fail-closed-unsupported.json") as PortfolioRecord;
  const portfolioText = readFileSync(path.join(REPO, "runs/fail-closed-unsupported.json"), "utf8");
  const readme = readFileSync(path.join(REPO, "runs/README.md"), "utf8");
  const rootReadme = readFileSync(path.join(REPO, "README.md"), "utf8");

  it("keeps the missing-scorer metrics null and refuses Soft-PASS", () => {
    expect(portfolio.seed).toBeNull();
    expect(portfolio.model).toBe("unsupported");
    expect(portfolio.decision).toBe("unsupported");
    expect(portfolio.closure).toBe("deny-closed");
    expect(portfolio.flip_rate).toBeNull();
    expect(portfolio.ece).toBeNull();
    expect(portfolio.soft_pass).toBe(false);
    expect(portfolio.message).toContain(REFUSAL);
    expect(portfolio.timestamp).toBe(source.generatedAt);
    expect(portfolio.reproduce).toContain("npm run --silent e2e-demo");
    expect(portfolio.reproduce).toContain("http://127.0.0.1:9");
    expect(portfolio.exitCode).toBe(2);
    expect(portfolio.source).toBe("runs/e2e-demo-fail-closed.json");

    expect(portfolio.nimble.decision).toBe("unsupported");
    expect(portfolio.nimble.status).toBe("unsupported");
    expect(portfolio.nimble.model).toBe("unsupported");
    expect(portfolio.nimble.flip_rate).toBeNull();
    expect(portfolio.nimble.ece).toBeNull();
    expect(portfolio.nimble.soft_pass).toBe(false);
    expect(portfolio.nimble.message).toContain(REFUSAL);
    expect(portfolio.nimble.flip_rate).toBe(source.flip.comparators["nimble-ollama"]?.flipRate);
    expect(portfolio.nimble.ece).toBe(source.flip.comparators["nimble-ollama"]?.ece);
  });

  it("counts deny-closed gate choices and does not treat them as flip metrics", () => {
    expect(source.schemaVersion).toBe("e2e-demo.report.v1");
    expect(source.gate.status).toBe("unavailable");
    expect(source.decisions).toHaveLength(32);
    expect(source.observations).toHaveLength(32);
    const choices = source.decisions.map((row) => row.decision.choice);
    expect(portfolio.admit).toBe(choices.filter((choice) => choice === "allow").length);
    expect(portfolio.deny).toBe(choices.filter((choice) => choice === "deny").length);
    expect(portfolio.escalate).toBe(choices.filter((choice) => choice === "escalate").length);
    expect(portfolio.admit).toBe(0);
    expect(portfolio.deny).toBe(32);
    expect(portfolio.escalate).toBe(0);
    for (const row of source.decisions) {
      expect(row.decision.choice).toBe("deny");
      expect(row.decision.reasonCode).toBe("fail_closed_down");
    }
    for (const row of source.observations) {
      expect(row.entry.sideEffect).toBe(false);
      expect(row.entry.reasonCode).toBe("fail_closed_down");
    }
    for (const row of Object.values(source.flip.comparators)) {
      expect(row.status).toBe("unsupported");
      expect(row.flipRate).toBeNull();
      expect(row.rawFlipRate).toBeNull();
      expect(row.ece).toBeNull();
      expect(row.calibration).toBeNull();
    }
  });

  it("states the prove non-claims and keeps credentials and pass claims out", () => {
    expect(portfolio.nonClaims).toEqual([...NON_CLAIMS]);
    expect(source.nonClaims).toEqual([...NON_CLAIMS]);
    const combined = `${portfolioText}\n${readme}\n${rootReadme}`;
    expect(combined).not.toContain("adaptiveSandboxQualified");
    expect(combined).not.toMatch(/gate[- ]calibrated/i);
    expect(portfolioText).not.toMatch(/sk-[A-Za-z0-9]{8,}/);
    expect(portfolioText).not.toContain("Bearer ");
    expect(portfolioText).not.toContain("/home/");
    expect(readme).toContain("Nimble score ≠ gate held");
    expect(readme).toContain("Live flip/ECE was deferred until this artifact");
    expect(readme).toContain("no Soft-PASS substitute");
    expect(rootReadme).toContain("runs/fail-closed-unsupported.json");
    expect(rootReadme).toContain("Live flip/ECE was deferred until this artifact");
  });
});
