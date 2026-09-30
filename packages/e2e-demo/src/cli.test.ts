import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import type { FlipReport } from "../../authority-flip/src/types.js";
import { main } from "./cli.js";
import type { GateCase, GatePathResult } from "./types.js";

function denyPath(cases: readonly GateCase[]): GatePathResult {
  return {
    status: "unavailable",
    notes: ["Ollama is down"],
    decisions: cases.map((item) => ({
      pairId: item.pairId,
      side: item.side,
      gold: item.gold,
      decision: { choice: "deny", probs: {}, reasonCode: "fail_closed_down" },
    })),
    observations: cases.map((item) => ({
      pairId: item.pairId,
      side: item.side,
      entry: {
        schemaVersion: 1,
        choice: "deny",
        probs: {},
        reasonCode: "fail_closed_down",
        sideEffect: false,
        toolName: item.tool,
        withinGrantedAuthority: true,
      },
    })),
  };
}

function unsupportedFlip(dataset: { id: string; pairsFile: string; sha256: string; bytes: number; pairs: readonly unknown[] }): FlipReport {
  const row = {
    status: "unsupported" as const,
    flipRate: null,
    rawFlipRate: null,
    ece: null,
    counts: {
      pairs: dataset.pairs.length,
      items: dataset.pairs.length * 2,
      scoredPairs: 0,
      correctFlips: 0,
      rawFlips: 0,
      scoredItems: 0,
      correctItems: 0,
    },
    calibration: null,
    notes: ["Ollama is unavailable"],
  };
  return {
    schemaVersion: "authority-flip.report.v1",
    generatedAt: "2026-09-30T00:00:00.000Z",
    dataset: {
      id: dataset.id,
      pairsFile: dataset.pairsFile,
      sha256: dataset.sha256,
      bytes: dataset.bytes,
      pairCount: dataset.pairs.length,
    },
    comparators: {
      "nimble-ollama": row,
      "base-qwen": { ...row, counts: { ...row.counts } },
      "frontier-judge": { ...row, counts: { ...row.counts } },
    },
  };
}

describe("e2e demo cli", () => {
  it("prints an unavailable report and exits non-zero", async () => {
    let sawCases = 0;
    let stdout = "";
    const code = await main({
      env: {},
      fetchImpl: async () => {
        throw new Error("injected runners must be used");
      },
      stdout: (chunk) => {
        stdout += chunk;
      },
      stderr: () => {},
      now: () => new Date("2026-09-30T00:00:00.000Z"),
      runGatePath: async (cases) => {
        sawCases = cases.length;
        return denyPath(cases);
      },
      runFlip: async (dataset) => unsupportedFlip(dataset),
    });
    const body = JSON.parse(stdout) as {
      gate: { status: string };
      decisions: unknown[];
      observations: unknown[];
      flipSummary: { "nimble-ollama": { flipRate: number | null; ece: number | null } };
      nonClaims: string[];
    };
    expect(code).toBe(2);
    expect(sawCases).toBe(32);
    expect(body.gate.status).toBe("unavailable");
    expect(body.decisions).toHaveLength(32);
    expect(body.observations).toHaveLength(32);
    expect(body.flipSummary["nimble-ollama"].flipRate).toBeNull();
    expect(body.flipSummary["nimble-ollama"].ece).toBeNull();
    expect(body.nonClaims).toContain("Nimble score ≠ gate held");
    expect(body.nonClaims).toContain("this is not AdaptiveSandbox");
    expect(body.nonClaims).toContain("this is not open Jev");
  });

  it("does not call gate or flip when the pin does not match", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "e2e-demo-cli-"));
    writeFileSync(path.join(dir, "manifest.json"), "{}\n");
    writeFileSync(path.join(dir, "pairs.jsonl"), "{}\n");
    let called = 0;
    let stdout = "";
    let stderr = "";
    const code = await main({
      env: {},
      dataDir: dir,
      fetchImpl: async () => {
        throw new Error("pin failure must not fetch");
      },
      stdout: (chunk) => {
        stdout += chunk;
      },
      stderr: (chunk) => {
        stderr += chunk;
      },
      runGatePath: async () => {
        called += 1;
        return { status: "ok", notes: [], decisions: [], observations: [] };
      },
      runFlip: async () => {
        called += 1;
        throw new Error("flip must not run");
      },
    });
    expect(code).toBe(1);
    expect(called).toBe(0);
    expect(stdout).toBe("");
    expect(stderr.length).toBeGreaterThan(0);
  });

  it("records a flip runner failure with null metrics", async () => {
    let stdout = "";
    const code = await main({
      env: {},
      fetchImpl: async () => {
        throw new Error("unused");
      },
      stdout: (chunk) => {
        stdout += chunk;
      },
      stderr: () => {},
      now: () => new Date("2026-09-30T00:00:00.000Z"),
      runGatePath: async (cases) => denyPath(cases),
      runFlip: async () => {
        throw new Error("harness exploded");
      },
    });
    const body = JSON.parse(stdout) as {
      flip: { comparators: Record<string, { status: string; flipRate: number | null; ece: number | null }> };
    };
    expect(code).toBe(1);
    expect(body.flip.comparators["nimble-ollama"]?.status).toBe("failed");
    expect(body.flip.comparators["nimble-ollama"]?.flipRate).toBeNull();
    expect(body.flip.comparators["base-qwen"]?.ece).toBeNull();
  });
});
