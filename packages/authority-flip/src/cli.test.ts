import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { main } from "./cli.js";
import type { ComparatorSource } from "./types.js";

function unsupportedSources(): ComparatorSource[] {
  return [
    { id: "nimble-ollama", resolve: async () => ({ availability: "unsupported", notes: ["Ollama is unavailable"] }) },
    { id: "base-qwen", resolve: async () => ({ availability: "unsupported", notes: ["Ollama is unavailable"] }) },
    {
      id: "frontier-judge",
      resolve: async () => ({ availability: "unsupported", notes: ["AUTHORITY_FLIP_JUDGE_API_KEY is not set"] }),
    },
  ];
}

describe("cli", () => {
  it("verifies the pinned hash without scoring a model", async () => {
    let stdout = "";
    const code = await main({
      argv: ["verify"],
      env: {},
      fetchImpl: async () => {
        throw new Error("verify must not fetch");
      },
      stdout: (chunk) => {
        stdout += chunk;
      },
      stderr: () => {},
    });
    const body = JSON.parse(stdout) as { status: string; checked: string; pairCount: number; sha256: string };
    expect(code).toBe(0);
    expect(body.status).toBe("ok");
    expect(body.checked).toBe("sha256");
    expect(body.pairCount).toBe(16);
    expect(body.sha256).toHaveLength(64);
  });

  it("prints an unsupported report and exits non-zero", async () => {
    let stdout = "";
    const code = await main({
      argv: ["run"],
      env: {},
      fetchImpl: async () => {
        throw new Error("injected sources must be used");
      },
      stdout: (chunk) => {
        stdout += chunk;
      },
      stderr: () => {},
      now: () => new Date("2026-09-30T00:00:00.000Z"),
      sources: unsupportedSources(),
    });
    const body = JSON.parse(stdout) as {
      comparators: Record<string, { status: string; flipRate: number | null; ece: number | null }>;
    };
    expect(code).toBe(2);
    expect(body.comparators["nimble-ollama"]?.status).toBe("unsupported");
    expect(body.comparators["base-qwen"]?.flipRate).toBeNull();
    expect(body.comparators["frontier-judge"]?.ece).toBeNull();
  });

  it("does not score comparators when the pin does not match", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "authority-flip-cli-"));
    writeFileSync(path.join(dir, "manifest.json"), "{}\n");
    writeFileSync(path.join(dir, "pairs.jsonl"), "{}\n");
    let resolved = 0;
    let stdout = "";
    let stderr = "";
    const sources: ComparatorSource[] = unsupportedSources().map((entry) => ({
      id: entry.id,
      resolve: async () => {
        resolved += 1;
        return { availability: "unsupported", notes: ["unused"] };
      },
    }));
    const code = await main({
      argv: [],
      env: {},
      fetchImpl: async () => {
        throw new Error("should not fetch");
      },
      stdout: (chunk) => {
        stdout += chunk;
      },
      stderr: (chunk) => {
        stderr += chunk;
      },
      dataDir: dir,
      sources,
    });
    expect(code).toBe(1);
    expect(resolved).toBe(0);
    expect(stdout).toBe("");
    expect(stderr.length).toBeGreaterThan(0);
  });

  it("rejects unknown arguments", async () => {
    let stderr = "";
    const code = await main({
      argv: ["--regenerate"],
      env: {},
      fetchImpl: async () => {
        throw new Error("should not fetch");
      },
      stdout: () => {},
      stderr: (chunk) => {
        stderr += chunk;
      },
    });
    expect(code).toBe(1);
    expect(stderr).toContain("unknown argument");
  });
});
