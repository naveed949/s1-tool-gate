import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { defaultDataDir, parsePairs, sha256Hex, verifyPinnedDataset } from "./dataset.js";

const dataDir = defaultDataDir();

describe("pinned authority pairs", () => {
  it("matches the manifest hash and the one-fact rules", () => {
    const verified = verifyPinnedDataset(dataDir);
    expect(verified.ok).toBe(true);
    if (!verified.ok) {
      return;
    }
    const bytes = readFileSync(path.join(dataDir, "pairs.jsonl"));
    expect(verified.dataset.sha256).toBe(sha256Hex(bytes));
    expect(verified.dataset.bytes).toBe(bytes.length);
    expect(verified.dataset.pairs).toHaveLength(16);
    expect(verified.dataset.id).toBe("agent-authority-one-fact-v1");
    expect(verified.dataset.pairsFile).toBe("packages/authority-flip/data/pairs.jsonl");
    expect(sha256Hex(Buffer.concat([bytes, Buffer.from(" ")])).length).toBe(64);
    expect(sha256Hex(Buffer.concat([bytes, Buffer.from(" ")]))).not.toBe(verified.dataset.sha256);

    const flips = new Set(verified.dataset.pairs.map((pair) => pair.flip));
    expect(flips.has("allow-deny")).toBe(true);
    expect(flips.has("deny-allow")).toBe(true);
    expect(flips.has("allow-escalate")).toBe(true);
    expect(flips.has("deny-escalate")).toBe(true);
    expect(flips.has("escalate-allow")).toBe(true);
    for (const pair of verified.dataset.pairs) {
      expect(pair.domain).toBe("agent-authority");
      expect(pair.base.gold).not.toBe(pair.flipped.gold);
    }
  });

  it("fails closed when the pair bytes change", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "authority-flip-"));
    const original = readFileSync(path.join(dataDir, "pairs.jsonl"));
    const tampered = Buffer.from(original);
    tampered[0] = tampered[0] === 123 ? 124 : 123;
    writeFileSync(path.join(dir, "pairs.jsonl"), tampered);
    writeFileSync(path.join(dir, "manifest.json"), readFileSync(path.join(dataDir, "manifest.json")));
    const verified = verifyPinnedDataset(dir);
    expect(verified.ok).toBe(false);
    if (verified.ok) {
      return;
    }
    expect(verified.errors.some((error) => error.includes("sha256 mismatch"))).toBe(true);
  });

  it("rejects a pair that changes two facts", () => {
    const first = readFileSync(path.join(dataDir, "pairs.jsonl"), "utf8").split("\n")[0] ?? "";
    const pair = JSON.parse(first) as { flipped: { policy: string } };
    pair.flipped.policy = "A second fact was changed.";
    expect(() => parsePairs(`${JSON.stringify(pair)}\n`)).toThrow(/exactly one fact/);
  });

  it("rejects identical gold labels and CR LF", () => {
    const first = readFileSync(path.join(dataDir, "pairs.jsonl"), "utf8").split("\n")[0] ?? "";
    const pair = JSON.parse(first) as { flipped: { gold: string }; flip: string };
    pair.flipped.gold = "allow";
    pair.flip = "allow-allow";
    expect(() => parsePairs(`${JSON.stringify(pair)}\n`)).toThrow(/gold labels must differ/);
    expect(() => parsePairs(`${first}\r\n`)).toThrow(/LF/);
  });
});

describe("report schema", () => {
  it("names the three statuses and keeps metrics null unless ok", () => {
    const schemaPath = fileURLToPath(new URL("../schema/report.schema.json", import.meta.url));
    const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as { $id: string };
    const text = JSON.stringify(schema);
    expect(schema.$id).toContain("report.schema.json");
    expect(text).toContain("unsupported");
    expect(text).toContain("failed");
    expect(text).toContain('"const":"ok"');
    expect(text).toContain('"type":"null"');
  });
});
