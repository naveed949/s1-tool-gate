import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { NON_CLAIMS, REPORT_SCHEMA_VERSION } from "./types.js";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

describe("demo language", () => {
  it("carries the prove non-claims on the report and in the schema", () => {
    expect([...NON_CLAIMS]).toEqual([
      "Nimble score ≠ gate held",
      "high noul ≠ safe",
      "this is not AdaptiveSandbox",
      "this is not open Jev",
    ]);
    const schema = JSON.parse(readFileSync(path.join(ROOT, "schema/report.schema.json"), "utf8")) as {
      properties: { schemaVersion: { const: string }; nonClaims: { prefixItems: { const: string }[] } };
    };
    expect(schema.properties.schemaVersion.const).toBe(REPORT_SCHEMA_VERSION);
    expect(schema.properties.nonClaims.prefixItems.map((item) => item.const)).toEqual([...NON_CLAIMS]);
  });
});
