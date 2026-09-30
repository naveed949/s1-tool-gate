import path from "node:path";
import { pathToFileURL } from "node:url";

import { createDefaultSources } from "./comparators.js";
import { verifyPinnedDataset } from "./dataset.js";
import { exitCodeForReport, runHarness } from "./harness.js";
import { MANIFEST_SCHEMA_VERSION, type ComparatorSource } from "./types.js";

export interface MainOptions {
  argv: readonly string[];
  env: NodeJS.ProcessEnv;
  fetchImpl: typeof fetch;
  stdout: (chunk: string) => void;
  stderr: (chunk: string) => void;
  now?: () => Date;
  dataDir?: string;
  sources?: readonly ComparatorSource[];
}

export async function main(options: MainOptions): Promise<number> {
  const unknown = options.argv.filter((arg) => arg !== "run" && arg !== "verify");
  if (unknown.length > 0) {
    options.stderr(`unknown argument ${unknown[0] ?? ""}\n`);
    return 1;
  }
  if (options.argv.includes("verify")) {
    return verifyCommand(options);
  }
  return runCommand(options);
}

function verifyCommand(options: MainOptions): number {
  const verified = verifyPinnedDataset(options.dataDir);
  if (!verified.ok) {
    options.stderr(`${verified.errors.join("\n")}\n`);
    options.stdout(
      `${JSON.stringify({ schemaVersion: MANIFEST_SCHEMA_VERSION, status: "failed", checked: "sha256", errors: verified.errors }, null, 2)}\n`,
    );
    return 1;
  }
  options.stdout(
    `${JSON.stringify(
      {
        schemaVersion: MANIFEST_SCHEMA_VERSION,
        status: "ok",
        checked: "sha256",
        datasetId: verified.dataset.id,
        sha256: verified.dataset.sha256,
        bytes: verified.dataset.bytes,
        pairCount: verified.dataset.pairs.length,
      },
      null,
      2,
    )}\n`,
  );
  return 0;
}

async function runCommand(options: MainOptions): Promise<number> {
  const verified = verifyPinnedDataset(options.dataDir);
  if (!verified.ok) {
    options.stderr(`${verified.errors.join("\n")}\n`);
    return 1;
  }
  const sources =
    options.sources ??
    createDefaultSources({
      env: options.env,
      fetchImpl: options.fetchImpl,
    });
  try {
    const report = await runHarness({
      dataset: verified.dataset,
      sources,
      ...(options.now ? { now: options.now } : {}),
    });
    options.stdout(`${JSON.stringify(report, null, 2)}\n`);
    return exitCodeForReport(report);
  } catch (error) {
    const message = error instanceof Error ? error.message : "harness failed";
    options.stderr(`${message}\n`);
    return 1;
  }
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (!entry) {
    return false;
  }
  return import.meta.url === pathToFileURL(path.resolve(entry)).href;
}

if (isDirectRun()) {
  void main({
    argv: process.argv.slice(2),
    env: process.env,
    fetchImpl: globalThis.fetch,
    stdout: (chunk) => {
      process.stdout.write(chunk);
    },
    stderr: (chunk) => {
      process.stderr.write(chunk);
    },
  }).then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      const message = error instanceof Error ? error.message : "harness failed";
      process.stderr.write(`${message}\n`);
      process.exitCode = 1;
    },
  );
}
