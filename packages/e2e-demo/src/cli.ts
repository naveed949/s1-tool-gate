import path from "node:path";
import { pathToFileURL } from "node:url";

import { verifyPinnedDataset } from "../../authority-flip/src/dataset.js";
import type { Dataset, FlipReport } from "../../authority-flip/src/types.js";
import { repoRoot, runPythonGatePath } from "./gate-path.js";
import { failedFlipReport, runFlipPath } from "./flip-path.js";
import { exitCodeForDemo, runDemo } from "./run.js";
import type { GateCase, GatePathResult } from "./types.js";

export interface MainOptions {
  env: NodeJS.ProcessEnv;
  fetchImpl: typeof fetch;
  stdout: (chunk: string) => void;
  stderr: (chunk: string) => void;
  now?: () => Date;
  dataDir?: string;
  root?: string;
  python?: string;
  runGatePath?: (cases: readonly GateCase[]) => Promise<GatePathResult>;
  runFlip?: (dataset: Dataset) => Promise<FlipReport>;
}

export async function main(options: MainOptions): Promise<number> {
  const verified = verifyPinnedDataset(options.dataDir);
  if (!verified.ok) {
    options.stderr(`${verified.errors.join("\n")}\n`);
    return 1;
  }
  const now = options.now ?? (() => new Date());
  const root = options.root ?? repoRoot();
  const dataset = verified.dataset;
  const runGatePath =
    options.runGatePath ??
    ((cases: readonly GateCase[]) =>
      runPythonGatePath(cases, {
        root,
        ...(options.python ? { python: options.python } : {}),
        env: options.env,
      }));
  const runFlip =
    options.runFlip ??
    ((current: Dataset) =>
      runFlipPath({
        dataset: current,
        env: options.env,
        fetchImpl: options.fetchImpl,
        now,
      }));

  const gateRunner = async (cases: readonly GateCase[]) => {
    try {
      return await runGatePath(cases);
    } catch (error) {
      const message = error instanceof Error ? error.message : "gate path failed";
      return { status: "failed" as const, notes: [message], decisions: [], observations: [] };
    }
  };
  const flipRunner = async (current: Dataset) => {
    try {
      return await runFlip(current);
    } catch (error) {
      const message = error instanceof Error ? error.message : "flip path failed";
      return failedFlipReport(current, message, now());
    }
  };

  try {
    const report = await runDemo({
      dataset,
      runGatePath: gateRunner,
      runFlip: flipRunner,
      now,
    });
    options.stdout(`${JSON.stringify(report, null, 2)}\n`);
    return exitCodeForDemo(report);
  } catch (error) {
    const message = error instanceof Error ? error.message : "demo failed";
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
      const message = error instanceof Error ? error.message : "demo failed";
      process.stderr.write(`${message}\n`);
      process.exitCode = 1;
    },
  );
}
