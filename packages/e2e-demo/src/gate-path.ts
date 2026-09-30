import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { GateCase, GatePathResult, GatePathStatus } from "./types.js";

export interface PythonGateOptions {
  root: string;
  python?: string;
  /** Defaults to `python -m e2e_demo`. Tests pass a stand-in script. */
  args?: readonly string[];
  env?: NodeJS.ProcessEnv;
}

const STATUSES: readonly GatePathStatus[] = ["ok", "unavailable", "failed"];

export function repoRoot(): string {
  return path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));
}

export function pythonPath(root: string, existing: string | undefined): string {
  const entries = [
    path.join(root, "packages/e2e-demo/python"),
    path.join(root, "packages/gate-client/src"),
    path.join(root, "packages/gate-enforcement/src"),
  ];
  if (existing && existing.trim() !== "") {
    entries.push(existing);
  }
  return entries.join(path.delimiter);
}

/**
 * Spawn `python -m e2e_demo` and parse its JSON.
 *
 * A non-zero exit, a missing interpreter, or unusable JSON becomes
 * `status: failed` with empty decision rows. That result is not a pass.
 */
export function runPythonGatePath(
  cases: readonly GateCase[],
  options: PythonGateOptions,
): Promise<GatePathResult> {
  const env = options.env ?? process.env;
  const python = options.python ?? env.E2E_DEMO_PYTHON ?? "python3";
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: GatePathResult) => {
      if (settled) {
        return;
      }
      settled = true;
      resolve(result);
    };
    const child = spawn(python, [...(options.args ?? ["-m", "e2e_demo"])], {
      cwd: options.root,
      env: {
        ...env,
        PYTHONPATH: pythonPath(options.root, env.PYTHONPATH),
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      finish(failedGate(error.message));
    });
    child.on("close", (code) => {
      if (code !== 0) {
        const detail = stderr.trim() || `e2e_demo exited ${code ?? "null"}`;
        finish(failedGate(truncate(detail)));
        return;
      }
      try {
        finish(parseGateOutput(stdout));
      } catch (error) {
        const message = error instanceof Error ? error.message : "invalid gate-path output";
        finish(failedGate(message));
      }
    });
    child.stdin.end(JSON.stringify({ cases }));
  });
}

export function parseGateOutput(stdout: string): GatePathResult {
  const parsed: unknown = JSON.parse(stdout);
  if (!parsed || typeof parsed !== "object") {
    throw new Error("gate-path output is not an object");
  }
  const body = parsed as Record<string, unknown>;
  const status = body.status;
  if (typeof status !== "string" || !STATUSES.includes(status as GatePathStatus)) {
    throw new Error("gate-path output has no status");
  }
  if (!Array.isArray(body.notes) || !body.notes.every((note) => typeof note === "string")) {
    throw new Error("gate-path output notes must be strings");
  }
  if (!Array.isArray(body.decisions) || !Array.isArray(body.observations)) {
    throw new Error("gate-path output is missing decisions or observations");
  }
  return {
    status: status as GatePathStatus,
    notes: body.notes as string[],
    decisions: body.decisions as GatePathResult["decisions"],
    observations: body.observations as GatePathResult["observations"],
  };
}

function failedGate(note: string): GatePathResult {
  return {
    status: "failed",
    notes: [note],
    decisions: [],
    observations: [],
  };
}

function truncate(text: string): string {
  const limit = 500;
  if (text.length <= limit) {
    return text;
  }
  return `${text.slice(0, limit)}…`;
}
