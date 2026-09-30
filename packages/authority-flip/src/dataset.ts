import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  CHOICES,
  MANIFEST_SCHEMA_VERSION,
  PINNED_PAIRS_FILE,
  type Choice,
  type Dataset,
  type Pair,
  type Side,
} from "./types.js";

const PAIR_KEYS = ["id", "domain", "tool", "fact", "flip", "base", "flipped"] as const;
const SIDE_KEYS = ["policy", "args", "context", "gold"] as const;
const MANIFEST_KEYS = [
  "schemaVersion",
  "datasetId",
  "description",
  "algorithm",
  "pairsFile",
  "sha256",
  "bytes",
  "pairCount",
  "pairIds",
] as const;
const ARG_KEY = /^[a-z][a-z0-9_]*$/;
const PAIR_ID = /^af-[0-9]{3}$/;

export class DatasetError extends Error {
  readonly errors: string[];

  constructor(errors: string[]) {
    super(errors.join("\n"));
    this.name = "DatasetError";
    this.errors = errors;
  }
}

export function defaultDataDir(): string {
  return fileURLToPath(new URL("../data/", import.meta.url));
}

export function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function parsePairs(text: string): Pair[] {
  const errors: string[] = [];
  const pairs = collectPairs(text, errors);
  if (errors.length > 0 || pairs === null) {
    throw new DatasetError(errors.length > 0 ? errors : ["pairs.jsonl could not be parsed"]);
  }
  return pairs;
}

export function verifyPinnedDataset(dataDir: string = defaultDataDir()):
  | { ok: true; dataset: Dataset }
  | { ok: false; errors: string[] } {
  const errors: string[] = [];
  const manifestPath = path.join(dataDir, "manifest.json");
  const pairsPath = path.join(dataDir, "pairs.jsonl");
  const manifestBytes = readOptional(manifestPath, errors);
  const pairBytes = readOptional(pairsPath, errors);
  if (manifestBytes === null || pairBytes === null) {
    return { ok: false, errors };
  }

  const manifest = parseManifest(manifestBytes, errors);
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(pairBytes);
  } catch {
    errors.push("pairs.jsonl is not valid UTF-8");
    return { ok: false, errors };
  }

  const digest = sha256Hex(pairBytes);
  if (manifest && manifest.sha256 !== digest) {
    errors.push(`sha256 mismatch for pairs.jsonl: manifest ${manifest.sha256} computed ${digest}`);
  }
  if (manifest && manifest.bytes !== pairBytes.length) {
    errors.push(`byte length mismatch for pairs.jsonl: manifest ${manifest.bytes} computed ${pairBytes.length}`);
  }

  const pairs = collectPairs(text, errors);
  if (manifest && pairs) {
    if (manifest.pairCount !== pairs.length) {
      errors.push(`pairCount mismatch: manifest ${manifest.pairCount} computed ${pairs.length}`);
    }
    const ids = pairs.map((pair) => pair.id);
    if (manifest.pairIds.length !== ids.length || manifest.pairIds.some((id, index) => id !== ids[index])) {
      errors.push("manifest pairIds do not match pairs.jsonl order");
    }
  }

  if (!manifest || !pairs || errors.length > 0) {
    return { ok: false, errors };
  }

  return {
    ok: true,
    dataset: {
      id: manifest.datasetId,
      pairsFile: PINNED_PAIRS_FILE,
      sha256: digest,
      bytes: pairBytes.length,
      pairs,
    },
  };
}

interface Manifest {
  datasetId: string;
  sha256: string;
  bytes: number;
  pairCount: number;
  pairIds: string[];
}

function readOptional(file: string, errors: string[]): Buffer | null {
  try {
    return readFileSync(file);
  } catch {
    errors.push(`missing file ${path.basename(file)}`);
    return null;
  }
}

function parseManifest(bytes: Buffer, errors: string[]): Manifest | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    errors.push("manifest.json is not valid UTF-8");
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    errors.push("manifest.json is not JSON");
    return null;
  }
  if (!isRecord(parsed) || !exactKeys(parsed, MANIFEST_KEYS)) {
    errors.push("manifest.json keys are not the pinned manifest schema");
    return null;
  }
  if (parsed.schemaVersion !== MANIFEST_SCHEMA_VERSION) {
    errors.push(`manifest schemaVersion must be ${MANIFEST_SCHEMA_VERSION}`);
  }
  if (typeof parsed.datasetId !== "string" || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(parsed.datasetId)) {
    errors.push("manifest datasetId is invalid");
  }
  if (typeof parsed.description !== "string" || parsed.description.trim() === "") {
    errors.push("manifest description is empty");
  }
  if (parsed.algorithm !== "sha256") {
    errors.push("manifest algorithm must be sha256");
  }
  if (parsed.pairsFile !== "pairs.jsonl") {
    errors.push("manifest pairsFile must be pairs.jsonl");
  }
  if (typeof parsed.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(parsed.sha256)) {
    errors.push("manifest sha256 is invalid");
  }
  if (typeof parsed.bytes !== "number" || !Number.isInteger(parsed.bytes) || parsed.bytes < 0) {
    errors.push("manifest bytes is invalid");
  }
  if (typeof parsed.pairCount !== "number" || !Number.isInteger(parsed.pairCount) || parsed.pairCount < 1) {
    errors.push("manifest pairCount is invalid");
  }
  if (!Array.isArray(parsed.pairIds) || parsed.pairIds.some((id) => typeof id !== "string")) {
    errors.push("manifest pairIds is invalid");
  }
  if (errors.length > 0) {
    return null;
  }
  return {
    datasetId: parsed.datasetId as string,
    sha256: parsed.sha256 as string,
    bytes: parsed.bytes as number,
    pairCount: parsed.pairCount as number,
    pairIds: parsed.pairIds as string[],
  };
}

function collectPairs(text: string, errors: string[]): Pair[] | null {
  if (text.includes("\r")) {
    errors.push("pairs.jsonl must use LF line endings");
    return null;
  }
  if (!text.endsWith("\n")) {
    errors.push("pairs.jsonl must end with a newline");
    return null;
  }
  if (text.endsWith("\n\n")) {
    errors.push("pairs.jsonl must not end with a blank line");
  }
  const body = text.slice(0, -1);
  if (body.length === 0) {
    errors.push("pairs.jsonl has no pairs");
    return null;
  }
  const lines = body.split("\n");
  const pairs: Pair[] = [];
  const seen = new Set<string>();
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const where = `pairs.jsonl line ${index + 1}`;
    if (line === undefined || line.length === 0) {
      errors.push(`${where} is blank`);
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(line) as unknown;
    } catch {
      errors.push(`${where} is not JSON`);
      continue;
    }
    const pair = validatePair(parsed, where, errors);
    if (!pair) {
      continue;
    }
    if (seen.has(pair.id)) {
      errors.push(`${where} repeats id ${pair.id}`);
      continue;
    }
    seen.add(pair.id);
    pairs.push(pair);
  }
  if (pairs.length === 0) {
    errors.push("pairs.jsonl has no valid pairs");
    return null;
  }
  if (errors.length > 0) {
    return null;
  }
  return pairs;
}

function validatePair(value: unknown, where: string, errors: string[]): Pair | null {
  const before = errors.length;
  if (!isRecord(value) || !exactKeys(value, PAIR_KEYS)) {
    errors.push(`${where} keys must be ${PAIR_KEYS.join(", ")}`);
    return null;
  }
  const id = typeof value.id === "string" && PAIR_ID.test(value.id) ? value.id : null;
  const label = id ?? where;
  if (id === null) {
    errors.push(`${where} id must match af-000`);
  }
  if (value.domain !== "agent-authority") {
    errors.push(`${label} domain must be agent-authority`);
  }
  if (typeof value.tool !== "string" || value.tool.trim() === "") {
    errors.push(`${label} tool must be a non-empty string`);
  }
  if (typeof value.fact !== "string" || value.fact.trim() === "") {
    errors.push(`${label} fact must be a non-empty string`);
  }
  if (typeof value.flip !== "string") {
    errors.push(`${label} flip must be a string`);
  }
  const base = validateSide(value.base, `${label} base`, errors);
  const flipped = validateSide(value.flipped, `${label} flipped`, errors);
  if (!base || !flipped || typeof value.tool !== "string" || typeof value.fact !== "string" || typeof value.flip !== "string" || id === null) {
    return null;
  }
  if (base.gold === flipped.gold) {
    errors.push(`${label} gold labels must differ`);
    return null;
  }
  const expectedFlip = `${base.gold}-${flipped.gold}`;
  if (value.flip !== expectedFlip) {
    errors.push(`${label} flip must be ${expectedFlip}`);
  }
  const argKeys = Object.keys(base.args);
  const flippedKeys = Object.keys(flipped.args);
  if (argKeys.length !== flippedKeys.length || argKeys.some((key, index) => key !== flippedKeys[index])) {
    errors.push(`${label} args keys differ between sides`);
    return null;
  }
  const changed = changedFacts(base, flipped);
  if (changed.length !== 1) {
    errors.push(`${label} must change exactly one fact, changed ${changed.join(", ") || "nothing"}`);
    return null;
  }
  if (value.fact !== changed[0]) {
    errors.push(`${label} fact is ${value.fact}, the changed fact is ${changed[0]}`);
  }
  if (errors.length > before) {
    return null;
  }
  return {
    id,
    domain: "agent-authority",
    tool: value.tool,
    fact: value.fact,
    flip: value.flip,
    base,
    flipped,
  };
}

function validateSide(value: unknown, where: string, errors: string[]): Side | null {
  if (!isRecord(value) || !exactKeys(value, SIDE_KEYS)) {
    errors.push(`${where} keys must be ${SIDE_KEYS.join(", ")}`);
    return null;
  }
  if (typeof value.policy !== "string" || value.policy.trim() === "") {
    errors.push(`${where} policy must be a non-empty string`);
  }
  if (typeof value.context !== "string" || value.context.trim() === "") {
    errors.push(`${where} context must be a non-empty string`);
  }
  if (!isChoice(value.gold)) {
    errors.push(`${where} gold must be allow, deny, or escalate`);
  }
  if (!isRecord(value.args)) {
    errors.push(`${where} args must be an object of strings`);
    return null;
  }
  const args: Record<string, string> = {};
  for (const [key, arg] of Object.entries(value.args)) {
    if (!ARG_KEY.test(key)) {
      errors.push(`${where} arg key ${key} is invalid`);
      continue;
    }
    if (typeof arg !== "string" || arg.length === 0) {
      errors.push(`${where} arg ${key} must be a non-empty string`);
      continue;
    }
    args[key] = arg;
  }
  if (typeof value.policy !== "string" || typeof value.context !== "string" || !isChoice(value.gold)) {
    return null;
  }
  if (Object.keys(args).length !== Object.keys(value.args).length) {
    return null;
  }
  return { policy: value.policy, args, context: value.context, gold: value.gold };
}

function changedFacts(base: Side, flipped: Side): string[] {
  const changed: string[] = [];
  if (base.policy !== flipped.policy) {
    changed.push("policy");
  }
  if (base.context !== flipped.context) {
    changed.push("context");
  }
  for (const key of Object.keys(base.args)) {
    if (base.args[key] !== flipped.args[key]) {
      changed.push(`args.${key}`);
    }
  }
  return changed;
}

function isChoice(value: unknown): value is Choice {
  return typeof value === "string" && (CHOICES as readonly string[]).includes(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
