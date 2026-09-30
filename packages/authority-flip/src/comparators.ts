import { requestJson } from "./http.js";
import {
  parseChoiceScore,
  parseNimbleScore,
  readFrontierContent,
  readOllamaChatContent,
} from "./parse.js";
import { buildChatPrompt, CHAT_SYSTEM, nimbleRequest } from "./prompt.js";
import type { AuthorityCase, ComparatorSource, ModelScore } from "./types.js";

export class ComparatorConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ComparatorConfigError";
  }
}

export interface AdapterOptions {
  env: NodeJS.ProcessEnv;
  fetchImpl: typeof fetch;
  timeoutMs?: number;
}

const DEFAULT_OLLAMA = "http://127.0.0.1:11434";
const DEFAULT_JUDGE_URL = "https://api.openai.com/v1";
const DEFAULT_JUDGE_MODEL = "gpt-4.1";
const DEFAULT_NIMBLE_MODEL = "nimble";
const DEFAULT_QWEN_MODEL = "qwen2.5:7b";
const DEFAULT_TIMEOUT_MS = 30_000;

export function ollamaBaseUrl(env: NodeJS.ProcessEnv): string {
  const explicit = env.AUTHORITY_FLIP_OLLAMA_BASE_URL?.trim();
  const raw = explicit || env.OLLAMA_HOST?.trim() || DEFAULT_OLLAMA;
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  return withScheme.replace(/\/+$/, "");
}

export function readTimeoutMs(env: NodeJS.ProcessEnv): number | null {
  const raw = env.AUTHORITY_FLIP_TIMEOUT_MS;
  if (raw === undefined || raw.trim() === "") {
    return DEFAULT_TIMEOUT_MS;
  }
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    return null;
  }
  return value;
}

/** `nimble` matches `nimble:latest`. `qwen2.5:7b` does not match `qwen2.5:latest`. */
export function ollamaModelPresent(installed: readonly string[], requested: string): boolean {
  return installed.some((name) => name === requested || name.split(":")[0] === requested);
}

export function createDefaultSources(options: AdapterOptions): ComparatorSource[] {
  const timeoutMs = options.timeoutMs === undefined ? readTimeoutMs(options.env) : options.timeoutMs;
  const baseUrl = ollamaBaseUrl(options.env);
  const probe = createProbe(baseUrl, options.fetchImpl, timeoutMs);
  const nimbleModel = options.env.AUTHORITY_FLIP_NIMBLE_MODEL?.trim() || DEFAULT_NIMBLE_MODEL;
  const qwenModel = options.env.AUTHORITY_FLIP_QWEN_MODEL?.trim() || DEFAULT_QWEN_MODEL;
  return [
    ollamaChoiceSource({
      id: "nimble-ollama",
      baseUrl,
      model: nimbleModel,
      timeoutMs,
      probe,
      score: (item) => scoreNimble(options.fetchImpl, baseUrl, nimbleModel, timeoutMs, item),
    }),
    ollamaChoiceSource({
      id: "base-qwen",
      baseUrl,
      model: qwenModel,
      timeoutMs,
      probe,
      score: (item) => scoreQwen(options.fetchImpl, baseUrl, qwenModel, timeoutMs, item),
    }),
    frontierSource(options.env, options.fetchImpl, timeoutMs),
  ];
}

type Probe = { kind: "up"; models: string[] } | { kind: "down"; note: string };

function createProbe(baseUrl: string, fetchImpl: typeof fetch, timeoutMs: number | null): () => Promise<Probe> {
  let pending: Promise<Probe> | undefined;
  return () => {
    pending ??= probeOllama(baseUrl, fetchImpl, timeoutMs);
    return pending;
  };
}

async function probeOllama(baseUrl: string, fetchImpl: typeof fetch, timeoutMs: number | null): Promise<Probe> {
  if (timeoutMs === null) {
    return { kind: "down", note: "AUTHORITY_FLIP_TIMEOUT_MS is not a positive number" };
  }
  try {
    const result = await requestJson(fetchImpl, `${baseUrl}/api/tags`, { method: "GET", timeoutMs });
    const models = readModelNames(result.body);
    if (models === null) {
      return { kind: "down", note: `Ollama is unavailable at ${baseUrl} (unusable tags response)` };
    }
    return { kind: "up", models };
  } catch (error) {
    const reason = error instanceof Error ? error.message : "request failed";
    return { kind: "down", note: `Ollama is unavailable at ${baseUrl} (${reason})` };
  }
}

function ollamaChoiceSource(options: {
  id: "nimble-ollama" | "base-qwen";
  baseUrl: string;
  model: string;
  timeoutMs: number | null;
  probe: () => Promise<Probe>;
  score: (item: AuthorityCase) => Promise<ModelScore>;
}): ComparatorSource {
  return {
    id: options.id,
    async resolve() {
      requireTimeout(options.timeoutMs);
      const probe = await options.probe();
      if (probe.kind === "down") {
        return { availability: "unsupported", notes: [probe.note] };
      }
      if (!ollamaModelPresent(probe.models, options.model)) {
        return {
          availability: "unsupported",
          notes: [`Ollama at ${options.baseUrl} does not have model ${options.model}`],
        };
      }
      return {
        availability: "ready",
        notes: [`ollama=${options.baseUrl}`, `model=${options.model}`],
        score: options.score,
      };
    },
  };
}

function frontierSource(env: NodeJS.ProcessEnv, fetchImpl: typeof fetch, timeoutMs: number | null): ComparatorSource {
  return {
    id: "frontier-judge",
    async resolve() {
      const apiKey = env.AUTHORITY_FLIP_JUDGE_API_KEY?.trim() ?? "";
      if (apiKey === "") {
        return { availability: "unsupported", notes: ["AUTHORITY_FLIP_JUDGE_API_KEY is not set"] };
      }
      const readyTimeout = requireTimeout(timeoutMs);
      const baseUrl = (env.AUTHORITY_FLIP_JUDGE_BASE_URL?.trim() || DEFAULT_JUDGE_URL).replace(/\/+$/, "");
      const model = env.AUTHORITY_FLIP_JUDGE_MODEL?.trim() || DEFAULT_JUDGE_MODEL;
      return {
        availability: "ready",
        notes: [`endpoint=${baseUrl}`, `model=${model}`],
        score: (item) => scoreFrontier(fetchImpl, baseUrl, apiKey, model, readyTimeout, item),
      };
    },
  };
}

function requireTimeout(timeoutMs: number | null): number {
  if (timeoutMs === null || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new ComparatorConfigError("AUTHORITY_FLIP_TIMEOUT_MS is not a positive number");
  }
  return timeoutMs;
}

async function scoreNimble(
  fetchImpl: typeof fetch,
  baseUrl: string,
  model: string,
  timeoutMs: number | null,
  item: AuthorityCase,
): Promise<ModelScore> {
  const result = await requestJson(fetchImpl, `${baseUrl}/v1/systemone`, {
    method: "POST",
    timeoutMs: requireTimeout(timeoutMs),
    body: nimbleRequest(model, item),
  });
  return parseNimbleScore(result.body);
}

async function scoreQwen(
  fetchImpl: typeof fetch,
  baseUrl: string,
  model: string,
  timeoutMs: number | null,
  item: AuthorityCase,
): Promise<ModelScore> {
  const result = await requestJson(fetchImpl, `${baseUrl}/api/chat`, {
    method: "POST",
    timeoutMs: requireTimeout(timeoutMs),
    body: {
      model,
      stream: false,
      format: "json",
      options: { temperature: 0 },
      messages: [
        { role: "system", content: CHAT_SYSTEM },
        { role: "user", content: buildChatPrompt(item) },
      ],
    },
  });
  return parseChoiceScore(readOllamaChatContent(result.body));
}

async function scoreFrontier(
  fetchImpl: typeof fetch,
  baseUrl: string,
  apiKey: string,
  model: string,
  timeoutMs: number,
  item: AuthorityCase,
): Promise<ModelScore> {
  const result = await requestJson(fetchImpl, `${baseUrl}/chat/completions`, {
    method: "POST",
    timeoutMs,
    headers: { authorization: `Bearer ${apiKey}` },
    body: {
      model,
      temperature: 0,
      messages: [
        { role: "system", content: CHAT_SYSTEM },
        { role: "user", content: buildChatPrompt(item) },
      ],
    },
  });
  return parseChoiceScore(readFrontierContent(result.body));
}

function readModelNames(body: unknown): string[] | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return null;
  }
  const models = (body as { models?: unknown }).models;
  if (!Array.isArray(models)) {
    return null;
  }
  const names: string[] = [];
  for (const item of models) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      return null;
    }
    const name = (item as { name?: unknown }).name;
    if (typeof name !== "string" || name.length === 0) {
      return null;
    }
    names.push(name);
  }
  return names;
}
