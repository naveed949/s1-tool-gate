import { CHOICES, type Choice, type ModelScore } from "./types.js";

/** Probabilities may miss 1 by this much and still be accepted. They are not renormalized. */
export const PROB_SUM_TOLERANCE = 0.02;

export class ScoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScoreError";
  }
}

export function parseNimbleScore(body: unknown): ModelScore {
  if (!isRecord(body) || !isRecord(body.answers)) {
    throw new ScoreError("Nimble response has no answers");
  }
  const answer = body.answers.authority;
  if (!isRecord(answer)) {
    throw new ScoreError("Nimble response has no authority answer");
  }
  return parseChoiceFields(answer.choice, answer.probabilities);
}

export function parseChoiceScore(text: string): ModelScore {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) {
    throw new ScoreError("response did not contain a JSON object");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.slice(start, end + 1)) as unknown;
  } catch {
    throw new ScoreError("response JSON could not be parsed");
  }
  if (!isRecord(parsed)) {
    throw new ScoreError("response JSON was not an object");
  }
  return parseChoiceFields(parsed.choice, parsed.probs);
}

export function parseChoiceFields(choice: unknown, probs: unknown): ModelScore {
  if (!isChoice(choice)) {
    throw new ScoreError("choice must be allow, deny, or escalate");
  }
  if (!isRecord(probs)) {
    throw new ScoreError("probs must be an object");
  }
  const extra = Object.keys(probs).filter((key) => !isChoice(key));
  if (extra.length > 0) {
    throw new ScoreError("probs has unknown labels");
  }
  const parsed = {} as Record<Choice, number>;
  let sum = 0;
  for (const label of CHOICES) {
    const value = probs[label];
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
      throw new ScoreError(`prob for ${label} must be a finite number from 0 to 1`);
    }
    parsed[label] = value;
    sum += value;
  }
  // Inclusive bound. 0.34 + 0.34 + 0.34 is 1.02 plus a rounding ulp, and that still counts.
  if (Math.abs(sum - 1) > PROB_SUM_TOLERANCE + 1e-9) {
    throw new ScoreError(`probs sum to ${sum}, expected 1`);
  }
  return { choice, probs: parsed };
}

export function readOllamaChatContent(body: unknown): string {
  if (!isRecord(body) || !isRecord(body.message)) {
    throw new ScoreError("Ollama chat response has no message");
  }
  const content = body.message.content;
  if (typeof content === "string" && content.trim() !== "") {
    return content;
  }
  if (isRecord(content)) {
    return JSON.stringify(content);
  }
  throw new ScoreError("Ollama chat response content was empty");
}

export function readFrontierContent(body: unknown): string {
  if (!isRecord(body) || !Array.isArray(body.choices) || body.choices.length === 0) {
    throw new ScoreError("frontier response has no choices");
  }
  const first = body.choices[0];
  if (!isRecord(first) || !isRecord(first.message) || typeof first.message.content !== "string") {
    throw new ScoreError("frontier response has no message");
  }
  if (first.message.content.trim() === "") {
    throw new ScoreError("frontier response content was empty");
  }
  return first.message.content;
}

function isChoice(value: unknown): value is Choice {
  return typeof value === "string" && (CHOICES as readonly string[]).includes(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
