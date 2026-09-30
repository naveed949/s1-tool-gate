/**
 * Point the flip harness at the same local Ollama the gate client uses.
 *
 * `createDefaultSources` reads `AUTHORITY_FLIP_OLLAMA_BASE_URL` and
 * `AUTHORITY_FLIP_NIMBLE_MODEL`. The demo's documented variables are
 * `TYPESAFE_BASE_URL` and `TYPESAFE_DEFAULT_MODEL`. When the flip-specific
 * variable is unset, the TypeSafe variable is copied into the env passed to
 * the harness. An explicit flip variable is left alone.
 */
export function envForFlip(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const next: NodeJS.ProcessEnv = { ...env };
  const flipBase = env.AUTHORITY_FLIP_OLLAMA_BASE_URL?.trim();
  const typesafeBase = env.TYPESAFE_BASE_URL?.trim();
  if (!flipBase && typesafeBase) {
    next.AUTHORITY_FLIP_OLLAMA_BASE_URL = typesafeBase;
  }
  const flipModel = env.AUTHORITY_FLIP_NIMBLE_MODEL?.trim();
  const typesafeModel = env.TYPESAFE_DEFAULT_MODEL?.trim();
  if (!flipModel && typesafeModel) {
    next.AUTHORITY_FLIP_NIMBLE_MODEL = typesafeModel;
  }
  return next;
}
