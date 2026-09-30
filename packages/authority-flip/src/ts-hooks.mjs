// Node's type stripper does not map TypeScript's `.js` specifiers onto `.ts` files.
export async function resolve(specifier, context, nextResolve) {
  if (specifier.startsWith(".") && specifier.endsWith(".js")) {
    try {
      return await nextResolve(`${specifier.slice(0, -3)}.ts`, context);
    } catch {
      // The specifier is a real `.js` file, not a TypeScript path.
      return nextResolve(specifier, context);
    }
  }
  return nextResolve(specifier, context);
}
