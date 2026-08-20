/** The crate's version, substituted at build time by vite.config.ts. */
declare const __VERSION__: string;

/**
 * The one Node function the build config uses, declared rather than
 * installed.
 *
 * `@types/node` is 2 MB of declarations for an API this project touches
 * once, in a file that never reaches the bundle. Naming the function we
 * actually call keeps the dependency list honest about what the app needs.
 */
declare module 'node:fs' {
  export function readFileSync(path: string, encoding: 'utf8'): string;
}
