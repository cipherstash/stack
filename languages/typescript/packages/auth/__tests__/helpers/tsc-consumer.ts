// Type-check a throwaway consumer project against this package, the way a
// real consumer's `tsc` would. vitest erases type-only imports and never runs
// `tsc`, so a broken declaration file compiles green through every runtime
// test; the suites that guard the public type surface
// (`consumer-typecheck.test.ts`, `start.test.ts`) drive this instead.

import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/** The package under test (`languages/typescript/packages/auth`). */
export const packageDir = join(__dirname, '..', '..')

// Run the locally-installed tsc as a script under the current node, so this is
// cross-platform (no shell, no `.bin` shim) and pinned to the devDependency.
const tscBin = require.resolve('typescript/bin/tsc')

const scratchDirs: string[] = []

/** A fresh temp directory, removed by {@link removeScratchDirs}. */
export function scratchDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  scratchDirs.push(dir)
  return dir
}

/** Remove every directory {@link scratchDir} handed out. Call from `afterAll`. */
export function removeScratchDirs(): void {
  for (const dir of scratchDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true })
  }
}

/**
 * Write `tsconfig` into `dir` and run tsc over it. Returns whether tsc
 * accepted the project and its combined output.
 */
export function runTsc(
  dir: string,
  tsconfig: object,
): { ok: boolean; output: string } {
  writeFileSync(join(dir, 'tsconfig.json'), JSON.stringify(tsconfig))
  try {
    const output = execFileSync(
      process.execPath,
      [tscBin, '-p', join(dir, 'tsconfig.json')],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    )
    return { ok: true, output }
  } catch (err) {
    const e = err as { stdout?: Buffer | string; stderr?: Buffer | string }
    return { ok: false, output: `${e.stdout ?? ''}${e.stderr ?? ''}` }
  }
}

/** The file list `npm pack` would publish for this package. */
export function packedFiles(): string[] {
  const out = execFileSync('npm', ['pack', '--json', '--dry-run'], {
    cwd: packageDir,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  return (
    JSON.parse(out) as Array<{ files: Array<{ path: string }> }>
  )[0].files.map((f) => f.path)
}
