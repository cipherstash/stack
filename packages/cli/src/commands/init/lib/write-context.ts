import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type {
  HandoffChoice,
  InitState,
  Integration,
  SchemaDef,
} from '../types.js'
import {
  type PackageManager,
  detectPackageManager,
  prodInstallCommand,
} from '../utils.js'
import type { PlanStep } from './parse-plan.js'
import { type SetupPromptContext, renderSetupPrompt } from './setup-prompt.js'

export const CONTEXT_REL_PATH = '.cipherstash/context.json'
export const SETUP_PROMPT_REL_PATH = '.cipherstash/setup-prompt.md'

export interface ContextFile {
  cliVersion: string
  integration: Integration
  encryptionClientPath: string
  packageManager: PackageManager
  installCommand: string
  envKeys: string[]
  /** Every encrypted-table schema written to the encryption client. The
   *  generated client file is still authoritative for column types and ops;
   *  this lets agents see the full set without parsing TypeScript. */
  schemas: SchemaDef[]
  /** Names of skills `stash init` copied into the project (e.g.
   *  `stash-encryption`, `stash-drizzle`, `stash-cli`). Empty for the
   *  AGENTS.md handoff (skill content is inlined into AGENTS.md instead)
   *  and for wizard (the wizard installs its own). */
  installedSkills: string[]
  /** Plan-step the CLI resolved at handoff time. Written by `stash plan`
   *  so the wizard handoff (and any other reader of this file) can pick
   *  up the same rollout/cutover/complete dispatch the prompt-driven
   *  handoffs use. Absent when the file was written by `stash init` or
   *  `stash impl` rather than `stash plan`. */
  planStep?: PlanStep
  generatedAt: string
}

/**
 * Walk up from this file to find the CLI's package.json. The compiled file
 * lives at `dist/index.js` (or similar) and the source at
 * `src/commands/init/lib/write-context.ts`, so we walk up to six levels.
 * Falling back to `'unknown'` is fine — the field is informational.
 *
 * Memoized: the answer is fixed for the lifetime of the process.
 */
let cliVersionCache: string | undefined

export function readCliVersion(): string {
  if (cliVersionCache !== undefined) return cliVersionCache
  let dir = dirname(fileURLToPath(import.meta.url))
  for (let i = 0; i < 6; i++) {
    const candidate = resolve(dir, 'package.json')
    if (existsSync(candidate)) {
      try {
        const pkg = JSON.parse(readFileSync(candidate, 'utf-8')) as {
          name?: string
          version?: string
        }
        if (pkg.name === 'stash' && pkg.version) {
          cliVersionCache = pkg.version
          return pkg.version
        }
      } catch {
        // keep walking
      }
    }
    dir = dirname(dir)
  }
  cliVersionCache = 'unknown'
  return cliVersionCache
}

function ensureDir(path: string): void {
  const dir = dirname(path)
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
}

/**
 * Build the universal `.cipherstash/context.json` from `InitState`.
 *
 * `schemas` is allowed to be empty — `stash init` no longer asks the user
 * which columns to encrypt, so there are no inferred schemas at init time.
 * The agent (or `stash encrypt` commands later) populates this when real
 * encrypted tables exist.
 */
export function buildContextFile(state: InitState): ContextFile {
  const integration = state.integration ?? 'postgresql'
  const clientFilePath = state.clientFilePath ?? './src/encryption/index.ts'
  const pm = detectPackageManager()
  return {
    cliVersion: readCliVersion(),
    integration,
    encryptionClientPath: clientFilePath,
    packageManager: pm,
    installCommand: prodInstallCommand(pm, '@cipherstash/stack'),
    envKeys: [],
    schemas: state.schemas ?? [],
    installedSkills: [],
    planStep: state.planStep,
    generatedAt: new Date().toISOString(),
  }
}

/**
 * Persist the context file to disk. The CLI owns this path; never call from
 * outside the init / handoff steps.
 */
export function writeContextFile(absPath: string, ctx: ContextFile): void {
  ensureDir(absPath)
  writeFileSync(absPath, `${JSON.stringify(ctx, null, 2)}\n`, 'utf-8')
}

/**
 * Write `.cipherstash/context.json` immediately after the encryption client
 * is generated. Handoff steps refresh it later with the list of skills they
 * installed; this baseline guarantees the file is always in sync with the
 * encryption client even if init aborts mid-flow.
 *
 * Without this baseline, a failed install-eql or a Ctrl+C between
 * build-schema and the handoff would leave context.json from a previous
 * run on disk — which an agent reading it would happily believe.
 */
export function writeBaselineContextFile(
  state: InitState,
  cwd: string,
  envKeys: string[],
): void {
  const absPath = resolve(cwd, CONTEXT_REL_PATH)
  const ctx = buildContextFile(state)
  ctx.envKeys = envKeys
  writeContextFile(absPath, ctx)
}

/**
 * Build a `SetupPromptContext` from the current init state for the given
 * handoff choice. Returns `undefined` for the wizard handoff — the wizard
 * has its own prompt logic and doesn't read this file.
 */
export function buildSetupPromptContext(
  state: InitState,
  handoff: HandoffChoice,
  installedSkills: string[],
): SetupPromptContext | undefined {
  if (handoff === 'wizard') return undefined
  const integration = state.integration ?? 'postgresql'
  const encryptionClientPath =
    state.clientFilePath ?? './src/encryption/index.ts'
  return {
    integration,
    encryptionClientPath,
    packageManager: detectPackageManager(),
    schemaFromIntrospection: state.schemaFromIntrospection ?? false,
    eqlInstalled: state.eqlInstalled ?? false,
    stackInstalled: state.stackInstalled ?? false,
    cliInstalled: state.cliInstalled ?? false,
    handoff,
    mode: state.mode ?? 'implement',
    installedSkills,
    planStep: state.planStep,
  }
}

/**
 * Render and persist `.cipherstash/setup-prompt.md`. The file is plain
 * markdown — no sentinel markers — because it's regenerated wholesale on
 * every init run and is meant to reflect the current state, not a managed
 * block alongside user content.
 */
export function writeSetupPrompt(
  absPath: string,
  ctx: SetupPromptContext,
): void {
  ensureDir(absPath)
  writeFileSync(absPath, renderSetupPrompt(ctx), 'utf-8')
}
