import { spawn } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import type { HandoffChoice, InitState } from '../types.js'
import { upsertManagedBlock } from './sentinel-upsert.js'
import {
  buildContextFile,
  buildSetupPromptContext,
  CONTEXT_REL_PATH,
  SETUP_PROMPT_REL_PATH,
  type SkillsDelivery,
  writeContextFile,
  writeSetupPrompt,
} from './write-context.js'

export type { SkillsDelivery } from './write-context.js'

export const AGENTS_MD_REL_PATH = 'AGENTS.md'

/**
 * Spawn an interactive CLI agent (`claude` / `codex`) with the launch
 * prompt as a single argument. `stdio: 'inherit'` so the user sees tool
 * calls and approves edits live; the call resolves with the exit code.
 *
 * Claude is launched with `--allow-dangerously-skip-permissions` so the
 * user can opt in to skip-permissions mode for the integration handoff
 * without having to relaunch — the flag permits the toggle, it doesn't
 * force it on.
 *
 * Returns -1 if the binary isn't on PATH (the spawn `error` event fires
 * before `close` does). Init never aborts on a non-zero code — the
 * artifacts are already written, the user can re-run the agent.
 */
export function spawnAgent(
  binary: 'claude' | 'codex',
  prompt: string,
): Promise<number> {
  const args =
    binary === 'claude'
      ? ['--allow-dangerously-skip-permissions', prompt]
      : [prompt]
  return new Promise((resolvePromise) => {
    const child = spawn(binary, args, { stdio: 'inherit', shell: false })
    child.on('close', (code) => resolvePromise(code ?? 0))
    child.on('error', () => resolvePromise(-1))
  })
}

/**
 * Sentinel-upsert `AGENTS.md` at the project root, degrading to a warning
 * on failure. Returns whether the write landed, so callers can report the
 * inline fallback honestly (skills are only "inlined" if this succeeded).
 *
 * Guarded for the same reason `installSkills` never throws: this runs
 * before `writeArtifacts`, so an exception here — an unwritable root, or
 * `upsertManagedBlock` refusing a malformed sentinel pair — used to abort
 * the whole step and take `.cipherstash/` down with it (the #736 blast
 * radius, one call further along).
 */
export function writeAgentsMd(cwd: string, managed: string): boolean {
  const abs = resolve(cwd, AGENTS_MD_REL_PATH)
  try {
    const existing = existsSync(abs) ? readFileSync(abs, 'utf-8') : undefined
    writeFileSync(abs, upsertManagedBlock({ existing, managed }), 'utf-8')
    p.log.success(`Wrote ${AGENTS_MD_REL_PATH}`)
    return true
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    p.log.warn(`Could not write ${AGENTS_MD_REL_PATH}: ${message}`)
    return false
  }
}

/**
 * Write `.cipherstash/context.json` and `.cipherstash/setup-prompt.md` for
 * a non-wizard handoff. Shared across the Claude / Codex / AGENTS.md
 * paths, which all need the same artifacts with handoff-specific values
 * threaded into the setup prompt.
 *
 * `skills` records where the skills actually ended up (installed as
 * directories, inlined into AGENTS.md, or failed) so the generated prompt
 * never mislabels an unwritable destination as a stripped build.
 */
export function writeArtifacts(
  cwd: string,
  state: InitState,
  handoff: HandoffChoice,
  skills: SkillsDelivery,
): void {
  const ctx = buildContextFile(state)
  ctx.envKeys = state.envKeys ?? []
  ctx.installedSkills = skills.installed
  ctx.inlinedSkills = skills.inlined
  writeContextFile(resolve(cwd, CONTEXT_REL_PATH), ctx)
  p.log.success(`Wrote ${CONTEXT_REL_PATH}`)

  const promptCtx = buildSetupPromptContext(state, handoff, skills)
  if (promptCtx) {
    writeSetupPrompt(resolve(cwd, SETUP_PROMPT_REL_PATH), promptCtx)
    p.log.success(`Wrote ${SETUP_PROMPT_REL_PATH}`)
  }
}
