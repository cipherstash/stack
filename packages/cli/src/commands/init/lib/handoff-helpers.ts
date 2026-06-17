import { spawn } from 'node:child_process'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import type { HandoffChoice, InitState } from '../types.js'
import {
  buildContextFile,
  buildSetupPromptContext,
  CONTEXT_REL_PATH,
  SETUP_PROMPT_REL_PATH,
  writeContextFile,
  writeSetupPrompt,
} from './write-context.js'

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
 * Write `.cipherstash/context.json` and `.cipherstash/setup-prompt.md` for
 * a non-wizard handoff. Shared across the Claude / Codex / AGENTS.md
 * paths, which all need the same artifacts with handoff-specific values
 * threaded into the setup prompt.
 *
 * `installedSkills` is the list of skill names the handoff installed (or
 * `[]` for the AGENTS.md path that inlines content instead of installing
 * a skill directory).
 */
export function writeArtifacts(
  cwd: string,
  state: InitState,
  handoff: HandoffChoice,
  installedSkills: string[],
): void {
  const ctx = buildContextFile(state)
  ctx.envKeys = state.envKeys ?? []
  ctx.installedSkills = installedSkills
  writeContextFile(resolve(cwd, CONTEXT_REL_PATH), ctx)
  p.log.success(`Wrote ${CONTEXT_REL_PATH}`)

  const promptCtx = buildSetupPromptContext(state, handoff, installedSkills)
  if (promptCtx) {
    writeSetupPrompt(resolve(cwd, SETUP_PROMPT_REL_PATH), promptCtx)
    p.log.success(`Wrote ${SETUP_PROMPT_REL_PATH}`)
  }
}
