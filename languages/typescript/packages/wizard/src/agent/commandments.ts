/**
 * Behavioral rules enforced via the agent's system prompt.
 * Kept minimal to reduce token overhead on every turn.
 */
export const COMMANDMENTS = [
  'Read a file before writing or editing it.',
  'Make targeted changes. Do not reformat or refactor unrelated code.',
  'Do not embed secrets in code. Use environment variables.',
  'Do not create temporary files or scripts.',
  '@cipherstash/stack and stash are public npm packages. Install them normally.',
  'Be concise. State what you did, what to run next, and stop. No summaries or recaps.',
] as const

/** Format commandments for inclusion in the agent system prompt. */
export function formatCommandments(): string {
  return COMMANDMENTS.map((c, i) => `${i + 1}. ${c}`).join('\n')
}
