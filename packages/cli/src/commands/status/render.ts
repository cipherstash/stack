import type { ColumnQuest, Objective, QuestLog } from './quest.js'

const PROGRESS_BAR_WIDTH = 6

/**
 * Render a quest log as the balanced TTY quest-log shape — emoji,
 * progress bars, lock icons, "← you are here" markers, and one-line
 * "next move" hints. Designed for an interactive terminal; non-TTY
 * callers should use {@link renderQuestLogPlain} instead.
 */
export function renderQuestLogTTY(log: QuestLog): string {
  if (!log.initialized) {
    return [
      '⚔️   CipherStash Quest Log',
      '',
      '  No quests yet — your encryption rollout has not begun.',
      '',
      '  First move: run `npx stash init` to set up CipherStash, then',
      '  `npx stash plan` to draft an encryption rollout.',
    ].join('\n')
  }

  const lines: string[] = ['⚔️   CipherStash Quest Log', '']

  if (log.active.length === 0 && log.completed.length === 0) {
    lines.push(
      '  No active quests yet — your encryption rollout has not begun.',
      '',
      '  First move: run `npx stash plan` to draft a rollout for the',
      '  columns you want to protect.',
    )
    return lines.join('\n')
  }

  for (const quest of log.active) {
    lines.push(...renderActiveQuestTTY(quest))
    lines.push('')
  }

  for (const quest of log.completed) {
    lines.push(`  🏆 COMPLETED  ·  ${quest.table}.${quest.column} — fully encrypted`)
  }

  if (!log.observedFromDb) {
    lines.push(
      '',
      '  Note: could not reach the database, so per-column progress is',
      '  derived from `.cipherstash/migrations.json` only. Run again with',
      '  the database available for live state.',
    )
  }

  return lines.join('\n').replace(/\n+$/, '')
}

function renderActiveQuestTTY(quest: ColumnQuest): string[] {
  const lines: string[] = []
  lines.push(`  ▶ ACTIVE QUEST  ·  ${quest.title}`)
  const bar = progressBar(quest.progress.done, quest.progress.total)
  lines.push(
    `    ${bar}  ${quest.progress.done}/${quest.progress.total} objectives`,
  )
  for (const obj of quest.objectives) {
    lines.push(`      ${objectiveIconTTY(obj)}  ${decorate(obj)}`)
  }
  if (quest.nextMove) {
    lines.push(`    💡 Next move: ${quest.nextMove}`)
  }
  return lines
}

function objectiveIconTTY(obj: Objective): string {
  switch (obj.status) {
    case 'done':
      return '✓'
    case 'active':
      return '▸'
    case 'locked':
      return '🔒'
  }
}

function decorate(obj: Objective): string {
  if (obj.status === 'active') return `${obj.label}       ← you are here`
  return obj.label
}

function progressBar(done: number, total: number): string {
  if (total === 0) return ''.padEnd(PROGRESS_BAR_WIDTH, '░')
  const filled = Math.round((done / total) * PROGRESS_BAR_WIDTH)
  return '▓'.repeat(filled) + '░'.repeat(PROGRESS_BAR_WIDTH - filled)
}

/**
 * Render a quest log as plain text. Same content as the TTY shape,
 * stripped of emoji, lock icons, and progress-bar glyphs. The structure
 * stays identical so a script grepping the output of either form gets
 * the same fields.
 *
 * Used in non-TTY contexts by default — CI logs, pipes, agents reading
 * the output. The user can force the TTY shape anywhere with `--quest`.
 */
export function renderQuestLogPlain(log: QuestLog): string {
  if (!log.initialized) {
    return [
      'CipherStash status — encryption rollout',
      '',
      '  No quests yet — encryption rollout has not begun.',
      '  First move: run `npx stash init`, then `npx stash plan`.',
    ].join('\n')
  }

  const lines: string[] = ['CipherStash status — encryption rollout', '']

  if (log.active.length === 0 && log.completed.length === 0) {
    lines.push(
      '  No active quests.',
      '  First move: run `npx stash plan` to draft a rollout.',
    )
    return lines.join('\n')
  }

  if (log.active.length > 0) {
    lines.push('Active rollouts')
    lines.push('───────────────────────────────────────────────────')
    for (const quest of log.active) {
      lines.push(...renderActiveQuestPlain(quest))
      lines.push('')
    }
  }

  if (log.completed.length > 0) {
    lines.push('Completed')
    lines.push('───────────────────────────────────────────────────')
    for (const quest of log.completed) {
      lines.push(`  ${quest.table}.${quest.column} — fully encrypted`)
    }
  }

  if (!log.observedFromDb) {
    lines.push(
      '',
      'Note: could not reach the database; per-column progress is derived from',
      '.cipherstash/migrations.json only. Run again with the database available',
      'for live state.',
    )
  }

  return lines.join('\n').replace(/\n+$/, '')
}

function renderActiveQuestPlain(quest: ColumnQuest): string[] {
  const lines: string[] = []
  lines.push(`  ${quest.title}`)
  lines.push(
    `  Progress: ${quest.progress.done}/${quest.progress.total} objectives`,
  )
  for (const obj of quest.objectives) {
    lines.push(`    ${objectiveIconPlain(obj)} ${obj.label}`)
  }
  if (quest.nextMove) {
    lines.push(`  Next move: ${quest.nextMove}`)
  }
  return lines
}

function objectiveIconPlain(obj: Objective): string {
  switch (obj.status) {
    case 'done':
      return '[x]'
    case 'active':
      return '[>]'
    case 'locked':
      return '[ ]'
  }
}

/**
 * Render a quest log as JSON. Stable shape — flat per-quest objects with
 * an objectives array, designed for scripts and agents reading the
 * status output. We never break this shape without a major version bump.
 */
export function renderQuestLogJSON(log: QuestLog): string {
  return `${JSON.stringify(
    {
      initialized: log.initialized,
      observedFromDb: log.observedFromDb,
      active: log.active.map(serializeQuest),
      completed: log.completed.map(serializeQuest),
    },
    null,
    2,
  )}\n`
}

function serializeQuest(quest: ColumnQuest) {
  return {
    table: quest.table,
    column: quest.column,
    path: quest.path,
    title: quest.title,
    progress: quest.progress,
    complete: quest.complete,
    nextMove: quest.nextMove ?? null,
    objectives: quest.objectives.map((o) => ({
      label: o.label,
      status: o.status,
    })),
  }
}
