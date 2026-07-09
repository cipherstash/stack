/**
 * Per-command `--help` rendering, driven by the command-descriptor registry so
 * it can't drift from `stash manifest` or the real command set. `bin/main.ts`
 * still owns the global `HELP` banner (the no-command / `stash --help` surface);
 * this module handles `stash <command> --help` for a specific command or command
 * group. See `docs/plans/cli-help-and-manifest.md`.
 */
import { messages } from '../messages.js'
import { type CommandDescriptor, type Flag, registry } from './registry.js'

/** Two-space indent used throughout the help surface. */
const INDENT = '  '

/** Render a flag's left column, e.g. `--eql-version <2|3>` or `--force`. */
function flagSignature(flag: Flag): string {
  return flag.value ? `${flag.name} ${flag.value}` : flag.name
}

/**
 * Compose a flag's description with any default / env annotation, matching the
 * style of the global HELP ("… (default: 2)", "Also settable via STASH_REGION.").
 */
function flagDescription(flag: Flag): string {
  const parts = [flag.description]
  if (flag.default !== undefined) parts.push(`(default: ${flag.default})`)
  if (flag.env !== undefined) parts.push(`Also settable via ${flag.env}.`)
  return parts.join(' ')
}

/** Left-align a two-column list into "  <col>   <desc>" rows. */
function renderColumns(rows: Array<[string, string]>): string {
  const width = Math.max(...rows.map(([left]) => left.length))
  return rows
    .map(([left, right]) => `${INDENT}${left.padEnd(width)}   ${right}`)
    .join('\n')
}

/** Full help for a single leaf command, e.g. `stash eql install --help`. */
function renderSingleCommand(cmd: CommandDescriptor, runner: string): string {
  const sections: string[] = []

  sections.push(
    `${messages.cli.usagePrefix}${runner} ${cmd.name} [options]`,
    cmd.summary,
  )

  if (cmd.long) sections.push(cmd.long)

  if (cmd.flags && cmd.flags.length > 0) {
    const rows = cmd.flags.map((f): [string, string] => [
      flagSignature(f),
      flagDescription(f),
    ])
    sections.push(`Options:\n${renderColumns(rows)}`)
  }

  if (cmd.examples && cmd.examples.length > 0) {
    const lines = cmd.examples.map((ex) => `${INDENT}${runner} ${ex}`)
    sections.push(`Examples:\n${lines.join('\n')}`)
  }

  return sections.join('\n\n')
}

/**
 * Listing for a command group prefix, e.g. `stash eql --help` →
 * the eql install/upgrade/status commands with a pointer to their own `--help`.
 */
function renderGroup(
  path: string,
  children: CommandDescriptor[],
  runner: string,
): string {
  const rows = children.map((c): [string, string] => [c.name, c.summary])
  return [
    `${messages.cli.usagePrefix}${runner} ${path} <command> [options]`,
    `Commands:\n${renderColumns(rows)}`,
    `Run \`${runner} ${path} <command> --help\` for details on a command.`,
  ].join('\n\n')
}

/**
 * Resolve `--help` for a command path into rendered help text, using the
 * descriptor registry as the single source of truth. Returns `null` when the
 * path matches no command or command-group prefix, so the caller can fall back
 * to the global HELP banner.
 *
 * `path` is the command without the runner prefix, e.g. `"eql"`, `"eql install"`,
 * `"auth login"`, `"init"`. `runner` is the package-manager-aware prefix, e.g.
 * `"npx stash"`.
 */
export function renderCommandHelp(path: string, runner: string): string | null {
  const commands = registry.flatMap((g) => g.commands).filter((c) => !c.hidden)

  // Exact command match → full single-command help.
  const exact = commands.find((c) => c.name === path)
  if (exact) return renderSingleCommand(exact, runner)

  // Prefix match (e.g. "eql" → eql install / upgrade / status) → group listing.
  const children = commands.filter((c) => c.name.startsWith(`${path} `))
  if (children.length > 0) return renderGroup(path, children, runner)

  return null
}
