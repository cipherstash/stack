/**
 * `stash manifest --json` — the structured, versioned command surface the docs
 * generator (cipherstash/docs#45) and agents consume instead of scraping
 * `--help`. Built from the command-descriptor registry so it can't drift from
 * the real command set. See `docs/plans/cli-help-and-manifest.md`.
 */
import { type CommandDescriptor, type Flag, registry } from './registry.js'

/** A flag as it appears in the manifest (registry `Flag`, unchanged shape). */
export type ManifestFlag = Flag

/** A command as it appears in the manifest — the descriptor minus `hidden`. */
export interface ManifestCommand {
  name: string
  summary: string
  long?: string
  examples?: string[]
  flags?: ManifestFlag[]
}

export interface ManifestGroup {
  title: string
  commands: ManifestCommand[]
}

export interface Manifest {
  name: string
  version: string
  groups: ManifestGroup[]
}

/** Drop `hidden` and undefined optionals so the JSON is clean and stable. */
function toManifestCommand(cmd: CommandDescriptor): ManifestCommand {
  const out: ManifestCommand = { name: cmd.name, summary: cmd.summary }
  if (cmd.long !== undefined) out.long = cmd.long
  if (cmd.examples !== undefined) out.examples = cmd.examples
  if (cmd.flags !== undefined) out.flags = cmd.flags
  return out
}

/**
 * Build the manifest for a given CLI version. `version` is threaded in from the
 * CLI's own `package.json`, so a page generated from the manifest is always
 * stamped with the exact version it describes. Hidden commands are excluded.
 */
export function buildManifest(version: string): Manifest {
  return {
    name: 'stash',
    version,
    groups: registry.map((group) => ({
      title: group.title,
      commands: group.commands
        .filter((cmd) => !cmd.hidden)
        .map(toManifestCommand),
    })),
  }
}
