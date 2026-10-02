/**
 * `stash manifest --json` — the structured, versioned command surface the docs
 * generator (cipherstash/docs#45) and agents consume instead of scraping
 * `--help`. Built from the command-descriptor registry so it can't drift from
 * the real command set. See `docs/plans/cli-help-and-manifest.md`.
 */
import {
  type CommandDescriptor,
  type CommandGroup,
  type Flag,
  registry,
} from './registry.js'

/** A command as it appears in the manifest — the descriptor minus `hidden`. */
export interface ManifestCommand {
  name: string
  summary: string
  long?: string
  examples?: string[]
  flags?: Flag[]
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

/**
 * Drop `hidden` and undefined optionals, and defensively copy `examples` /
 * `flags` so the manifest never aliases the registry's arrays or its shared
 * flag singletons (`DATABASE_URL_FLAG`, …) — a consumer that mutates a manifest
 * entry must not corrupt the registry or other commands sharing that object.
 */
function toManifestCommand(cmd: CommandDescriptor): ManifestCommand {
  const out: ManifestCommand = { name: cmd.name, summary: cmd.summary }
  if (cmd.long !== undefined) out.long = cmd.long
  if (cmd.examples !== undefined) out.examples = [...cmd.examples]
  if (cmd.flags !== undefined) out.flags = cmd.flags.map((f) => ({ ...f }))
  return out
}

/**
 * Build the manifest for a given CLI version. `version` is threaded in from the
 * CLI's own `package.json`, so a page generated from the manifest is always
 * stamped with the exact version it describes. Hidden commands are excluded.
 *
 * `groups` defaults to the real `registry`; it's an injection seam so tests can
 * drive the hidden-command filter with a stub instead of depending on whether
 * the live registry happens to contain a hidden command.
 */
export function buildManifest(
  version: string,
  groups: CommandGroup[] = registry,
): Manifest {
  return {
    name: 'stash',
    version,
    groups: groups.map((group) => ({
      title: group.title,
      commands: group.commands
        .filter((cmd) => !cmd.hidden)
        .map(toManifestCommand),
    })),
  }
}
