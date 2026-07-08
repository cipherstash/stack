import { buildManifest } from '../../cli/manifest.js'

export interface ManifestCommandOptions {
  /** Emit the structured JSON manifest instead of the human-readable list. */
  json?: boolean
  /** CLI version, threaded from the caller's package.json. */
  version: string
}

/**
 * `stash manifest` — print the CLI's command surface.
 *
 * `--json` emits the machine-readable manifest (docs generator / agents);
 * without it a grouped, human-readable command list is printed. Pure metadata:
 * loads no native code, so it runs anywhere `stash` does.
 */
export function manifestCommand(opts: ManifestCommandOptions): void {
  const manifest = buildManifest(opts.version)

  if (opts.json) {
    console.log(JSON.stringify(manifest, null, 2))
    return
  }

  console.log(`stash ${manifest.version}\n`)
  for (const group of manifest.groups) {
    console.log(`${group.title}:`)
    for (const cmd of group.commands) {
      console.log(`  ${cmd.name.padEnd(20)} ${cmd.summary}`)
    }
    console.log('')
  }
  console.log('Run `stash manifest --json` for the machine-readable surface.')
}
