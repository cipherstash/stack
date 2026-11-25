import { readFileSync, writeFileSync } from 'node:fs'

const source = new URL(
  '../e2e/migration-guide/postgres-conversion.ts',
  import.meta.url,
)
const target = new URL(
  '../docs/migration/protect-dynamodb-to-stack.md',
  import.meta.url,
)
const guide = readFileSync(target, 'utf8')
const start = '<!-- migration-conversion:start -->'
const end = '<!-- migration-conversion:end -->'
const region = new RegExp(`${start}[\\s\\S]*?${end}`, 'g')
if ([...guide.matchAll(region)].length !== 1)
  throw new Error('Expected one migration snippet region')
const replacement = `${start}\n\n\`\`\`typescript\n${readFileSync(source, 'utf8').trimEnd()}\n\`\`\`\n\n${end}`
const updated = guide.replace(region, () => replacement)
if (process.argv.includes('--check')) {
  if (guide !== updated)
    throw new Error(
      'Migration snippet drift: run node scripts/sync-migration-guide.mjs',
    )
} else if (guide !== updated) {
  writeFileSync(target, updated)
}
