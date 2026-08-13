import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { basename, dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(packageRoot, '../..')
const check = process.argv.includes('--check')

const sourceBindings = join(repoRoot, 'crates/eql-bindings/bindings/v3')
const sourceSchemas = join(repoRoot, 'crates/eql-bindings/schema/v3')
const generatedRoot = join(packageRoot, 'src/generated')
const generatedBindings = join(generatedRoot, 'v3')
const generatedSchemas = join(generatedRoot, 'schema/v3')

function listFiles(dir, suffix) {
  return readdirSorted(dir).filter((name) => name.endsWith(suffix))
}

function readdirSorted(dir) {
  return readdirSync(dir).sort((a, b) => a.localeCompare(b))
}

function read(path) {
  return readFileSync(path, 'utf8')
}

function write(path, contents) {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, contents)
}

function copyText(src, dest) {
  write(dest, read(src))
}

function renderTypeBarrel(files) {
  const exports = files
    .map((file) => `export type * from './${basename(file, '.ts')}'`)
    .join('\n')
  return `${exports}\n`
}

function renderSchemaManifest(files) {
  const entries = files.map((file) => {
    const name = basename(file, '.json')
    const json = JSON.parse(read(join(sourceSchemas, file)))
    return { name, id: json.$id }
  })
  const names = entries.map((entry) => `  '${entry.name}',`).join('\n')
  const ids = entries.map((entry) => `  ${JSON.stringify(entry.name)}: ${JSON.stringify(entry.id)},`).join('\n')
  return `export const schemaNames = [\n${names}\n] as const\n\nexport const schemaIds = {\n${ids}\n} as const\n`
}

function renderReleaseManifest() {
  if (preservedReleaseManifest !== undefined) return preservedReleaseManifest
  return `export const releaseManifest = {\n  eqlVersion: 'DEV',\n  schemaVersion: 3,\n  installSqlSha256: '',\n  uninstallSqlSha256: '',\n} as const\n`
}

function snapshot(dir) {
  if (!existsSync(dir)) return new Map()
  const out = new Map()
  walk(dir, (path) => out.set(relative(dir, path), read(path)))
  return out
}

function walk(dir, visit) {
  for (const name of readdirSorted(dir)) {
    const path = join(dir, name)
    const stat = statSync(path)
    if (stat.isDirectory()) walk(path, visit)
    else visit(path)
  }
}

function assertUnchanged(before, dir) {
  const after = snapshot(dir)
  const beforeJson = JSON.stringify([...before.entries()].sort())
  const afterJson = JSON.stringify([...after.entries()].sort())
  if (beforeJson !== afterJson) {
    throw new Error('@cipherstash/eql generated files are stale; run `pnpm --filter @cipherstash/eql sync:generated`')
  }
}

const before = snapshot(generatedRoot)
const releaseManifestPath = join(generatedRoot, 'release-manifest.ts')
const preservedReleaseManifest = existsSync(releaseManifestPath)
  ? read(releaseManifestPath)
  : undefined
rmSync(generatedRoot, { recursive: true, force: true })

const bindingFiles = listFiles(sourceBindings, '.ts')
for (const file of bindingFiles) {
  copyText(join(sourceBindings, file), join(generatedBindings, file))
}
write(join(generatedBindings, 'index.ts'), renderTypeBarrel(bindingFiles))

const schemaFiles = listFiles(sourceSchemas, '.json')
for (const file of schemaFiles) {
  copyText(join(sourceSchemas, file), join(generatedSchemas, file))
}
write(join(generatedRoot, 'schema-manifest.ts'), renderSchemaManifest(schemaFiles))
write(join(generatedRoot, 'release-manifest.ts'), renderReleaseManifest())

if (check) {
  assertUnchanged(before, generatedRoot)
}

console.log(`synced ${bindingFiles.length} TypeScript bindings and ${schemaFiles.length} JSON schemas`)
