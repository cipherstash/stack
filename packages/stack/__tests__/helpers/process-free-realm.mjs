/**
 * Evaluate an emitted ESM file graph in a realm with NO `process` global —
 * i.e. a Worker or a Deno isolate.
 *
 * Uses `node:vm`'s `SourceTextModule` with a linker that COMPILES each relative
 * import into the same sandbox context, rather than `import()`ing it in the host
 * realm (which would hand the module the host's `process` and prove nothing).
 * Bare specifiers are rejected: the graphs this is pointed at have none, and a
 * new one appearing is itself a finding.
 *
 * Run with `node --experimental-vm-modules`; callers spawn it that way, as a
 * CHILD PROCESS, so no vitest configuration or flag is involved.
 *
 * Usage: node --experimental-vm-modules process-free-realm.mjs <entry.js>
 * Exits 0 and prints `OK <n> exports`, or exits 1 and prints the failure.
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve as resolvePath } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import vm from 'node:vm'

async function loadInProcessFreeRealm(entryPath) {
  // Deliberately minimal: `console` for diagnostics and the handful of globals
  // a Worker genuinely has. NO `process`, NO `require`, NO `Buffer`.
  const context = vm.createContext({
    console,
    TextEncoder,
    TextDecoder,
    URL,
    WebAssembly,
    atob,
    btoa,
  })
  const cache = new Map()

  const compile = (file) => {
    const cached = cache.get(file)
    if (cached) return cached
    const mod = new vm.SourceTextModule(readFileSync(file, 'utf8'), {
      context,
      identifier: pathToFileURL(file).href,
      initializeImportMeta(meta) {
        meta.url = pathToFileURL(file).href
      },
    })
    cache.set(file, mod)
    return mod
  }

  const link = (specifier, referencing) => {
    if (!specifier.startsWith('.') && !specifier.startsWith('/')) {
      throw new Error(
        `unexpected bare specifier "${specifier}" in ${referencing.identifier} — this graph is supposed to be self-contained`,
      )
    }
    const base = dirname(fileURLToPath(referencing.identifier))
    return compile(resolvePath(base, specifier))
  }

  const entry = compile(entryPath)
  await entry.link(link)
  await entry.evaluate()
  return entry.namespace
}

const [, , entryPath] = process.argv
try {
  const namespace = await loadInProcessFreeRealm(entryPath)
  console.log(`OK ${Object.keys(namespace).length} exports`)
} catch (error) {
  console.error(`${error.constructor.name}: ${error.message}`)
  process.exit(1)
}
