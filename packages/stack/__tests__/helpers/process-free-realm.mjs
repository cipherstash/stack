/**
 * Evaluate an emitted ESM file graph in a realm with NO `process` global —
 * i.e. a Worker or a Deno isolate.
 *
 * Uses `node:vm`'s `SourceTextModule` with a linker that COMPILES each relative
 * import into the same sandbox context, rather than `import()`ing it in the host
 * realm (which would hand the module the host's `process` and prove nothing).
 * Bare specifiers are rejected. The graphs this is pointed at have none today
 * only because everything they reach is bundled (`noExternal` in
 * `packages/stack/tsup.config.ts`) — a property of the build config, not of
 * module resolution. So a new one is a SIGNAL, not automatically a defect: if
 * it is a legitimate external the target runtime resolves, allow it here.
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
        `unexpected bare specifier "${specifier}" in ${referencing.identifier} — this graph is bundled (tsup \`noExternal\`) and should have none. If this is a legitimate new external, allow it in this harness.`,
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
