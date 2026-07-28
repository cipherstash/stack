/**
 * Evaluate an emitted ESM file graph in a realm with NO `process` global —
 * i.e. a Worker or a Deno isolate.
 *
 * Uses `node:vm`'s `SourceTextModule` with a linker that COMPILES each relative
 * import into the same sandbox context, rather than `import()`ing it in the host
 * realm (which would hand the module the host's `process` and prove nothing).
 * Bare specifiers are rejected unless named as an allowed external (below).
 * `dist/adapter-kit.js` has none at all, because everything it reaches is
 * bundled (`noExternal` in `packages/stack/tsup.config.ts`) — a property of the
 * build config, not of module resolution. So an unexpected one is a SIGNAL, not
 * automatically a defect.
 *
 * Run with `node --experimental-vm-modules`; callers spawn it that way, as a
 * CHILD PROCESS, so no vitest configuration or flag is involved.
 *
 * An entry MAY declare externals it legitimately expects the target runtime to
 * resolve — the WASM entry has two, the `/wasm-inline` subpaths of protect-ffi
 * and auth, which Deno and Workers supply through an import map. Naming each
 * one on the command line replaces it with a STUB module rather than loading
 * it: the point here is whether the graph *evaluates* without `process`, and
 * loading the real WASM binding would drag in a megabyte of unrelated
 * behaviour (and its own globals) for no extra signal. Anything not named is
 * still rejected, so a new external stays a conscious decision.
 *
 * A stub's exports are `undefined`, which is deliberate: if module-scope code
 * *calls* into an external at import time, that is itself a portability defect
 * and should fail here rather than pass quietly.
 *
 * Usage: node --experimental-vm-modules process-free-realm.mjs <entry.js> [allowed-external ...]
 * Exits 0 and prints `OK <n> exports`, or exits 1 and prints the failure.
 */
import { readFileSync } from 'node:fs'
import { dirname, resolve as resolvePath } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import vm from 'node:vm'

/**
 * Names a file imports from `specifier`, so a stub can export exactly those.
 *
 * `SyntheticModule` needs its export list up front — a namespace Proxy will not
 * do, because ESM linking resolves named imports against the declared list
 * before any code runs. Scanning the importer is the only way to know them, and
 * a missing name surfaces as a link error naming the export, which is a fine
 * failure mode.
 */
const importedNamesFrom = (source, specifier) => {
  const names = new Set()
  const quoted = specifier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const pattern = new RegExp(
    `import\\s*(?:([\\w$]+)\\s*,\\s*)?(?:\\{([^}]*)\\}|\\*\\s*as\\s*([\\w$]+))?\\s*from\\s*["']${quoted}["']`,
    'g',
  )
  for (const [, defaultName, braced, namespaceName] of source.matchAll(
    pattern,
  )) {
    if (defaultName || namespaceName) names.add('default')
    for (const clause of braced?.split(',') ?? []) {
      // `newClient as wasmNewClient` — the stub exports the ORIGINAL name.
      const original = clause
        .trim()
        .split(/\s+as\s+/)[0]
        .trim()
      if (original) names.add(original.replace(/^type\s+/, ''))
    }
  }
  return names
}

async function loadInProcessFreeRealm(entryPath, allowedExternals = []) {
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

  const stubs = new Map()

  const link = (specifier, referencing) => {
    if (!specifier.startsWith('.') && !specifier.startsWith('/')) {
      if (!allowedExternals.includes(specifier)) {
        throw new Error(
          `unexpected bare specifier "${specifier}" in ${referencing.identifier} — this graph is bundled (tsup \`noExternal\`) and should have none beyond the externals named on the command line. If this is a legitimate new external, pass it as an argument (and say why in the caller).`,
        )
      }
      const cached = stubs.get(specifier)
      if (cached) return cached
      const source = readFileSync(fileURLToPath(referencing.identifier), 'utf8')
      const exportNames = [...importedNamesFrom(source, specifier)]
      const stub = new vm.SyntheticModule(
        exportNames,
        function () {
          for (const name of exportNames) this.setExport(name, undefined)
        },
        { context, identifier: `stub:${specifier}` },
      )
      stubs.set(specifier, stub)
      return stub
    }
    const base = dirname(fileURLToPath(referencing.identifier))
    return compile(resolvePath(base, specifier))
  }

  const entry = compile(entryPath)
  await entry.link(link)
  await entry.evaluate()
  return entry.namespace
}

const [, , entryPath, ...allowedExternals] = process.argv
try {
  const namespace = await loadInProcessFreeRealm(entryPath, allowedExternals)
  console.log(`OK ${Object.keys(namespace).length} exports`)
} catch (error) {
  console.error(`${error.constructor.name}: ${error.message}`)
  process.exit(1)
}
