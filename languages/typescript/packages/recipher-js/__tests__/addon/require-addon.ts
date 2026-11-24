import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// `test:addon` is for a machine that has built the addon. Without it every
// suite here would fail one test at a time with a load error; this says why
// once, before any of them runs.
const addon = fileURLToPath(new URL('../../recipher.node', import.meta.url))
if (!existsSync(addon)) {
  throw new Error(
    `test:addon needs the native build at ${addon}. ` +
      'Run `pnpm --filter @cipherstash/recipher build:debug` first.',
  )
}
