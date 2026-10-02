// Thin launcher.
//
// The CLI body lives in main.ts. It is loaded via dynamic import so the native
// addons it pulls in (e.g. @cipherstash/protect-ffi through @cipherstash/stack)
// are evaluated *inside* a try/catch. When npm has skipped the platform-
// specific optional dependency, that evaluation throws MODULE_NOT_FOUND; we
// catch it here and print actionable guidance instead of a raw stack trace.
//
// `doctor` is dispatched before the body loads so it remains runnable even when
// the native binary is missing — that's precisely when you want to diagnose.

import * as p from '@clack/prompts'
import { isNativeBinaryMissing, reportNativeBinaryMissing } from '../native.js'

async function bootstrap() {
  if (process.argv[2] === 'doctor') {
    const { doctorCommand } = await import('../commands/doctor/index.js')
    await doctorCommand()
    return
  }

  let run: () => Promise<void>
  try {
    ;({ run } = await import('./main.js'))
  } catch (err) {
    if (isNativeBinaryMissing(err)) {
      reportNativeBinaryMissing(err)
      process.exit(1)
    }
    throw err
  }

  await run()
}

bootstrap().catch((err: unknown) => {
  // Also caught here in case a native addon loads lazily (at call time) rather
  // than during module evaluation.
  if (isNativeBinaryMissing(err)) {
    reportNativeBinaryMissing(err)
    process.exit(1)
  }
  const message = err instanceof Error ? err.message : String(err)
  p.log.error(`Fatal error: ${message}`)
  process.exit(1)
})
