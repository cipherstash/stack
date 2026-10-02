import type { Reporter, TestModule } from 'vitest/node'

/**
 * Fail the integration run if any test was skipped.
 *
 * A skipped test reads exactly like a passing one. Every silent hole this suite
 * has found took that shape: `matches` never ran on `text_match` because its
 * needle was `''`; the non-ASCII ORE needle test had zero cases after the OPE
 * re-pin; the Supabase grants check quietly did not run for the Drizzle job
 * because `dbVariant()` mis-inferred the database. In each case a green run
 * reported coverage it did not have.
 *
 * So the integration suites carry no `skip`, no `todo`, no `runIf` and no
 * `skipIf`. Environmental differences are asserted rather than skipped: a plain
 * Postgres has no `anon` role, and that is a fact worth stating. Where a
 * behaviour genuinely cannot be exercised — the block-ORE domains cannot hold
 * data on managed Postgres — the domain is excluded from the matrix by the
 * catalog's `deferred` field, and a separate, PASSING test asserts that the
 * excluded set is exactly what it should be.
 *
 * The unit suites still skip (the `LIVE_*` gates), so this is scoped to the
 * integration config rather than imposed repo-wide.
 */
export default class NoSkipsReporter implements Reporter {
  private readonly skipped: string[] = []

  onTestModuleEnd(testModule: TestModule): void {
    for (const test of Array.from(testModule.children.allTests())) {
      const result = test.result()
      if (result.state === 'skipped') this.skipped.push(test.fullName)
    }
  }

  onTestRunEnd(): void {
    if (this.skipped.length === 0) return

    const list = this.skipped.map((name) => `  - ${name}`).join('\n')
    console.error(
      `\n${this.skipped.length} test(s) were SKIPPED. The integration suites must not skip:\n` +
        `${list}\n\n` +
        'A skipped test reads exactly like a passing one. Assert the environmental\n' +
        "difference instead, or exclude the domain via the catalog's `deferred`\n" +
        'field and assert the excluded set separately.\n',
    )
    process.exitCode = 1
  }
}
