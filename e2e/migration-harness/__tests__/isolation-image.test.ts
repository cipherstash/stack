import { readFile } from 'node:fs/promises'
import { expect, test } from 'vitest'

// A Docker bind mount's root can appear root-owned inside the container (as
// Colima's virtiofs does on macOS) while the actor runs as the host uid. Git
// then refuses /workspace as "dubious ownership" and the Run fails at its first
// harness git command. The image must trust /workspace at system level.
test('the isolation image trusts /workspace for Git regardless of mount ownership', async () => {
  const dockerfile = await readFile(
    new URL('../isolation/Dockerfile', import.meta.url),
    'utf8',
  )
  expect(dockerfile).toMatch(
    /^RUN git config --system --add safe\.directory \/workspace$/m,
  )
})
