# Declaration-emit contract

These files typecheck against `../dist`, not `../src`.

Every other type test in this package imports `@/…`, which resolves to source.
That is the right default — it keeps the tests fast and independent of a build —
but it means nothing checked what customers actually consume, and a defect lived
in the published `.d.ts` for the whole rc series because of it:
`EncryptedV3Column`'s domain parameter `D` was recoverable in source and not in
the emitted declarations, so typed `encryptQuery` was uncallable for every column
against the published package.

Anything whose correctness depends on what `tsc` *emits* — rather than on what
the source says — belongs here. Requires a build first; wired into CI as
`test:types:dist`.
