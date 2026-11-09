# Run skeleton

From the repository root:

```sh
pnpm exec turbo run harness:selftest harness:typecheck --filter @cipherstash/e2e
pnpm exec turbo run harness:isolation-probe harness:store-probe --filter @cipherstash/e2e
```

The probes require a Linux Docker daemon. They create disposable containers,
volumes and temporary workspaces. Store ports bind to random localhost ports;
cleanup targets only resources created by the harness. The isolation image uses
a root-owned ptrace observer and unprivileged application processes with no
Docker socket mount. The isolation probe builds that image, including its
Python supervisor, and checks denial and supervisor termination paths.

The `Migration harness` PR workflow runs these four commands without service
credentials. The existing credentialed E2E job additionally runs the complete
Fixture App matrix with deterministic Fake Migrators, including the Reference
Migration, Broken Migrations, lifecycle denials and an in-tree Stack tarball.
No model calls are made by either self-test path.

For a real Run, first build workspace dependencies with `pnpm --filter @cipherstash/e2e... build`, then use `pnpm --filter @cipherstash/e2e harness:run --migrator '<command>'`
and require the CipherStash credentials described in the repository README.
Reports are written under `.migration-harness-runs/` relative to the package.
Real application execution is gated on the backend capability proof. The full
credentialed no-op and rewrite-on-read acceptance Runs are covered in CI.

Use `harness:run --fake reference` for a deterministic known-correct migration.
Other Fake Migrator variants are `noop`, `downcase`, `stale-hmac`, `bigint`,
`rewrite`, `missing-log`, `legacy-ffi`, `denied-app` and `denied-lifecycle`.
The harness copies only the selected application into the workspace; the hidden
Reference Migration directory is never mounted into an actor.

`--stack` accepts an npm range (default `^1.2.1`), `tree`, or a `.tgz` path.
The tree option requires the Stack package's build outputs first and uses
`pnpm pack` to rewrite workspace dependency protocols. The Run Manifest records
the exact version and, for tarballs, the SHA-256 digest. To run the credentialed
matrix locally, put the four `CS_*` credentials and `HARNESS_LIVE=1` in the e2e
`.env`, then run `pnpm --filter @cipherstash/e2e harness:selftest`.
