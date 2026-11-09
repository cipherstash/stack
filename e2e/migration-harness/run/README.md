# Run skeleton

From the repository root:

```sh
pnpm --filter @cipherstash/e2e harness:selftest
pnpm --filter @cipherstash/e2e harness:typecheck
pnpm --filter @cipherstash/e2e harness:isolation-probe
pnpm --filter @cipherstash/e2e harness:store-probe
```

The probes require a Linux Docker daemon. They create disposable containers,
volumes and temporary workspaces. Store ports bind to random localhost ports;
cleanup targets only resources created by the harness. The isolation image uses
a root-owned ptrace observer and unprivileged application processes with no
Docker socket mount. The isolation probe builds that image, including its
Python supervisor, and checks denial and supervisor termination paths.

The `Migration harness` PR workflow runs these four commands without service
credentials. It verifies the skeleton and backend probes, not the complete
credentialed Fixture App migration.

Real Runs use `pnpm --filter @cipherstash/e2e harness:run --migrator '<command>'`
and require the CipherStash credentials described in the repository README.
Reports are written under `.migration-harness-runs/` relative to the package.
Real application execution is gated on the backend capability proof. The full
credentialed no-op Migrator acceptance run remains unverified in this PR.
