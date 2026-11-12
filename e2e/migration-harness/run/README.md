# Run skeleton

## PostgreSQL v2-to-v3 procedure

The `postgres-fixture` directory and `postgres-behaviour.mjs` / `postgres-oracle.mjs`
provide the separate PostgreSQL v2-to-v3 procedure tracked by #1605. They cover the
guide's text equality, safe integer equality and storage-only text mappings.
The oracle compares retained ciphertext and equality terms while permitting
the documented envelope change and verifies source/target domains and indexes.

Select it with `harness:run --procedure postgres-v2-to-v3 --migrator <adapter>`.
For deterministic acceptance use `--fake reference` instead of `--migrator`.
The default remains `--procedure dynamodb`. Both procedures record their identity,
source and target EQL generations, exact Stack source and guide hash.

The PostgreSQL procedure installs the historical EQL 2.2.1 bundle alongside v3
and seeds each independent Store Set with Protect.js writes to v2 columns.
Legacy reads and queries must pass before migration. As the guide prescribes a
one-off conversion in a write-maintenance window rather than at application
startup, the Fixture App has a separate entry point, `src/migrate.mjs`
`migrate(env)`, and `createApp` must not alter the schema. The Oracle runs
`migrate(env)` inside App Host (`node /harness/app-host.mjs migrate`) using the
Oracle Store Set's application role, then runs it again: the rerun passes
`migration.postgres-migrate-rerun` only if the Oracle snapshots before and after
it are identical, whether it succeeded or refused with a non-zero exit; a rerun
the isolation backend timed out fails. A failed first `migrate(env)` fails
`migration.postgres-migrate` as a behaviour failure. Only then does App Host
start `createApp`. The harness snapshots stored rows, domains and indexes
independently, as the Run's own application role rather than the superuser, so
an object a migration planted cannot run with superuser privileges. The storage
checks must hold on the snapshot taken after the first `migrate(env)`, before
`createApp` runs, and again after read-only application checks. The snapshot
after the fresh write must add exactly the fresh row and leave every other row,
retained v2 sources included, unchanged. The EQL 2.2.1 bundle is downloaded once
per process with a timeout and refused unless its SHA-256 digest matches the
release asset's.

The hidden Reference Migration retains source columns and rebuilds only the
envelopes the guide proves convertible. Deterministic variants `noop`, `row-loss`,
`wrong-mapping`, `fresh-v2`, `missing-index`, `rewrite` and `missing-log` exercise the named
failure checks. The existing credentialed CI self-test job runs this matrix
when `HARNESS_LIVE=1`; ordinary self-tests skip it. Local unit checks alone do
not establish a completed live PostgreSQL migration.

## Running the existing baseline

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
credentials. It verifies the skeleton and backend probes, not the complete
credentialed Fixture App migration.

For a real Run, first build workspace dependencies with
`pnpm --filter @cipherstash/e2e... build`, then use
`pnpm --filter @cipherstash/e2e harness:run --migrator 'node /absolute/path/to/adapter.mjs'`.
The CipherStash credentials described in the repository README are required.
Reports are written under `.migration-harness-runs/` relative to the package.
Real application execution is gated on the backend capability proof. The full
credentialed no-op Migrator acceptance run remains unverified in this PR.

## Host model adapter

`--migrator` is a **trusted host adapter command**. It runs in a fresh temporary
directory with the host's model authentication available. The harness removes
`CS_*`, `DATABASE_URL` and inherited `HARNESS_*` values from its environment.
Application credentials and store connections are supplied only to isolated
tool commands. The adapter receives virtual `/workspace` paths in
`HARNESS_WORKSPACE`, `HARNESS_GUIDE` and `HARNESS_FRICTION_LOG`.

The adapter uses JSON Lines on stdout to request application commands:

```json
{"id":"read-guide","method":"exec","command":["cat","/workspace/migration-guide.md"]}
```

The harness fixes the actor, workspace, credentials, forwards and remaining
deadline, executes the command through the proven isolation backend, and writes
a response to the adapter's stdin:

```json
{"id":"read-guide","result":{"exitCode":0,"stdout":"...","stderr":""}}
```

Only `id`, `method` and `command` are accepted in requests. IDs must be unique
nonempty strings of at most 128 characters. Commands are nonempty arrays of
strings. Requests are processed in order; nonzero tool exits are returned so the
adapter can recover. The adapter must wait for outstanding responses before
exiting. Exit zero means it finished; a nonzero exit is an agent failure. Send
diagnostics to stderr, reserving stdout for protocol requests. Malformed or
duplicate requests stop the adapter and its active tools.

Every application file operation also goes through `exec`, for example using
`cat` to read a file or `node` to write one. An adapter integrating an agent
runtime must disable its direct host file and shell tools and replace them with
this broker. **The host adapter is trusted, not an OS sandbox for arbitrary
agents.** A raw `claude -p` command does not implement this protocol; it needs an
adapter and enforced tool restrictions in that runtime. This implementation
does not claim those restrictions exist merely because a command was supplied.

The harness enforces the wall-clock deadline and a separate limit on broker
requests (`agents.limits.toolCalls`, default 200). On timeout it terminates the
adapter process group and isolated tools, preserves `agent-limit`, and skips
post-agent Git commands. `HARNESS_MAX_MODEL_TURNS` communicates
`agents.limits.turns` (default 200) to the trusted adapter, which must configure
its model runtime to enforce that budget. Tool-call counts are not model-turn
counts. `HARNESS_MAX_TOOL_CALLS` and
`HARNESS_BROKER_PROTOCOL=json-lines-exec-v1` describe the broker contract.

## Oracle acceptance

After read-only behavior checks, the driver compares the Oracle's original
DynamoDB `__source`/`__hmac` and Postgres `c`/`hm` values before performing any
mutations. Metadata changes alone do not fail this comparison. The mutation
checks then run, followed by the migration layer: old Protect imports and npm
dependencies must be gone, every FFI lockfile entry must match the actual
version selected for the exact Stack dependency, the endpoint shim must be
removed. The import, dependency and shim checks read both the Migrator workspace
and the App Host's installed copy after its lifecycle scripts. For the DynamoDB
procedure only, stored Mutation Data must contain no `active__hmac` immediately
after `setActive`, before any read or later write can repair it. PostgreSQL runs
require `requiredPostgresChecks` instead, which has no `active__hmac` check.
Missing checks or missing inspection evidence prevent a pass.

Diff evidence uses the host-recorded fixture commit, so an adapter can commit
its changes without hiding them. Failed Git commands fail the migration stage
instead of publishing an empty diff. Raw transcripts and snapshots remain local
Run artifacts; this command does not export them to an Editor.

## Deterministic acceptance matrix

Use `harness:run --fake reference` for the known-correct migration. Other variants
are `noop`, `downcase`, `stale-hmac`, `bigint`, `rewrite`, `missing-log`,
`legacy-ffi`, `denied-app` and `denied-lifecycle`. These harness-owned substitutes
copy application files; dependency installation and application execution stay
inside isolation. The hidden Reference Migration is never mounted into an actor.

`--stack` also accepts `tree` or a `.tgz` path. Tree mode requires Stack build
outputs and packs them with pnpm. Exact versions and tarball SHA-256 digests are
recorded in the manifest. Set `HARNESS_LIVE=1` and the four `CS_*` credentials
to run the credentialed self-test matrix; CI runs it without model calls.
