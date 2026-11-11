# Claude Migrator adapter

The trusted host runs Claude Code. The model gets one MCP tool, `exec`, which
forwards argument arrays to the harness's existing isolation broker. Commands,
file reads and file writes therefore execute in the Migrator Environment, with
the same filesystem and network policy as Fake Migrators.

## Run

Install a recent Claude Code CLI supporting `--bare`, `--restricted` and
`--permission-prompts none` on the trusted host. Supply one model credential
through the host's secret environment:

- `ANTHROPIC_API_KEY`, billed to an API account. The CLI runs with `--bare`.
- `CLAUDE_CODE_OAUTH_TOKEN`, a long-lived Claude subscription token created
  with `claude setup-token`. `--bare` never reads OAuth credentials, so the CLI
  runs without it; the remaining flags, the empty configuration directory and
  the initialization check below still apply. Usage counts against the
  subscription's limits.

When both are set the API key is used. The adapter deliberately does not use a
Claude login session, keychain, provider overrides, or an API-key helper.
CipherStash and store credentials remain owned by the harness.

Pass an **absolute** adapter path because the broker starts it in an empty
working directory:

```sh
pnpm --filter @cipherstash/e2e harness:run \
  --migrator 'node /absolute/path/to/stack/e2e/migration-harness/run/claude-adapter.mjs' \
  [other harness options]
```

The same adapter works with each supported migration procedure. It follows the
Run's staged guide at `/workspace/migration-guide.md`, upgrades the Fixture App,
and writes `/workspace/friction.json`. It receives no previous Run Reports,
Friction Logs, Oracle results, or Reference Migration.

## Configuration and evidence

The default model is `sonnet`, with `acceptEdits` permission mode, a 200-turn
budget and a 40-minute outer deadline. The broker passes the configured turn
budget to the adapter; Claude's documented `--max-turns` enforces it during print
mode, even though some CLI versions omit the flag from `--help`. The broker
separately enforces tool-call and wall-clock limits. A Claude turn-limit result
returns exit code 124. See the [Claude CLI reference](https://code.claude.com/docs/en/cli-reference).

Each invocation uses an empty temporary working/configuration directory and an
allowlisted environment. Built-in tools, implicit MCP servers, settings sources,
slash commands, hooks, automatic memory, browser access and persistent sessions
are disabled. The adapter checks Claude's initialization record for the expected
tool set and permission mode, then records the CLI version, resolved model
identifier and final turn count in `manifest.agents.runtime`. Model text never
becomes a broker request. CLI stderr is consumed but not exported, because it can
contain provider details. The broker transcript records the actual isolated
command requests and runtime metadata; the broker also returns tool-call exit codes.

The MCP bridge connects through a private Unix socket and a per-run token. It
accepts only `exec` with a string argument array; the model cannot select a host
working directory, environment, mount or policy. The model credential is supplied
only to the host CLI and explicitly removed from the bridge's environment. The
adapter and CLI are trusted host code, not an additional security boundary
against a compromised host executable. Temporary configuration and socket files
are removed after execution.

## Verification

`harness:selftest` runs a fake CLI through the production MCP bridge and broker.
It checks isolated command dispatch, rejected execution-context overrides,
configuration/credential separation, resolved runtime metadata, malformed runtime
completion, unexpected tool/permission settings, and turn limits. These tests
make no model calls and need no Docker. They do need permission to create a local
Unix socket.

A real model Run for each procedure remains pending on a disposable remote host
selected by the maintainer. Real agents remain outside CI under the ADR; CI runs
deterministic Fake Migrators. Fake CLI coverage does not prove that an installed
Claude version can complete a migration or that the guide is sufficient for a
real model.
