#!/usr/bin/env bash
# NOTE: this script is invoked via `bash tasks/...` from an inline mise task, so
# `#MISE` directives here would be INERT (they only fire when mise auto-discovers
# a script as a file-task). The `test:sqlx:prep` dependency is therefore declared
# on the inline [tasks."test:sqlx:archive"] block.

# bash is pinned via the shebang (mise honors a `#!` first line) so pipefail is
# available regardless of the runner's /bin/sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Archive lands at the repo root so the workflow can upload it by a stable path.
# A relative NEXTEST_ARCHIVE is resolved against REPO_ROOT; an absolute override
# is used verbatim (otherwise it would be mangled into "${REPO_ROOT}/abs/path").
ARCHIVE_INPUT="${NEXTEST_ARCHIVE:-nextest.tar.zst}"
case "${ARCHIVE_INPUT}" in
  /*) ARCHIVE_PATH="${ARCHIVE_INPUT}" ;;
  *)  ARCHIVE_PATH="${REPO_ROOT}/${ARCHIVE_INPUT}" ;;
esac

# The mise task's `depends = ["test:sqlx:prep"]` has already produced
# release/cipherstash-encrypt.sql, copied it to migrations/001_install_eql.sql,
# and regenerated the per-type fixtures. These are NOT optional: the sqlx::test
# macros `include_str!` the migration + fixtures into the compiled binaries at
# COMPILE time, so they must be on disk before `cargo nextest archive` runs.
# Belt-and-braces: fail loudly if any are missing (e.g. the script was run
# directly, or without a live Postgres + CS_* for fixture generation).
test -f release/cipherstash-encrypt.sql \
  || { echo "release/cipherstash-encrypt.sql missing — run via 'mise run test:sqlx:archive' (it depends on test:sqlx:prep)" >&2; exit 2; }
test -f tests/sqlx/migrations/001_install_eql.sql \
  || { echo "tests/sqlx/migrations/001_install_eql.sql missing — prep did not run (needs a live Postgres)" >&2; exit 2; }
ls tests/sqlx/fixtures/eql_v3_*.sql >/dev/null 2>&1 \
  || { echo "tests/sqlx/fixtures/eql_v3_*.sql missing — fixture:generate:all did not run (needs Postgres + CS_* creds)" >&2; exit 2; }

# Compile every tests/sqlx test binary with DEFAULT features and pack them. The
# migration + fixtures (embedded via include_str at compile time) are baked into
# the archive, so the shards consume them without regenerating. The shards still
# need their own live Postgres for sqlx::test's per-test scratch databases.
echo "==> archiving sqlx test binaries to ${ARCHIVE_PATH}"
cd tests/sqlx
cargo nextest archive --archive-file "${ARCHIVE_PATH}"

echo "==> archive written: ${ARCHIVE_PATH}"
