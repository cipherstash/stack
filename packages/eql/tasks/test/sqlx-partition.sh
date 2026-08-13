#!/usr/bin/env bash
#MISE description="Run one hash partition of the sqlx suite from a prebuilt nextest archive"

# bash is pinned via the shebang so pipefail is available on dash-based runners.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Required: which shard (1-based) and how many shards total.
: "${SHARD:?SHARD (1-based shard index) must be set}"
: "${SHARD_TOTAL:?SHARD_TOTAL (number of shards) must be set}"
# A relative NEXTEST_ARCHIVE is resolved against REPO_ROOT; an absolute override
# is used verbatim (matching tasks/test/sqlx-archive.sh).
ARCHIVE_INPUT="${NEXTEST_ARCHIVE:-nextest.tar.zst}"
case "${ARCHIVE_INPUT}" in
  /*) ARCHIVE_PATH="${ARCHIVE_INPUT}" ;;
  *)  ARCHIVE_PATH="${REPO_ROOT}/${ARCHIVE_INPUT}" ;;
esac

test -f "${ARCHIVE_PATH}" \
  || { echo "archive ${ARCHIVE_PATH} missing — run test:sqlx:archive / download the artifact first" >&2; exit 2; }

# The archive already carries everything compiled-in: build-archive ran prep
# (build → cp 001_install_eql.sql → sqlx migrate → fixture:generate:all) BEFORE
# `cargo nextest archive`, so the migration AND the per-type fixtures are
# include_str!'d into the binaries. The shard therefore does NOT re-run prep or
# regenerate fixtures — doing so would force a full `cargo test` compile on every
# shard (defeating the build-once archive) for no effect, since sqlx::test uses
# the embedded copies. `sqlx::test` provisions its own per-test scratch databases
# against the live Postgres (the job's postgres:up step) and applies the embedded
# migrations + fixtures to each.
#
# The only on-disk runtime dependency is release/*.sql (read by
# build_validation_tests via std::fs); those arrive with the downloaded artifact.
# release/ is NOT touched here — no cp, no migrate, no CS_* — the shard just runs
# the prebuilt binaries.
echo "==> running nextest partition hash:${SHARD}/${SHARD_TOTAL} from ${ARCHIVE_PATH}"
cd tests/sqlx
cargo nextest run \
  --archive-file "${ARCHIVE_PATH}" \
  --workspace-remap "${REPO_ROOT}" \
  --partition "hash:${SHARD}/${SHARD_TOTAL}"
