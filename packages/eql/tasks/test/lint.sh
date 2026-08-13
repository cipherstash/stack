#!/usr/bin/env bash
#MISE description="Run lint tests"

set -euo pipefail

(
  cd tests/sqlx/
  cargo fmt --check -- --files-with-diff
)
