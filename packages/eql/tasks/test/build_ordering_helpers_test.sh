#!/usr/bin/env bash
#MISE description="DB-free unit tests for tasks/build/ordering.sh (anchored REQUIRE strip)"
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
source tasks/build/ordering.sh

# strip_require_lines is all that remains in ordering.sh: the tsort cycle gate and
# the linearization checker moved into `eql-codegen order`, and are covered by the
# eql-codegen crate's ordering:: unit tests.

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# 1. Anchored strip keeps a body line that merely contains the substring REQUIRE.
printf -- '-- REQUIRE: src/v3/schema.sql\nSELECT 1; -- the REQUIRE keyword in prose\n' > "$tmp/body.sql"
out="$(strip_require_lines "$tmp/body.sql")"
[[ "$out" == "SELECT 1; -- the REQUIRE keyword in prose" ]] || { echo "FAIL: strip removed non-directive line: [$out]"; exit 1; }
echo "ok: anchored strip preserves non-directive REQUIRE substring"

# 2. strip_require_lines must FAIL (not silently succeed) on an unreadable file —
# a real grep error (exit >= 2) propagates so `set -e` aborts a truncated build.
if strip_require_lines "$tmp/does-not-exist.sql" 2>/dev/null; then
  echo "FAIL: strip_require_lines swallowed a missing-file error"; exit 1
fi
echo "ok: strip_require_lines propagates a real grep failure"

# 3. A file that is ENTIRELY -- REQUIRE: lines (grep exit 1, nothing left) is
# NOT an error — it contributes no body and must succeed with empty output.
printf -- '-- REQUIRE: a\n-- REQUIRE: b\n' > "$tmp/allreq.sql"
out="$(strip_require_lines "$tmp/allreq.sql")" || { echo "FAIL: all-REQUIRE file treated as error"; exit 1; }
[[ -z "$out" ]] || { echo "FAIL: all-REQUIRE file produced output: [$out]"; exit 1; }
echo "ok: all-REQUIRE file succeeds with empty output"

echo "ALL build-ordering helper tests passed"
