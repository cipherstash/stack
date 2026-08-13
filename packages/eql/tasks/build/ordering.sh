#!/usr/bin/env bash
# Sourceable helpers for the eql_v3 build. No side effects on source; each
# function is pure w.r.t. its args. Shared with the staged-installer refactor
# (do not fork strip_require_lines).
#
# Dependency ordering itself now lives in `eql-codegen order` (see
# crates/eql-codegen/src/ordering.rs), which walks src/v3 once and topologically
# sorts the whole surface. The shell tsort wrapper and linearization checker this
# file used to carry are gone with the two-block build they served.

# Emit a file's body with anchored `-- REQUIRE:` directive lines removed. Anchored
# (allows leading whitespace) so a body line that merely contains the substring
# "REQUIRE" survives — unlike the old unanchored `grep -v REQUIRE`.
strip_require_lines() {
  local rc=0
  grep -vE '^[[:space:]]*-- REQUIRE:' "$1" || rc=$?
  # grep exits 1 when EVERY line matched the exclude (nothing left) — not an
  # error. Exit codes >= 2 (missing file, unreadable, bad regex) are real
  # failures: propagate so `set -e` aborts assembly instead of silently emitting
  # a truncated monolith. (The blanket `|| true` this replaces hid exit 2.)
  (( rc <= 1 ))
}
