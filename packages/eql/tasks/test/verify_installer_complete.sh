#!/usr/bin/env bash
#MISE description="Assert release/cipherstash-encrypt.sql contains the body of every ordered src/v3 file (DB-free)"
#
# The order→artefact gate. `eql-codegen order` guarantees the ORDER LIST contains
# every .sql file on disk (pinned by install_order_contains_every_v3_sql_file in
# the eql-codegen parity tests). This gate closes the layer below: that build.sh's
# concat loop actually emitted each ordered file's body into the installer.
#
# Why that layer needs its own gate: 93 of the ~244 files in src/v3 are LEAVES —
# no other file `-- REQUIRE:`s them, and several define no object that any
# inventory test enumerates (a bare `DO` block; functions in eql_v3_internal; a
# `CREATE OPERATOR CLASS`). Drop a leaf and the monolith still applies cleanly and
# every symbol still resolves, so an install smoke test passes. A
# referenced-vs-defined checker (verify_symbol_order_v3.sh) is blind to it by
# construction: a dropped leaf removes its definition AND, being a leaf, leaves no
# reference dangling to trip on. The loss surfaces only in a DB behavioural test —
# which needs CipherStash credentials and is skipped on fork PRs.
#
# So this gate does not look for symbols. It does arithmetic on lines, which no
# leaf can hide from.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

ORDERED="${1:-src/deps-ordered-v3.txt}"
INSTALLER="${2:-release/cipherstash-encrypt.sql}"
PIN="tasks/pin_search_path_v3.sql"

for f in "$ORDERED" "$INSTALLER" "$PIN"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: $f missing — run 'mise run build' first" >&2
    exit 2
  fi
done

# `grep -c ''` counts a final line that lacks a trailing newline; `wc -l` does not.
# The trailing-newline gate below makes the two agree, but count the honest way.
#
# grep exits 1 on an empty file (zero lines — legitimate) and >= 2 on a real fault
# (missing, unreadable). Same rc <= 1 idiom as strip_require_lines in
# tasks/build/ordering.sh. A blanket `|| true` would print nothing on a fault, and
# the caller's `$(( expected + total - reqs ))` reads that empty string as 0 — the
# file silently contributes nothing to the identity. Gate 1 makes that unreachable
# today, but this script's whole job is to fail loudly.
#
# Every caller is `var=$(count_lines f)`, so this `exit 2` leaves only the
# command-substitution subshell; the parent aborts because `set -e` sees the
# failed assignment. Keep the callers as bare assignments — `local n=$(...)` or a
# `|| true` would mask the status and restore the silent-zero this replaces.
count_lines() {
  local n rc=0
  n=$(grep -c '' "$1") || rc=$?
  if (( rc > 1 )); then
    echo "ERROR: cannot count lines in $1 (grep exit $rc)" >&2
    exit 2
  fi
  echo "${n:-0}"
}

fail=0

# ---------------------------------------------------------------------------
# Gate 1: non-vacuity. The ordered list must name every .sql file on disk.
#
# Without this, an empty or truncated order list sails through every other gate:
# verify_symbol_order_v3.sh prints "OK (0 files)", the self-containment file gate
# finds no offending path, and build.sh emits an installer holding nothing but the
# pin script. Every check green, nothing shipped. Compare against an INDEPENDENT
# find(1) rather than trusting the list's own length.
# ---------------------------------------------------------------------------
echo "==> Non-vacuity gate: the order names every src/v3 SQL file"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
find src/v3 -type f -name '*.sql' ! -name '*_test.sql' | LC_ALL=C sort > "$work/disk"
grep -v '^[[:space:]]*$' "$ORDERED" | LC_ALL=C sort > "$work/order" || true
n_disk=$(count_lines "$work/disk")

if [[ "$n_disk" -eq 0 ]]; then
  echo "ERROR: no .sql files found under src/v3 — refusing to validate an empty surface" >&2
  exit 1
fi

# Report at most 10 offenders per direction. An empty order list would otherwise
# print every file in the surface and bury the verdict under 244 lines.
# comm(1) needs real files, not process substitutions: the list is read twice.
report_missing() {
  local label=$1 file=$2 n
  n=$(count_lines "$file")
  if [[ "$n" -gt 0 ]]; then
    echo "ERROR: $n file(s) $label:" >&2
    head -10 "$file" | sed 's/^/    /' >&2
    if [[ "$n" -gt 10 ]]; then
      echo "    … and $(( n - 10 )) more" >&2
    fi
    fail=1
  fi
  return 0
}
comm -23 "$work/disk" "$work/order" > "$work/only_disk"
comm -13 "$work/disk" "$work/order" > "$work/only_order"
report_missing "on disk but absent from $ORDERED (they will not ship)" "$work/only_disk"
report_missing "named in $ORDERED but absent from disk" "$work/only_order"
if [[ $fail -eq 0 ]]; then
  echo "    $n_disk files, order matches disk"
fi

# ---------------------------------------------------------------------------
# Gate 2: every ordered file ends with a newline.
#
# build.sh assembles with `>>`. A file whose last line has no trailing newline
# would glue its final statement onto the first line of the next file — silently
# producing different SQL, not a syntax error. Nothing else checks this.
# ---------------------------------------------------------------------------
echo "==> Trailing-newline gate: no file can glue onto the next on concat"
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  if [[ -s "$f" && -n "$(tail -c1 "$f")" ]]; then
    echo "ERROR: $f has no trailing newline — concatenation would merge it with the next file" >&2
    fail=1
  fi
done < "$ORDERED"

# ---------------------------------------------------------------------------
# Gate 3: line-count identity.
#
#   Σ_f (lines(f) − anchored REQUIRE lines(f))  +  lines(pin script)  ==  lines(installer)
#
# build.sh strips exactly the anchored `-- REQUIRE:` directives (strip_require_lines
# in tasks/build/ordering.sh) and appends the pin script. So the installer's line
# count is a pure function of the ordered inputs. A dropped file, a truncated body,
# or a duplicated file all break the arithmetic. The REQUIRE regex here MUST match
# strip_require_lines' — keep them in lockstep.
# ---------------------------------------------------------------------------
echo "==> Line-count identity: installer == Σ ordered bodies + pin script"
expected=0
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  total=$(count_lines "$f")
  reqs=$(grep -cE '^[[:space:]]*-- REQUIRE:' "$f" || true)
  expected=$(( expected + total - reqs ))
done < "$ORDERED"
expected=$(( expected + $(count_lines "$PIN") ))
actual=$(count_lines "$INSTALLER")

if [[ "$expected" -ne "$actual" ]]; then
  echo "ERROR: installer has $actual lines, expected $expected from the ordered inputs" >&2
  echo "       (difference of $(( actual - expected )) lines — a file's body was dropped, truncated, or emitted twice)" >&2
  fail=1
else
  echo "    $actual lines accounted for"
fi

if [[ $fail -ne 0 ]]; then
  echo "installer completeness gate FAILED" >&2
  exit 1
fi
echo "installer completeness gate OK"
