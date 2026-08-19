#!/usr/bin/env bash
#MISE description="Fail if any user-facing doc still references the removed eql_v2 surface"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# The eql_v2 schema and its entire surface were removed in 3.0.0 (see CHANGELOG).
# User-facing product documentation must teach only the eql_v3 surface — no doc
# in scope below may mention eql_v2.
#
# SCOPE IS INVERTED ON PURPOSE. Rather than allowlisting the specific files to
# check (which silently leaves every newly added doc unchecked), this scans the
# whole user-facing doc surface and fails on any eql_v2 match. A new reference or
# tutorial page is therefore covered with no edit to this script.
#
# In scope:
#   - the root entry-point docs in ROOT_DOCS below
#   - every git-tracked *.md under docs/ EXCEPT the excluded subtrees
#
# Enumeration is over GIT-TRACKED files (git ls-files), so it matches exactly
# what CI checks out and what ships. Untracked local scratch — e.g. a tooling
# working directory like docs/superpowers/ — is naturally ignored, and local
# runs agree with CI.
#
# Out of scope (NOT scanned) — these legitimately retain eql_v2 and are excluded
# by path, not by silent omission:
#   docs/upgrading/      historical upgrade guides for the v2.x line
#   docs/development/     internal contributor/process docs (release runbook, etc.)
#   CHANGELOG.md          the permanent release record (documents the v2 removal)
#   CLAUDE.md             project/dev instructions (describe the removal + provenance)
#   DEVELOPMENT.md        contributor guide; its eql_v2 mentions are the removal
#                         note + self-containment invariants ("no eql_v2 symbol"),
#                         reviewed by hand rather than grep-gated
#   .github/, tests/, src/  not product documentation

# Root entry-point docs that teach end users.
ROOT_DOCS=(
  "README.md"
  "SUPABASE.md"
  "docker/README.md"
)

# docs/ subtrees that legitimately keep eql_v2 references.
EXCLUDE_RE='^docs/(upgrading|development)/'

mapfile -t DOC_FILES < <(
  {
    printf '%s\n' "${ROOT_DOCS[@]}"
    git ls-files -- docs | grep -E '\.md$'
  } | grep -vE "$EXCLUDE_RE" | sort -u
)

status=0
for f in "${DOC_FILES[@]}"; do
  [ -f "$f" ] || continue
  if hits=$(grep -nE 'eql_v2' "$f"); then
    echo "FAIL: $f references the removed eql_v2 surface:" >&2
    echo "$hits" >&2
    status=1
  fi
done

# Deprecated SQL compatibility aliases remain installed, but the explicitly
# hidden block must never reach Doxygen — including its generated source browser.
ste_vec_alias_count=$(grep -c '^CREATE FUNCTION eql_v3\.ste_vec_contains' src/v3/json/functions.sql || true)
if [ "$ste_vec_alias_count" -ne 2 ]; then
  echo "FAIL: expected both deprecated ste_vec_contains overloads in src/v3/json/functions.sql" >&2
  status=1
else
  # CAPTURE, THEN MATCH — never `doxygen-filter.sh ... | grep -q ...`. `grep -q`
  # exits at the first match and closes the pipe; the filter's awk then takes
  # SIGPIPE and exits 141, and `set -o pipefail` makes that the pipeline's
  # status. So the LEAK path — the one this guard exists for — scored as "no
  # match" and the FAIL branch never ran, while the clean path (grep reads to
  # EOF, exits 1) reported correctly. A check that can only ever say OK.
  #
  # Measured at 141 against the real filter output on macOS. Linux's larger
  # pipe buffer absorbed the ~16 KB and hid it, so this was a platform split
  # rather than an obvious bug. Guarded repo-wide by
  # scripts/__tests__/workflow-grep-q-pipelines.test.mjs.
  #
  # A separate assignment also means `set -e` aborts if the filter itself
  # fails, instead of the old pipeline quietly scoring a crashed filter as a
  # pass.
  filtered_sql=$(tasks/docs/doxygen-filter.sh src/v3/json/functions.sql)
  if grep -q 'ste_vec_contains' <<< "$filtered_sql"; then
    echo "FAIL: deprecated ste_vec_contains aliases leaked through the Doxygen input filter" >&2
    status=1
  fi
fi

if [ "$status" -eq 0 ]; then
  echo "OK: user-facing docs contain neither eql_v2 nor the hidden ste_vec_contains alias (${#DOC_FILES[@]} files scanned)."
else
  echo >&2
  echo "The eql_v2 surface was removed in 3.0.0; user-facing docs must teach only eql_v3." >&2
  echo "If a mention is genuinely historical/internal, move it under an excluded path" >&2
  echo "(docs/upgrading, docs/development) or add that path to EXCLUDE_RE here." >&2
fi
exit "$status"
