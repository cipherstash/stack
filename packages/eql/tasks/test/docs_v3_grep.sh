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

if [ "$status" -eq 0 ]; then
  echo "OK: no user-facing doc references eql_v2 (${#DOC_FILES[@]} files scanned)."
else
  echo >&2
  echo "The eql_v2 surface was removed in 3.0.0; user-facing docs must teach only eql_v3." >&2
  echo "If a mention is genuinely historical/internal, move it under an excluded path" >&2
  echo "(docs/upgrading, docs/development) or add that path to EXCLUDE_RE here." >&2
fi
exit "$status"
