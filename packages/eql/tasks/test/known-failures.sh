#!/usr/bin/env bash
#MISE description="Verify every known-failure marker points at a real, OPEN GitHub issue"
#
# A `known_failure` marker (tests/sqlx/src/known_failure.rs) suppresses a test
# failure. Two things keep that honest:
#
#   1. The Rust side is self-expiring: `known_failure()` FAILS once the wrapped
#      assertion starts passing, so a marker cannot outlive its bug.
#   2. This gate: every `ISSUE_*` constant must name an issue that exists and is
#      still OPEN. A marker pointing at a closed (or fixed, or wontfix'd, or
#      never-created) issue fails here.
#
# Together: you cannot suppress a failure without an open, identified bug, and
# you cannot keep suppressing it once the bug is closed.
#
# Needs `gh` authenticated (CI: GITHUB_TOKEN). Read-only.
#
# Portability: targets bash 3.2 (stock macOS /bin/bash), since mise.toml invokes
# this as `bash tasks/test/known-failures.sh`. No `mapfile`, no other bash-4
# features.
set -euo pipefail

EQL_ROOT="${EQL_ROOT:-$(git rev-parse --show-toplevel)}"
REGISTRY="${EQL_ROOT}/tests/sqlx/src/known_failure.rs"

[ -f "$REGISTRY" ] || { echo "missing known-failure registry: $REGISTRY" >&2; exit 2; }

# The repo the issue numbers refer to, read from the registry so it cannot drift.
repo=$(sed -n 's/^pub const KNOWN_FAILURE_REPO: &str = "\(.*\)";$/\1/p' "$REGISTRY")
[ -n "$repo" ] || { echo "could not read KNOWN_FAILURE_REPO from $REGISTRY" >&2; exit 2; }

# Count declarations with a LOOSE matcher (anything that reads as an `ISSUE_*`
# constant), independently of the strict parse below. If the strict parse
# recovers FEWER rows than were declared, the format drifted (a `u32`, a renamed
# type, a malformed line) and the strict regex would silently skip markers. A
# gate that parses zero rows and exits 0 is the exact fail-open this check exists
# to prevent, so a declared-vs-parsed mismatch is a hard error, never a pass.
declared=$(grep -cE '^[[:space:]]*pub const ISSUE_[A-Za-z0-9_]+[[:space:]]*:' "$REGISTRY" || true)

# Strict parse: `pub const ISSUE_<NAME>: u64 = <n>;` → "<NAME> <n>". Tolerant of
# leading indentation, a trailing line comment, and `_` digit separators so that
# benign formatting is not mistaken for drift; the type must still be `u64`.
# bash 3.2-safe accumulation (no `mapfile`): a while-read loop over a process
# substitution runs in the current shell, so the array persists after the loop.
entries=()
while IFS= read -r line; do
  entries+=("$line")
done < <(
  sed -n -E \
    's/^[[:space:]]*pub const (ISSUE_[A-Z0-9_]+)[[:space:]]*:[[:space:]]*u64[[:space:]]*=[[:space:]]*([0-9_]+)[[:space:]]*;[[:space:]]*(\/\/.*)?$/\1 \2/p' \
    "$REGISTRY"
)
parsed=${#entries[@]}

if [ "$declared" -ne "$parsed" ]; then
  echo "known-failure gate: parsed ${parsed} of ${declared} declared ISSUE_ constant(s)." >&2
  echo '    The strict `pub const ISSUE_<NAME>: u64 = <n>;` parser skipped a declaration —' >&2
  echo "    a format change (wrong type, malformed line) would let a marker slip past this" >&2
  echo "    gate unverified. Fix the declaration or this parser; refusing to run." >&2
  exit 2
fi

if [ "$parsed" -eq 0 ]; then
  echo "==> no known-failure markers registered — nothing to verify."
  exit 0
fi

echo "==> verifying ${parsed} known-failure marker(s) against ${repo}"

# Classify one issue number via the REST issues endpoint. Prints exactly one of
#   OPEN | CLOSED | PULL_REQUEST | NOT_FOUND | ERROR:<detail>
# on stdout, and never itself exits non-zero (the caller decides pass/fail).
#
# Using `gh api repos/<repo>/issues/<n>` — rather than `gh issue view` — closes
# two review findings:
#   * T3: a TRANSIENT failure (5xx, rate-limit, unauthenticated, DNS) is
#     distinguishable from a genuine 404. `gh api` reports a missing issue as
#     `(HTTP 404)` and everything else with a different message, so a network
#     blip no longer masquerades as "issue missing" (nor the reverse).
#   * T15: issues and PRs share a number space and `gh issue view` happily
#     resolves a PR number. The REST issues object carries a `pull_request` key
#     iff the number is a PR, so PRs are rejected instead of passing as issues.
classify_number() {
  number="$1"
  err_file=$(mktemp)
  # On HTTP 200 the bundled `--jq` prints "<state>\t<is_pr>"; on any HTTP/network
  # error `gh` exits non-zero and writes the reason to stderr (jq is not applied).
  if out=$(gh api "repos/${repo}/issues/${number}" \
             --jq '"\(.state)\t\(has("pull_request"))"' 2>"$err_file"); then
    rm -f "$err_file"
    state="${out%%$'\t'*}"
    is_pr="${out##*$'\t'}"
    if [ "$is_pr" = "true" ]; then
      echo "PULL_REQUEST"
      return 0
    fi
    case "$state" in
      open)   echo "OPEN" ;;
      closed) echo "CLOSED" ;;
      *)      echo "ERROR:unexpected issue state '${state}'" ;;
    esac
    return 0
  fi

  err=$(cat "$err_file"); rm -f "$err_file"
  # A definitive 404 is a genuinely missing issue; anything else is transient
  # infrastructure and must NOT read as "missing".
  if printf '%s' "$err" | grep -qi 'HTTP 404'; then
    echo "NOT_FOUND"
  else
    # Collapse to a single line so the caller's diagnostic stays readable.
    echo "ERROR:$(printf '%s' "$err" | tr '\n' ' ' | sed 's/[[:space:]]\{1,\}/ /g')"
  fi
}

# A marker whose constant is never referenced by a test is dead weight: the bug
# may be long fixed and nobody noticed. Catch that too.
fail=0
for entry in "${entries[@]}"; do
  name=${entry%% *}
  number=${entry##* }
  number=${number//_/}   # `1_000` (Rust literal) → 1000 for the API path

  # `grep` exits 1 when it matches nothing — which is exactly the case this check
  # exists to report. Under `set -e` + `pipefail` that status propagates out of
  # the pipeline and kills the script here, before the diagnostic below can
  # print. Swallow only grep's status; `wc` still counts the (empty) input.
  refs=$( { grep -rl --include='*.rs' -- "$name" "${EQL_ROOT}/tests/sqlx/tests" 2>/dev/null || true; } | wc -l | tr -d ' ')
  if [ "$refs" -eq 0 ]; then
    echo "  ✗ ${name} (#${number}) is registered but referenced by no test — remove it" >&2
    fail=1
    continue
  fi

  result=$(classify_number "$number")
  case "$result" in
    OPEN)
      echo "  ✓ ${name} → ${repo}#${number} is OPEN (${refs} test ref(s))"
      ;;
    CLOSED)
      echo "  ✗ ${name} → ${repo}#${number} is CLOSED." >&2
      echo "    Either the bug is fixed (delete the marker and let the assertion run)" >&2
      echo "    or it was closed in error (reopen it)." >&2
      fail=1
      ;;
    PULL_REQUEST)
      echo "  ✗ ${name} → ${repo}#${number} is a PULL REQUEST, not an issue." >&2
      echo "    Issues and PRs share a number space; point the marker at the tracking issue." >&2
      fail=1
      ;;
    NOT_FOUND)
      echo "  ✗ ${name} → ${repo}#${number} does not exist." >&2
      echo "    A known-failure marker must name a real issue." >&2
      fail=1
      ;;
    ERROR:*)
      echo "  ✗ ${name} → ${repo}#${number} could not be verified (${result#ERROR:})." >&2
      echo "    This looks like a transient GitHub/network error, not a missing issue —" >&2
      echo "    re-run the gate; if it persists, check gh auth / GitHub status." >&2
      fail=1
      ;;
    *)
      echo "  ✗ ${name} → ${repo}#${number}: unexpected classifier result '${result}'." >&2
      fail=1
      ;;
  esac
done

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "known-failure gate FAILED: a suppressed test must have an open, identified issue." >&2
  exit 1
fi

echo "known-failure gate OK"
