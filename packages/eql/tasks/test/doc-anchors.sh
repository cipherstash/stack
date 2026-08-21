#!/usr/bin/env bash
#MISE description="Verify every intra-document markdown anchor link resolves to a real heading"
#
# A `[text](#fragment)` link that names no heading is a silently broken link: it
# renders fine, and clicking it just does nothing. The upgrade guides lean on
# these heavily to cross-link numbered notes (U-NNN) from the summary and the
# compatibility table, so a stale fragment quietly strands the reader on exactly
# the passage that was meant to explain a breaking change.
#
# Scope: hand-written markdown only. `docs/api/` is Doxygen-generated and
# gitignored (its anchors are the generator's problem, not a reviewable defect).
#
# Anchor derivation mirrors GitHub's `github-slugger`: lowercase, strip
# punctuation, then map EACH remaining space to a hyphen — note `/ /` and not
# `/ +/`, so `to `@@` / `x`` collapses to `to---x` (three hyphens), not one.
# Repeated headings get GitHub's `-1`, `-2`, … disambiguation suffixes.
#
# The punctuation class must cover NON-ASCII too: `github-slugger` strips the
# whole Unicode punctuation/symbol range, so an em-dash or a `→` in a heading
# vanishes and leaves its surrounding spaces behind as separate hyphens. Both
# appear in these docs. Rather than transcribe that range, keep only
# `[a-z0-9_ -]` (post-`tolower`) and drop the rest — under `LC_ALL=C` awk works
# on bytes, so every byte of a multi-byte char is dropped together.
#
# Known divergence: this also strips accented letters, which GitHub keeps. No
# heading in this repo has one, and the gate is byte-exact for ASCII headings.
#
# Portability: bash 3.2 (no associative arrays), awk for the slug computation.
set -euo pipefail

# Byte-wise matching, so the class below reaches inside multi-byte characters.
export LC_ALL=C

EQL_ROOT="${EQL_ROOT:-$(git rev-parse --show-toplevel)}"
cd "$EQL_ROOT"

# Emit every heading's anchor for the file on stdin, GitHub-style.
anchors_of() {
  awk '
    function slug(h,   s) {
      s = tolower(h)
      gsub(/[^a-z0-9_ -]/, "", s)
      gsub(/ /, "-", s)
      return s
    }
    /^```/ { fence = !fence; next }
    fence { next }
    /^#{1,6}[ ]/ {
      title = $0
      sub(/^#+[ ]+/, "", title)
      sub(/[ ]+$/, "", title)
      a = slug(title)
      # GitHub disambiguates repeats: first stays bare, then -1, -2, ...
      if (a in seen) { print a "-" seen[a]; seen[a]++ }
      else           { print a; seen[a] = 1 }
    }
  ' "$1"
}

# Emit "<line>:<fragment>" for every intra-document link in the file.
links_of() {
  awk '
    /^```/ { fence = !fence; next }
    fence { next }
    {
      line = $0
      while (match(line, /\]\(#[^)]+\)/)) {
        frag = substr(line, RSTART + 3, RLENGTH - 4)
        print NR ":" frag
        line = substr(line, RSTART + RLENGTH)
      }
    }
  ' "$1"
}

files=$(git ls-files '*.md' ':!:docs/api/*' | sort)
[ -n "$files" ] || { echo "doc-anchor gate: no markdown files found" >&2; exit 2; }

broken=0
checked=0
for f in $files; do
  anchor_file=$(mktemp)
  anchors_of "$f" > "$anchor_file"
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    line=${entry%%:*}
    frag=${entry#*:}
    checked=$((checked + 1))
    if ! grep -qxF -- "$frag" "$anchor_file"; then
      echo "  ✗ ${f}:${line} → #${frag} matches no heading" >&2
      broken=$((broken + 1))
    fi
  done < <(links_of "$f")
  rm -f "$anchor_file"
done

if [ "$broken" -ne 0 ]; then
  echo >&2
  echo "doc-anchor gate FAILED: ${broken} broken intra-document link(s) of ${checked} checked." >&2
  echo "    Fix the fragment, or the heading it should point at." >&2
  exit 1
fi

echo "doc-anchor gate OK — ${checked} intra-document link(s) resolve"
