#!/usr/bin/env bash
set -euo pipefail

# Public source, generated artifacts, tests, changelogs, and documentation must
# not disclose identifiers or links from CipherStash's private issue tracker.
# Split the literals so this guard does not match itself.
issue_prefix='CI''P-'
tracker_host='linear.app/''cipherstash'
pattern="${issue_prefix}[0-9]+|${tracker_host}"

if git grep -n -E "$pattern" -- . ':!tasks/test/public_identifiers.sh'; then
  echo "FAIL: tracked files contain private issue identifiers or tracker links." >&2
  echo "Describe the public behavior directly or link to a public GitHub issue." >&2
  exit 1
fi

echo "No private issue identifiers or tracker links found."
