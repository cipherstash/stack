# shellcheck shell=bash
# Catalog/.gitignore-driven stub preamble for the no-creds SQLx inventory gates.
#
# The inventory/coverage tasks compile a test binary just to `--list` its test
# names; they never RUN a test. But those binaries `include_str!` the gitignored,
# creds-generated fixtures at COMPILE time, so a bare worktree without CipherStash
# creds (the no-creds matrix-coverage CI job, or a checkout that has not run
# `mise run test:sqlx:prep`) cannot even compile them. Empty stub files satisfy
# `include_str!` perfectly for a `--list`.
#
# SOURCE this (don't execute it): it sets the cleanup trap in the caller's shell.
# It only CREATES the stubs — each task lists its own binary afterwards. It
# stubs the COMPLETE generated-fixture set (cheap, harmless extras are fine),
# so one helper serves every no-creds task regardless of which binary it lists.
#
# The set is derived from the two sources of truth, not from parsing rustc
# errors (an earlier preamble looped over compile-error text — brittle, coupled
# to rustc's wording, capped at 12 retries):
#   1. Catalog scalar tokens (`eql-codegen list-types`) -> `eql_v3_<token>.sql`
#      AND `eql_v3_<token>_doubles.sql` (the per-type doubles fixture the
#      cross-ciphertext oracle `include_str!`s), both covered by the
#      `tests/sqlx/fixtures/eql_v3*` .gitignore glob. A new scalar is stubbed
#      automatically. The doubles variant is stubbed for every token, not only
#      the comparison-capable ones that have a real doubles fixture — a harmless
#      extra under this helper's stub-the-complete-set policy.
#   2. The literal `tests/sqlx/fixtures/*.sql` entries in `.gitignore` (the
#      non-catalog generated fixtures: `v3_ste_vec`, `v3_doc_int4`,
#      `v3_numeric_collision`). A newly-generated fixture is stubbed
#      automatically once it is gitignored (which it must be — never committed).
#
# If a NEW compile-time `include_str!` target ever appears that is neither, the
# task's own `--list` fails with rustc's clear "couldn't read <path>" error —
# gitignore the new fixture (you must) and it is covered.
#
# Inputs (set before sourcing):
#   EQL_ROOT  - repo root (mise `{{config_root}}`). Falls back to two levels up
#               from the task's `tests/sqlx` working directory.
#
# Bash 3.2 compatible (macOS): created stubs are tracked in a temp file. Keep in
# step with `tasks/test/sqlx-archive.sh` / `test:sqlx:prep`, which produce the
# REAL fixtures for the jobs that actually run tests.

__eql_stub_root="${EQL_ROOT:-$(cd ../.. && pwd)}"
__eql_stub_dir="${__eql_stub_root}/tests/sqlx/fixtures"

__eql_stub_created=$(mktemp)
trap 'while IFS= read -r f; do [ -n "$f" ] && rm -f "$f"; done < "$__eql_stub_created"; rm -f "$__eql_stub_created"' EXIT

# (1) Catalog scalar tokens -> eql_v3_<token>.sql + eql_v3_<token>_doubles.sql.
# A failure here aborts under the caller's `set -e` with cargo's own error — no
# silent fallback.
__eql_stub_paths=""
__eql_stub_tokens=$(cd "$__eql_stub_root" && cargo run -q -p eql-codegen -- list-types)
while IFS= read -r __eql_stub_t; do
  [ -n "$__eql_stub_t" ] || continue
  __eql_stub_paths="${__eql_stub_paths}${__eql_stub_dir}/eql_v3_${__eql_stub_t}.sql
${__eql_stub_dir}/eql_v3_${__eql_stub_t}_doubles.sql
"
done <<EOF
$__eql_stub_tokens
EOF

# (2) Literal generated fixtures declared (gitignored) in .gitignore. The
# `eql_v3*` glob line has no `.sql` suffix, so this matches only the explicit
# v3_*.sql entries — the eql_v3 set is covered by (1).
__eql_stub_extra=$(grep -oE 'tests/sqlx/fixtures/[A-Za-z0-9_]+\.sql' "$__eql_stub_root/.gitignore" 2>/dev/null || true)
while IFS= read -r __eql_stub_rel; do
  [ -n "$__eql_stub_rel" ] || continue
  __eql_stub_paths="${__eql_stub_paths}${__eql_stub_root}/${__eql_stub_rel}
"
done <<EOF
$__eql_stub_extra
EOF

# Create each stub only when absent — real generated fixtures are never in the
# created list, so the trap leaves them untouched.
mkdir -p "$__eql_stub_dir"
while IFS= read -r __eql_stub_f; do
  [ -n "$__eql_stub_f" ] || continue
  if [ ! -e "$__eql_stub_f" ]; then
    : > "$__eql_stub_f"
    echo "$__eql_stub_f" >> "$__eql_stub_created"
  fi
done <<EOF
$__eql_stub_paths
EOF
