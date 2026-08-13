#!/usr/bin/env bash
# Unit test for prepare-bindings-assets.sh's version validation — the gate
# between an operator typo and building/bundling SQL under a wrong identity.
# The build path itself is not exercised: a stub `mise` on PATH proves that a
# valid version reaches the build step (stub exit code observed), while every
# invalid identity must be rejected before any build runs.

set -euo pipefail

script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/prepare-bindings-assets.sh"
failures=0

expect_reject() {
  local version="$1"
  if out=$("$script" --version "$version" 2>&1); then
    echo "FAIL: --version '$version' should have been rejected" >&2
    failures=$((failures + 1))
  elif [[ "$out" != *"exact release identity"* ]]; then
    echo "FAIL: --version '$version' rejected with unexpected message: $out" >&2
    failures=$((failures + 1))
  else
    echo "ok: rejects '$version'"
  fi
}

expect_accept() {
  local version="$1"
  # Stub mise: exit 42 so we can observe that validation passed and the build
  # step was reached, without running a real build.
  local stub_dir
  stub_dir="$(mktemp -d)"
  cat > "$stub_dir/mise" <<'EOF'
#!/usr/bin/env bash
exit 42
EOF
  chmod +x "$stub_dir/mise"
  set +e
  PATH="$stub_dir:$PATH" "$script" --version "$version" >/dev/null 2>&1
  local rc=$?
  set -e
  rm -rf "$stub_dir"
  if [[ "$rc" -ne 42 ]]; then
    echo "FAIL: --version '$version' should pass validation and reach the build (expected rc 42, got $rc)" >&2
    failures=$((failures + 1))
  else
    echo "ok: accepts '$version'"
  fi
}

expect_reject ""
expect_reject "3.0.0-alpha"          # channel without .N
expect_reject "3.0.0-alpha.1.2"      # extra segment
expect_reject "3.0.0-nightly.1"      # unknown channel
expect_reject "v3.0.0"               # tag-style prefix
expect_reject "3.0"                  # not full semver
expect_reject "3.0.0-alpha.1; rm -rf /" # metacharacters never reach a shell

expect_accept "3.0.0"
expect_accept "3.0.0-alpha.7"
expect_accept "10.20.30-rc.2"

if [[ "$failures" -gt 0 ]]; then
  echo "prepare-bindings-assets.test.sh: ${failures} failure(s)" >&2
  exit 1
fi
echo "prepare-bindings-assets.test.sh: all assertions passed"
