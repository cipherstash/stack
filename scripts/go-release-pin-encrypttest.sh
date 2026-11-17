#!/usr/bin/env bash
# Pins the encrypttest module to the SDK version a release tags.
#
# languages/golang/encrypt/encrypttest is a module of its own, so a program
# that never imports it never downloads the test builds of the engine it
# embeds. Those builds match the SDK's host code at one version only. In the
# tree it requires the SDK at the zero pseudo-version and replaces it with
# ../.., so every build of a checkout pairs the two at one commit. A
# consumer ignores the replace, so the release commit must name the version
# it tags: this rewrites the requirement to v<version>, and the two tags go on
# that one commit.
#
# release-golang.yml runs it in `build` and again in `publish`, which runs only
# git, gh and shell tools: so this is sed and grep, nothing else. Both jobs
# must arrive at the same tree, and `publish` refuses the release when they
# do not.
#
# Usage: go-release-pin-encrypttest.sh <version without the leading v> [<go.mod>]
set -euo pipefail

version=${1:?usage: go-release-pin-encrypttest.sh <version> [<go.mod>]}
gomod=${2:-languages/golang/encrypt/encrypttest/go.mod}
sdk=github.com/cipherstash/stack/languages/golang
placeholder=v0.0.0-00010101000000-000000000000

# Exactly one requirement of the SDK, at the placeholder. Anything else means
# the tree was edited in a way this script does not know, and guessing would
# tag a module that requires the wrong SDK.
count=$(grep -cE "^[[:space:]]*(require[[:space:]]+)?${sdk}[[:space:]]+${placeholder}[[:space:]]*$" "$gomod" || true)
if [ "$count" != "1" ]; then
  echo "error: $gomod must require $sdk at $placeholder exactly once, and does $count times" >&2
  exit 1
fi

tmp="$gomod.tmp"
sed -E "s#^([[:space:]]*(require[[:space:]]+)?${sdk}[[:space:]]+)${placeholder}[[:space:]]*\$#\\1v${version}#" "$gomod" > "$tmp"
mv "$tmp" "$gomod"

if ! grep -qE "^[[:space:]]*(require[[:space:]]+)?${sdk}[[:space:]]+v${version//./\\.}$" "$gomod"; then
  echo "error: $gomod does not require $sdk v$version after the rewrite" >&2
  exit 1
fi
echo "$gomod requires $sdk v$version"
