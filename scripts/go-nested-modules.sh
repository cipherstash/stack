#!/usr/bin/env bash
# Lists the Go modules nested under a module directory, one relative path per
# line, sorted: encrypt/encrypttest and encrypt/example under languages/golang.
#
# `./...` stops at a directory with its own go.mod, so every tool that walks
# the module (go vet and go test in go-binding-test.sh, golangci-lint in the
# `go:lint` task, go generate in tests-golang.yml) also runs in each nested
# module's directory. They all take the list from here, so they agree on which
# modules exist, and a new one is covered the day it lands.
#
# The stashgen fixtures under testdata are modules of their own, but they are
# test inputs, not modules of this repository's, and are left out.
#
# Usage: go-nested-modules.sh [<module dir>]   (default: the current directory)
set -euo pipefail

cd "${1:-.}"
find . -name go.mod -not -path ./go.mod -not -path '*/testdata/*' |
  sed -e 's#^\./##' -e 's#/go\.mod$##' |
  sort
