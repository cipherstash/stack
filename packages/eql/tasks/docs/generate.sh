#!/usr/bin/env bash
#MISE description="Generate API documentation (with Doxygen)"
# Build first so generated encrypted-domain SQL exists under src/.
#MISE depends=["build"]

set -e

# Use `command -v` (POSIX) rather than `which -s`: the `-s` (silent) flag is a
# BSD/macOS `which` extension and is unsupported by Ubuntu's `which`, so on the
# Linux CI runners the old check failed even when doxygen was installed.
if ! command -v doxygen >/dev/null 2>&1; then
  echo "error: doxygen not installed"
  exit 2
fi

echo "Generating API documentation..."
echo
doxygen Doxyfile
echo "✓ Documentation generated:"
echo "  - XML (primary): docs/api/xml/"
echo "  - HTML (preview): docs/api/html/index.html"
echo ""
