#!/usr/bin/env bash
#MISE description="Package documentation for release"

set -e

VERSION=${1:-"dev"}
OUTPUT_DIR="release"
DOCS_DIR="docs/api"

echo "Packaging documentation for version: ${VERSION}"

# Validate documentation exists
if [ ! -f "${DOCS_DIR}/html/index.html" ]; then
  echo "Error: ${DOCS_DIR}/html/index.html not found"
  echo "Run 'mise run docs:generate' first to generate documentation"
  exit 1
fi

if [ ! -f "${DOCS_DIR}/markdown/API.md" ]; then
  echo "Error: ${DOCS_DIR}/markdown/API.md not found"
  echo "Run 'mise run docs:generate:markdown' first to generate markdown documentation"
  exit 1
fi

if [ ! -d "${DOCS_DIR}/xml" ] || [ -z "$(ls -A ${DOCS_DIR}/xml/*.xml 2>/dev/null)" ]; then
  echo "Error: ${DOCS_DIR}/xml/*.xml files not found"
  echo "Run 'mise run docs:generate' first to generate XML documentation"
  exit 1
fi

if [ ! -f "${DOCS_DIR}/json/eql-manifest.json" ]; then
  echo "Error: ${DOCS_DIR}/json/eql-manifest.json not found"
  echo "Run 'mise run docs:generate:json' first to generate the JSON manifest"
  exit 1
fi



# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Create archives
echo "Creating archives..."
cd "${DOCS_DIR}"

# Create ZIP archive with all documentation formats
zip -r -q "../../${OUTPUT_DIR}/eql-docs-${VERSION}.zip" markdown/API.md json/eql-manifest.json xml/*.xml html/
echo "Created ${OUTPUT_DIR}/eql-docs-${VERSION}.zip"

# Create tarball with all documentation formats
tar czf "../../${OUTPUT_DIR}/eql-docs-${VERSION}.tar.gz" markdown/API.md json/ xml/ html/
echo "Created ${OUTPUT_DIR}/eql-docs-${VERSION}.tar.gz"

cd ../..

# Verify archives created
if [ -f "${OUTPUT_DIR}/eql-docs-${VERSION}.zip" ] && [ -f "${OUTPUT_DIR}/eql-docs-${VERSION}.tar.gz" ]; then
  echo ""
  echo "Documentation packaged successfully:"
  ls -lh "${OUTPUT_DIR}/eql-docs-${VERSION}".*
  exit 0
else
  echo "Error: Failed to create archives"
  exit 1
fi
