#!/usr/bin/env bash
#MISE description="Generate JSON manifest from XML documentation"
#USAGE arg "version" help="Version to include in the manifest" default="DEV"

VERSION=${ARGC_VERSION:-DEV}

echo "Converting XML to JSON manifest..."

# Ensure XML exists
if [ ! -d "docs/api/xml" ]; then
  echo "warning: XML documentation not found"
  echo "Generating XML documentation..."
  mise run --output prefix docs:generate
fi

# Emit the authoritative domain/variant matrix straight from the Rust catalog
# (eql_domains::CATALOG) — the source of truth the generated SQL is rendered from.
mkdir -p docs/api/json
echo "Dumping domain catalog (eql-codegen dump-catalog)..."
cargo run -q -p eql-codegen dump-catalog > docs/api/json/eql-catalog.json

# Run converter (functions from XML, domains from the catalog dump)
mise run --output prefix docs:generate:xml-to-json docs/api/xml docs/api/json "$VERSION" docs/api/json/eql-catalog.json

echo ""
echo "✓ JSON manifest: docs/api/json/eql-manifest.json"
