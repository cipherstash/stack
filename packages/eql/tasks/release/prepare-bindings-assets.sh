#!/usr/bin/env bash
#MISE description="Build exact-version SQL and copy it into Rust and TypeScript binding package asset directories"
#USAGE flag "--version <version>" help="Exact release identity, e.g. 3.0.0-alpha.7"

set -euo pipefail

version="${usage_version:-}"
# Support both invocation styles: as a mise file task (dashed name) usage
# parsing sets `usage_version`; via the toml wrapper (underscore name) mise
# appends `--version <value>` to the command, so parse positional args too.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --version=*) version="${1#*=}"; shift ;;
    *) shift ;;
  esac
done
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]]; then
  echo "error: --version must be an exact release identity (X.Y.Z or X.Y.Z-(alpha|beta|rc).N)" >&2
  exit 1
fi

mise run build --version "$version"

install_sql="release/cipherstash-encrypt.sql"
uninstall_sql="release/cipherstash-encrypt-uninstall.sql"
test -f "$install_sql"
test -f "$uninstall_sql"

install_hash="$(shasum -a 256 "$install_sql" | awk '{print $1}')"
uninstall_hash="$(shasum -a 256 "$uninstall_sql" | awk '{print $1}')"

for dir in crates/eql-bindings/sql packages/eql/sql; do
  mkdir -p "$dir"
  cp "$install_sql" "$dir/cipherstash-encrypt.sql"
  cp "$uninstall_sql" "$dir/cipherstash-encrypt-uninstall.sql"
  cat > "$dir/release-manifest.json" <<JSON
{
  "eqlVersion": "$version",
  "schemaVersion": 3,
  "installSqlSha256": "$install_hash",
  "uninstallSqlSha256": "$uninstall_hash"
}
JSON
done

mkdir -p packages/eql/src/generated
cat > packages/eql/src/generated/release-manifest.ts <<TS
export const releaseManifest = {
  eqlVersion: '$version',
  schemaVersion: 3,
  installSqlSha256: '$install_hash',
  uninstallSqlSha256: '$uninstall_hash',
} as const
TS

echo "prepared binding SQL assets for $version"
