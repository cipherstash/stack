#!/usr/bin/env bash
#MISE description="Build SQL into single release file"
#MISE alias="b"
#MISE sources=["src/v3/**/*.sql", "src/v3/version.template", "tasks/pin_search_path_v3.sql", "tasks/uninstall-v3.sql", "crates/eql-domains/src/**/*.rs", "crates/eql-codegen/src/**/*.rs", "Cargo.toml", "Cargo.lock", "crates/eql-codegen/Cargo.toml", "crates/eql-domains/Cargo.toml", "tasks/build/ordering.sh", "tasks/test/verify_symbol_order_v3.sh", "tasks/test/verify_installer_complete.sh", "tasks/test/symbol_order_allowlist.txt"]
#MISE outputs=["release/cipherstash-encrypt.sql","release/cipherstash-encrypt-uninstall.sql","src/deps-ordered-v3.txt"]
#USAGE flag "--version <version>" help="Specify release version of EQL" default="DEV"

#!/bin/bash

set -euo pipefail

# ordering.sh shapes the installer (strip_require_lines), and the two verify
# scripts below gate it. All four are in #MISE sources: a cache hit skips this
# script entirely, gates included, so an edit to any of them must invalidate the
# build rather than re-serve an installer built by the old logic.
#
# The Cargo manifests and Cargo.lock are sources for the same reason: the two
# `cargo run` steps below render this artefact, and eql-codegen's own deps decide
# what they render — minijinja templates the SQL, prettyplease (=0.2.37) formats
# the bindings. A dep bump changes the output with no .rs file touched.
source tasks/build/ordering.sh

# A failed `eql-codegen order` leaves its temp behind; don't strand it.
trap 'rm -f src/deps-ordered-v3.txt.tmp' EXIT

# Regenerate encrypted-domain SQL from the Rust catalog before building.
# The generated files (src/v3/scalars/<T>/<T>_*.sql) are COMMITTED in place and
# drift-gated by `mise run codegen:parity`; only src/v3/version.sql and the
# src/deps-ordered-v3.txt build intermediate are gitignored. The catalog at
# crates/eql-domains/src (eql-domains::CATALOG) is the source of truth, rendered
# by the eql-codegen binary.
#
# eql-codegen owns orphan removal: it writes every current file first (each via
# an atomic temp+rename), then prunes stale generated SQL across ALL
# src/v3/scalars/* type dirs — marker-aware, so a type dropped from the catalog
# can't leave orphans the `src/**/*.sql` build glob would pick up, and a
# hand-written *_extensions.sql (no AUTO-GENERATED marker) is never deleted.
# Because deletion happens only after every write succeeds, an aborted run never
# leaves the tree stripped (unlike the old filename-pattern `find -delete`, which
# deleted before regenerating and was blind to the AUTO-GENERATED marker).
#
# The plaintext fixture lists are not generated — the SQLx tests read them
# straight from the catalog (eql_domains::INT4_VALUES / …).
cargo run -q -p eql-codegen

mkdir -p release

rm -f release/cipherstash-encrypt.sql
rm -f release/cipherstash-encrypt-uninstall.sql
rm -f src/deps-ordered-v3.txt src/deps-ordered-v3.txt.tmp
rm -f src/v3/version.sql


# Bake the release version into eql_v3.version() (and the eql_v3 schema comment).
# The version is supplied via `mise run build --version <semver>` (the
# `usage_version` env var mise derives from the #USAGE flag); local builds with
# no flag fall back to DEV. The generated src/v3/version.sql is gitignored.
#
# This MUST precede `eql-codegen order` below: the ordering walks the surface on
# disk, so version.sql has to exist to be ordered into the installer.
RELEASE_VERSION=${usage_version:-DEV}
sed "s/\$RELEASE_VERSION/$RELEASE_VERSION/g" src/v3/version.template > src/v3/version.sql


# Resolve the install order of the whole eql_v3 surface — schema, SEM types,
# hand-written jsonb, generated scalars, version.sql — in ONE walk of src/v3,
# topologically sorted from the `-- REQUIRE:` edges every file declares.
#
# `eql-codegen order` is the sole enumeration of the surface, and it fails the
# build on a missing REQUIRE target, on an edge leaving src/v3 (self-containment,
# also gated by test:self_contained_v3), and on a dependency cycle. It replaces a
# two-block scheme — shell-globbed hand-written files, plus a codegen manifest of
# the generated ones — whose two enumerations could disagree about a file and
# silently drop it from the installer. Ordering what you walk makes that
# unrepresentable; `install_order_contains_every_v3_sql_file` in the codegen
# crate's parity tests pins the invariant.
#
# Written via a temp file so an aborted order leaves no truncated list behind for
# the downstream tasks (test:self_contained_v3, test:symbol_order_v3) to read.
cargo run -q -p eql-codegen -- order > src/deps-ordered-v3.txt.tmp
mv src/deps-ordered-v3.txt.tmp src/deps-ordered-v3.txt

bash tasks/test/verify_symbol_order_v3.sh src/deps-ordered-v3.txt

: > release/cipherstash-encrypt.sql
while IFS= read -r f; do
  strip_require_lines "$f" >> release/cipherstash-encrypt.sql
done < src/deps-ordered-v3.txt
cat tasks/pin_search_path_v3.sql >> release/cipherstash-encrypt.sql

# `eql-codegen order` guarantees the ORDER contains every file on disk. This gate
# closes the layer below — that the concat loop above actually emitted each ordered
# file's body. 93 of the ~244 v3 files are leaves (required by nothing, defining
# nothing another file references), so dropping one yields an installer that applies
# cleanly and passes the symbol checker while silently shipping less than it should.
bash tasks/test/verify_installer_complete.sh src/deps-ordered-v3.txt release/cipherstash-encrypt.sql

cat tasks/uninstall-v3.sql >> release/cipherstash-encrypt-uninstall.sql


echo
echo '###############################################'
echo "# ✅Build succeeded"
echo '###############################################'
echo
echo 'Installer:'
echo '    release/cipherstash-encrypt.sql'
echo
echo 'Uninstaller:'
echo '    release/cipherstash-encrypt-uninstall.sql'
