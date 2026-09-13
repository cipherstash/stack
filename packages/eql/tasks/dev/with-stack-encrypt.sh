#!/usr/bin/env bash
# Use the unpublished sibling suite without committing a machine-specific path.
# Usage: tasks/dev/with-stack-encrypt.sh /path/to/cipherstash-suite test -p eql-bindings --features stack-encrypt
set -euo pipefail
suite_root=$(cd "${1:?supply the cipherstash-suite checkout}" && pwd)
shift
patch_file=$(mktemp)
trap 'rm -f "$patch_file"' EXIT
python3 - "$suite_root" > "$patch_file" <<'PY'
import json, pathlib, sys
suite = pathlib.Path(sys.argv[1])
print('[patch.crates-io]')
for name in ('stack-encrypt', 'stack-kms'):
    path = suite / 'packages' / name
    if not (path / 'Cargo.toml').is_file():
        raise SystemExit(f'missing {path}/Cargo.toml')
    print(f'{name} = {{ path = {json.dumps(str(path))} }}')
PY
command=${1:?supply a Cargo command such as test or check}
shift
# External subcommands (notably clippy) need the override after their name.
cargo "$command" --config "$patch_file" "$@"
