#!/usr/bin/env python3
"""Assert a .wasm module's import surface is exactly what we promise.

The Go/wazero binding's security contract is that the guest can only reach
the outside world through the host functions we hand it: no ambient network
or filesystem access sneaking in through a dependency. That is a property of
the *linked module*, so it can only be checked on the built artifact — a
`cargo build` that succeeds proves nothing about it.

Fail-closed by construction: an import is rejected unless its module was
explicitly allowed (--allow-module) or the exact `module:name` pair was
required (--require), and every required pair must be present. A new
dependency that pulls in an extra host import therefore fails the build
rather than silently widening the surface.

`--deny-prefix` narrows an allowed module from within: WASI is one module
name covering both harmless calls (`random_get`, `fd_write` on stdio) and
the capability-granting ones (`path_open`, `sock_*`), so the ambient-access
half is denied by name even though the module is allowed.

Usage:
  check-wasm-imports.py MODULE.wasm --allow-module wasi_snapshot_preview1 \\
      --deny-prefix wasi_snapshot_preview1:path_ \\
      --require cipherstash_transport:transport_send
"""

import argparse
import sys


class MalformedModule(Exception):
    pass


class Reader:
    """Minimal cursor over a wasm binary (little-endian, LEB128 varuints)."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def bytes(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise MalformedModule("truncated module")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.bytes(1)[0]

    def varuint(self) -> int:
        result = 0
        shift = 0
        while True:
            if shift > 63:
                raise MalformedModule("LEB128 value too large")
            b = self.byte()
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                return result
            shift += 7

    def name(self) -> str:
        raw = self.bytes(self.varuint())
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MalformedModule("import name is not valid UTF-8") from exc


def skip_limits(reader: Reader) -> None:
    flags = reader.byte()
    reader.varuint()  # minimum
    if flags & 0x01:
        reader.varuint()  # maximum


def skip_import_descriptor(reader: Reader) -> None:
    kind = reader.byte()
    if kind == 0x00:  # func: type index
        reader.varuint()
    elif kind == 0x01:  # table: reftype, limits
        reader.byte()
        skip_limits(reader)
    elif kind == 0x02:  # memory: limits
        skip_limits(reader)
    elif kind == 0x03:  # global: valtype, mutability
        reader.byte()
        reader.byte()
    else:
        raise MalformedModule(f"unknown import kind 0x{kind:02x}")


def read_imports(data: bytes) -> list:
    """Every (module, name) pair in the module's import section."""
    reader = Reader(data)
    if reader.bytes(4) != b"\x00asm":
        raise MalformedModule("not a wasm module (bad magic)")
    version = int.from_bytes(reader.bytes(4), "little")
    if version != 1:
        raise MalformedModule(f"unsupported wasm version {version}")

    imports = []
    seen_import_section = False
    while reader.pos < len(data):
        section_id = reader.byte()
        size = reader.varuint()
        end = reader.pos + size
        if end > len(data):
            raise MalformedModule("section runs past end of module")
        if section_id == 2:  # import section
            if seen_import_section:
                raise MalformedModule("duplicate import section")
            seen_import_section = True
            for _ in range(reader.varuint()):
                module = reader.name()
                field = reader.name()
                skip_import_descriptor(reader)
                imports.append((module, field))
            if reader.pos != end:
                raise MalformedModule("import section size mismatch")
        reader.pos = end
    return imports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", help="path to the .wasm file")
    parser.add_argument(
        "--allow-module",
        action="append",
        default=[],
        metavar="MODULE",
        help="import module whose functions are all permitted (repeatable)",
    )
    parser.add_argument(
        "--deny-prefix",
        action="append",
        default=[],
        metavar="MODULE:PREFIX",
        help="reject imports from an allowed module whose name starts with "
        "PREFIX (repeatable)",
    )
    parser.add_argument(
        "--require",
        action="append",
        default=[],
        metavar="MODULE:NAME",
        help="import that must be present, and is permitted (repeatable)",
    )
    args = parser.parse_args()

    required = set()
    for spec in args.require:
        module, sep, name = spec.partition(":")
        if not sep or not module or not name:
            parser.error(f"--require expects MODULE:NAME, got {spec!r}")
        required.add((module, name))
    allowed_modules = set(args.allow_module)

    denied_prefixes = []
    for spec in args.deny_prefix:
        module, sep, prefix = spec.partition(":")
        if not sep or not module or not prefix:
            parser.error(f"--deny-prefix expects MODULE:PREFIX, got {spec!r}")
        denied_prefixes.append((module, prefix))

    try:
        with open(args.module, "rb") as f:
            data = f.read()
        imports = read_imports(data)
    except OSError as exc:
        print(f"error: cannot read {args.module}: {exc}", file=sys.stderr)
        return 1
    except MalformedModule as exc:
        print(f"error: {args.module}: {exc}", file=sys.stderr)
        return 1

    def denied(imp):
        return any(
            imp[0] == module and imp[1].startswith(prefix)
            for module, prefix in denied_prefixes
        )

    unexpected = [
        imp
        for imp in imports
        if denied(imp) or (imp[0] not in allowed_modules and imp not in required)
    ]
    missing = sorted(required - set(imports))

    for module, name in sorted(unexpected):
        print(f"error: unexpected host import {module}::{name}", file=sys.stderr)
    for module, name in missing:
        print(f"error: required host import {module}::{name} is absent", file=sys.stderr)
    if unexpected or missing:
        print(
            "error: import surface of "
            f"{args.module} is not the one the host contract promises",
            file=sys.stderr,
        )
        return 1

    print(f"import surface OK: {len(imports)} imports, all expected")
    for module, name in sorted(set(imports)):
        print(f"  {module}::{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
