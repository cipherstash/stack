#!/usr/bin/env python3
"""Check that the storage profile's golden corpus only grows.

`packages/aead-frame/testdata/storage-v1.json` pins the bytes of version 1
of the storage profile (packages/aead-frame/STORAGE.md). Customers keep
blobs in that format, so a row the corpus already had is a promise: its
bytes read as its value, or are refused as its class, in every later
release. The Rust test holds the code to the corpus; this check holds the
corpus to itself. Every row at the merge base must still be there, under
the same name and unchanged, as must the header and version. Rows and
sections may be added.

Run `mise run storage:corpus:check -- --base origin/main` to check this
branch against main.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS = "packages/aead-frame/testdata/storage-v1.json"
# The fields that identify the format, not a row.
FROZEN_FIELDS = ("version", "header")


def problems(base: dict, head: dict) -> list[str]:
    """Each way `head` drops or changes something `base` had."""
    found = []
    for name in FROZEN_FIELDS:
        if base.get(name) != head.get(name):
            found.append(f"{name} changed from {base.get(name)!r} to {head.get(name)!r}")
    for section, rows in base.items():
        if not isinstance(rows, list):
            continue
        kept = {row["name"]: row for row in head.get(section) or []}
        for row in rows:
            name = row["name"]
            if name not in kept:
                found.append(f"{section}: row {name!r} was removed")
            elif kept[name] != row:
                found.append(f"{section}: row {name!r} was changed")
    return found


def git(*args: str, root: Path = REPO_ROOT) -> str:
    out = subprocess.run(
        ["git", *args], cwd=root, check=True, stdout=subprocess.PIPE, text=True
    )
    return out.stdout


def corpus_at(rev: str, root: Path = REPO_ROOT) -> dict | None:
    """The corpus as it was at `rev`, or None if the path did not exist there.

    Only a path git lists as absent counts as new. Any other failure (an
    unknown revision, a blob a partial clone cannot fetch) raises, so the
    check fails rather than passing with nothing to compare.
    """
    if not git("ls-tree", "--name-only", rev, "--", CORPUS, root=root).strip():
        return None
    return json.loads(git("show", f"{rev}:{CORPUS}", root=root))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="origin/main", help="the branch this one merges into")
    args = parser.parse_args(argv)

    merge_base = git("merge-base", args.base, "HEAD").strip()
    base = corpus_at(merge_base)
    if base is None:
        print(f"{CORPUS} is new on this branch; nothing to hold it to")
        return 0
    with open(REPO_ROOT / CORPUS, encoding="utf-8") as f:
        head = json.load(f)
    found = problems(base, head)
    for problem in found:
        print(f"::error file={CORPUS}::{problem}; the stored format is frozen, add a row instead")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
