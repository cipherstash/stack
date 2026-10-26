#!/usr/bin/env python3
"""Check that the storage profile's golden corpora only grow.

`packages/aead-frame/testdata/storage-v1.json` pins the bytes of version 1
of the storage profile (packages/aead-frame/STORAGE.md), and each later
version gets a `storage-vN.json` of its own. Customers keep
blobs in that format, so a row the corpus already had is a promise: its
bytes read as its value, or are refused as its class, in every later
release. The Rust test holds the code to the corpus; this check holds the
corpus to itself. Every row at the merge base must still be there, under
the same name and unchanged, as must the header and version, in every
corpus the merge base had. Rows, sections and new corpora may be added.

Run `mise run storage:corpus:check -- --base origin/main` to check this
branch against main.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TESTDATA = "packages/aead-frame/testdata"
CORPUS = f"{TESTDATA}/storage-v1.json"
# A version's corpus: storage-v1.json, storage-v2.json, and so on.
CORPUS_NAME = re.compile(r"storage-v[0-9]+\.json")
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


def corpus_at(rev: str, root: Path = REPO_ROOT, path: str = CORPUS) -> dict | None:
    """The corpus at `path` as it was at `rev`, or None if it did not exist.

    Only a path git lists as absent counts as new. Any other failure (an
    unknown revision, a blob a partial clone cannot fetch) raises, so the
    check fails rather than passing with nothing to compare.
    """
    if not git("ls-tree", "--name-only", rev, "--", path, root=root).strip():
        return None
    return json.loads(git("show", f"{rev}:{path}", root=root))


def corpora_at(rev: str, root: Path = REPO_ROOT) -> list[str]:
    """Every version's corpus that existed at `rev`, by path."""
    listed = git("ls-tree", "--name-only", rev, "--", f"{TESTDATA}/", root=root)
    return sorted(
        path for path in listed.splitlines() if CORPUS_NAME.fullmatch(Path(path).name)
    )


def check(merge_base: str, root: Path = REPO_ROOT) -> list[tuple[str, str]]:
    """Each way the working tree drops or changes a corpus the merge base
    had, as the corpus's path and the problem."""
    found = []
    for path in corpora_at(merge_base, root):
        base = corpus_at(merge_base, root, path)
        if not (root / path).exists():
            found.append((path, "the corpus was removed"))
            continue
        with open(root / path, encoding="utf-8") as f:
            head = json.load(f)
        found.extend((path, problem) for problem in problems(base, head))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="origin/main", help="the branch this one merges into")
    args = parser.parse_args(argv)

    merge_base = git("merge-base", args.base, "HEAD").strip()
    if not corpora_at(merge_base):
        print("no storage corpus at the merge base; nothing to hold this branch to")
        return 0
    found = check(merge_base)
    for path, problem in found:
        print(f"::error file={path}::{problem}; the stored format is frozen, add a row instead")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
