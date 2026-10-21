"""Tests for collect_evidence.py against small synthetic git repositories.

Run: python3 -m unittest discover -s .agents/skills/change-risk/scripts/tests
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import collect_evidence as ce  # noqa: E402


class Repo:
    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = self.tmp.name
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "a@example.com")
        self.git("config", "user.name", "A")
        self.git("config", "commit.gpgsign", "false")
        self.n = 0

    def git(self, *args: str) -> str:
        env = {**os.environ, "GIT_COMMITTER_DATE": f"2026-01-{1 + self.__dict__.get('n', 0):02d}T00:00:00Z",
               "GIT_AUTHOR_DATE": f"2026-01-{1 + self.__dict__.get('n', 0):02d}T00:00:00Z"}
        return subprocess.run(["git", "-C", self.path, *args], check=True, capture_output=True, text=True, env=env).stdout

    def commit(self, files: dict[str, str], author: str = "a@example.com", msg: str = "c") -> str:
        for name, text in files.items():
            p = Path(self.path, name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
            self.git("add", name)
        self.n += 1
        self.git("-c", f"user.email={author}", "commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD").strip()

    def close(self) -> None:
        self.tmp.cleanup()


def run(repo: Repo, base: str, head: str, *extra: str) -> dict:
    args = ce.argparse.Namespace(
        repo=repo.path, base=base, head=head, repository="t/t", rules=None, ci=None,
        max_history=5000, recent_days=90, min_support=2, min_confidence=0.5,
        max_files_per_commit=5, format="json", out=None,
    )
    for kv in extra:
        k, v = kv.split("=")
        setattr(args, k, type(getattr(args, k))(v))
    return ce.collect(args)


class CollectEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.r = Repo()
        self.r.commit({"pkg/package.json": json.dumps({"name": "pkg", "dependencies": {"left": "1.0.0"}}),
                       "pkg/src/core.ts": "a\n", "pkg/src/core.test.ts": "t\n", "README.md": "x\n"})
        # core.ts and wire.ts change together three times
        for i in range(3):
            self.r.commit({"pkg/src/core.ts": f"a{i}\n", "pkg/src/wire.ts": f"w{i}\n"})
        self.base = self.r.commit({"README.md": "y\n"})

    def tearDown(self) -> None:
        self.r.close()

    def test_history_can_be_disabled(self):
        from unittest.mock import patch
        head = self.r.commit({"pkg/src/core.ts": "changed\n"})
        with patch.object(ce, "history", side_effect=AssertionError("history must not run")):
            ev = run(self.r, self.base, head, "max_history=0")
        self.assertEqual(ev["history_scope"]["status"], "unavailable")
        self.assertEqual(ev["history_scope"]["commits_read"], 0)
        self.assertEqual(ev["ownership"]["author_familiarity"], {})
        self.assertTrue(ev["files"])

    def test_history_is_cut_at_base(self) -> None:
        self.r.git("checkout", "-q", "-b", "feature")
        head = self.r.commit({"pkg/src/core.ts": "changed\n"})
        # a later commit on main touches core.ts many times; it must not count
        self.r.git("checkout", "-q", "main")
        for i in range(5):
            self.r.commit({"pkg/src/core.ts": f"future{i}\n", "pkg/src/later.ts": f"{i}\n"})
        ev = run(self.r, self.base, head)
        hot = {h["path"]: h["commits"] for h in ev["churn"]["hotspots"]}
        self.assertEqual(hot["pkg/src/core.ts"], 4)
        partners = {c["usually_changes_with"] for c in ev["co_change"]["omitted_co_changes"]}
        self.assertNotIn("pkg/src/later.ts", partners)
        self.assertEqual(ev["history_scope"]["cutoff_commit"], self.base)

    def test_pr_commits_are_not_history(self) -> None:
        head = self.r.commit({"pkg/src/core.ts": "1\n", "pkg/src/other.ts": "1\n"})
        head = self.r.commit({"pkg/src/core.ts": "2\n", "pkg/src/other.ts": "2\n"})
        ev = run(self.r, self.base, head)
        partners = {c["usually_changes_with"] for c in ev["co_change"]["omitted_co_changes"]}
        self.assertNotIn("pkg/src/other.ts", partners)

    def test_omitted_co_change_reported(self) -> None:
        head = self.r.commit({"pkg/src/core.ts": "only core\n"})
        ev = run(self.r, self.base, head)
        miss = ev["co_change"]["omitted_co_changes"]
        self.assertTrue(any(m["changed_file"] == "pkg/src/core.ts" and m["usually_changes_with"] == "pkg/src/wire.ts"
                            and m["co_commits"] == 3 for m in miss), miss)

    def test_co_change_not_reported_when_included(self) -> None:
        head = self.r.commit({"pkg/src/core.ts": "x\n", "pkg/src/wire.ts": "y\n"})
        ev = run(self.r, self.base, head)
        self.assertFalse([m for m in ev["co_change"]["omitted_co_changes"] if m["usually_changes_with"] == "pkg/src/wire.ts"])

    def test_bulk_commits_ignored_for_coupling(self) -> None:
        self.r.commit({f"bulk/f{i}.ts": "x\n" for i in range(8)} | {"pkg/src/core.ts": "bulk\n"})
        self.r.commit({f"bulk/f{i}.ts": "y\n" for i in range(8)} | {"pkg/src/core.ts": "bulk2\n"})
        base = self.r.git("rev-parse", "HEAD").strip()
        head = self.r.commit({"pkg/src/core.ts": "z\n"})
        ev = run(self.r, base, head)
        self.assertEqual(ev["co_change"]["bulk_commits_ignored"], 2)
        self.assertFalse([m for m in ev["co_change"]["omitted_co_changes"] if m["usually_changes_with"].startswith("bulk/")])

    def test_dependency_and_field_changes(self) -> None:
        head = self.r.commit({"pkg/package.json": json.dumps(
            {"name": "pkg", "dependencies": {"left": "2.0.0", "new": "^1"}, "exports": {".": "./x.js"}})})
        ev = run(self.r, self.base, head)
        deps = ev["dependencies"][0]
        self.assertIn({"section": "dependencies", "name": "left", "from": "1.0.0", "to": "2.0.0"}, deps["dependencies"])
        self.assertIn({"section": "dependencies", "name": "new", "from": None, "to": "^1"}, deps["dependencies"])
        self.assertIn("exports", deps["fields_changed"])

    def test_components_and_classes(self) -> None:
        head = self.r.commit({"pkg/src/auth/token.ts": "t\n", ".github/workflows/ci.yml": "on: push\n",
                              "db/migrations/001.sql": "create table t();\n"})
        ev = run(self.r, self.base, head)
        files = {f["path"]: f for f in ev["files"]}
        self.assertEqual(files["pkg/src/auth/token.ts"]["component"], "pkg")
        self.assertIn("security_sensitive", files["pkg/src/auth/token.ts"]["classes"])
        self.assertIn("ci_workflow", files[".github/workflows/ci.yml"]["classes"])
        self.assertIn("database_schema", files["db/migrations/001.sql"]["classes"])
        self.assertEqual(files["db/migrations/001.sql"]["component"], ".")

    def test_related_tests(self) -> None:
        head = self.r.commit({"pkg/src/core.ts": "q\n"})
        ev = run(self.r, self.base, head)
        m = {x["source"]: x for x in ev["tests"]["mapping"]}
        self.assertEqual(m["pkg/src/core.ts"]["related_tests_at_head"], ["pkg/src/core.test.ts"])
        self.assertFalse(m["pkg/src/core.ts"]["related_test_changed"])

    def test_ci_absent_is_explicit(self) -> None:
        head = self.r.commit({"pkg/src/core.ts": "q\n"})
        self.assertFalse(run(self.r, self.base, head)["ci"]["available"])

    def test_codeowners_last_match_wins(self) -> None:
        rules = [("*", ["@all"]), ("/pkg/", ["@pkg"]), ("*.sql", ["@db"]), ("docs/", ["@docs"])]
        self.assertEqual(ce.owners_for("pkg/src/a.ts", rules), ["@pkg"])
        self.assertEqual(ce.owners_for("pkg/m/1.sql", rules), ["@db"])
        self.assertEqual(ce.owners_for("x/docs/a.md", rules), ["@docs"])
        self.assertEqual(ce.owners_for("other.ts", rules), ["@all"])
        self.assertEqual(ce.owners_for("pkgx/a.ts", rules), ["@all"])

    def test_deterministic(self) -> None:
        head = self.r.commit({"pkg/src/core.ts": "q\n"})
        self.assertEqual(run(self.r, self.base, head), run(self.r, self.base, head))

    def test_cli_rejects_unknown_revision(self) -> None:
        rc = ce.main(["--repo", self.r.path, "--base", "deadbeef", "--head", "HEAD"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
