"""Tests for storage_corpus_append_only.py. Run with `mise run storage:corpus:check:test`."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from storage_corpus_append_only import CORPUS, TESTDATA, check, corpora_at, corpus_at, problems

BASE = {
    "description": "corpus",
    "version": 1,
    "header": "56435301",
    "vectors": [
        {"name": "null", "value": None, "blob": "5643530100"},
        {"name": "true", "value": {"bool": True}, "blob": "5643530103"},
    ],
    "refused": [{"name": "empty", "refusal": "not_a_blob", "blob": ""}],
}


class ProblemsTest(unittest.TestCase):
    def test_the_same_corpus_passes(self):
        self.assertEqual(problems(BASE, copy.deepcopy(BASE)), [])

    def test_a_new_row_and_a_new_section_pass(self):
        head = copy.deepcopy(BASE)
        head["vectors"].append({"name": "false", "value": {"bool": False}, "blob": "5643530102"})
        head["normalized"] = [{"name": "x"}]
        self.assertEqual(problems(BASE, head), [])

    def test_rows_may_move(self):
        head = copy.deepcopy(BASE)
        head["vectors"].reverse()
        self.assertEqual(problems(BASE, head), [])

    def test_the_description_may_change(self):
        head = copy.deepcopy(BASE)
        head["description"] = "clearer"
        self.assertEqual(problems(BASE, head), [])

    def test_a_changed_row_fails(self):
        head = copy.deepcopy(BASE)
        head["vectors"][1]["blob"] = "5643530102"
        self.assertEqual(problems(BASE, head), ["vectors: row 'true' was changed"])

    def test_a_changed_refusal_class_fails(self):
        head = copy.deepcopy(BASE)
        head["refused"][0]["refusal"] = "malformed"
        self.assertEqual(problems(BASE, head), ["refused: row 'empty' was changed"])

    def test_a_removed_row_fails(self):
        head = copy.deepcopy(BASE)
        del head["vectors"][0]
        self.assertEqual(problems(BASE, head), ["vectors: row 'null' was removed"])

    def test_a_renamed_row_is_a_removed_row(self):
        head = copy.deepcopy(BASE)
        head["vectors"][0]["name"] = "unit"
        self.assertEqual(problems(BASE, head), ["vectors: row 'null' was removed"])

    def test_a_removed_section_fails_for_every_row(self):
        head = copy.deepcopy(BASE)
        del head["refused"]
        self.assertEqual(problems(BASE, head), ["refused: row 'empty' was removed"])

    def test_the_header_and_version_are_frozen(self):
        head = copy.deepcopy(BASE)
        head["header"] = "56435302"
        head["version"] = 2
        self.assertEqual(
            problems(BASE, head),
            ["version changed from 1 to 2", "header changed from '56435301' to '56435302'"],
        )


class CorpusAtTest(unittest.TestCase):
    """`corpus_at` against a scratch repository."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "test")
        self.git("config", "commit.gpgsign", "false")
        (self.root / "README").write_text("x")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "without the corpus")
        self.without = self.git("rev-parse", "HEAD").strip()
        corpus = self.root / CORPUS
        corpus.parent.mkdir(parents=True)
        corpus.write_text(json.dumps(BASE))
        self.git("add", ".")
        self.git("commit", "-q", "-m", "with the corpus")
        self.with_corpus = self.git("rev-parse", "HEAD").strip()

    def tearDown(self):
        self.dir.cleanup()

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.root, check=True, stdout=subprocess.PIPE, text=True
        ).stdout

    def test_a_revision_without_the_corpus_has_none(self):
        self.assertIsNone(corpus_at(self.without, root=self.root))

    def test_a_revision_with_the_corpus_has_it(self):
        self.assertEqual(corpus_at(self.with_corpus, root=self.root), BASE)

    def test_a_revision_git_cannot_read_fails_rather_than_passing(self):
        with self.assertRaises(subprocess.CalledProcessError):
            corpus_at("0" * 40, root=self.root)

    def test_every_version_s_corpus_is_found_and_nothing_else(self):
        (self.root / TESTDATA / "storage-v2.json").write_text(json.dumps(BASE))
        (self.root / TESTDATA / "value-conformance.json").write_text("{}")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "a second version, and another file")
        head = self.git("rev-parse", "HEAD").strip()
        self.assertEqual(
            corpora_at(head, root=self.root),
            [CORPUS, f"{TESTDATA}/storage-v2.json"],
        )
        self.assertEqual(corpora_at(self.without, root=self.root), [])

    def test_a_later_version_s_corpus_is_held_too(self):
        v2 = self.root / TESTDATA / "storage-v2.json"
        v2.write_text(json.dumps(BASE))
        self.git("add", ".")
        self.git("commit", "-q", "-m", "a second version")
        base = self.git("rev-parse", "HEAD").strip()
        self.assertEqual(check(base, root=self.root), [])
        changed = json.loads(json.dumps(BASE))
        changed["vectors"][0]["blob"] = "00"
        v2.write_text(json.dumps(changed))
        self.assertEqual(
            [path for path, _ in check(base, root=self.root)],
            [f"{TESTDATA}/storage-v2.json"],
        )
        v2.unlink()
        self.assertEqual(
            check(base, root=self.root),
            [(f"{TESTDATA}/storage-v2.json", "the corpus was removed")],
        )


if __name__ == "__main__":
    unittest.main()
