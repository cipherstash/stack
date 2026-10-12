"""Tests for validate_assessment.py."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import validate_assessment as va  # noqa: E402

SCHEMA = json.loads(va.DEFAULT_SCHEMA.read_text())
VALID = json.loads((HERE / "fixtures" / "valid.json").read_text())

try:
    import jsonschema  # type: ignore
except ImportError:  # the validator itself never needs it
    jsonschema = None


def errs(doc: dict) -> list[str]:
    return va.validate(doc, SCHEMA)[0]


class SchemaTest(unittest.TestCase):
    def test_fixture_is_valid(self) -> None:
        e, w = va.validate(VALID, SCHEMA)
        self.assertEqual(e, [])
        self.assertEqual(w, [])

    def test_schema_is_valid_draft_2020_12(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema not installed")
        jsonschema.Draft202012Validator.check_schema(SCHEMA)

    def test_missing_required(self) -> None:
        d = copy.deepcopy(VALID)
        del d["inputs"]["ci_results"]
        self.assertTrue(any("ci_results" in x for x in errs(d)))

    def test_bad_enum_and_sha(self) -> None:
        d = copy.deepcopy(VALID)
        d["impact"] = "severe"
        d["head_sha"] = "abc"
        e = errs(d)
        self.assertTrue(any("$.impact" in x for x in e))
        self.assertTrue(any("$.head_sha" in x for x in e))

    def test_more_than_five_scenarios(self) -> None:
        d = copy.deepcopy(VALID)
        fs = d["failure_scenarios"][0]
        d["failure_scenarios"] = [dict(fs, id=f"FS-{i}") for i in range(1, 7)]
        self.assertTrue(any("more than 5" in x for x in errs(d)))

    def test_unknown_property(self) -> None:
        d = copy.deepcopy(VALID)
        d["risk_score"] = 7
        self.assertTrue(any("risk_score" in x for x in errs(d)))

    def test_agrees_with_jsonschema(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema not installed")
        v = jsonschema.Draft202012Validator(SCHEMA)
        mutations = [
            lambda d: d.__setitem__("impact", "x"),
            lambda d: d["evidence"][0].__setitem__("line_start", 0),
            lambda d: d["failure_scenarios"][0].__setitem__("evidence", []),
            lambda d: d["evidence"][0].__setitem__("id", "EV-1"),
            lambda d: d["assessor"].pop("model"),
            lambda d: d.__setitem__("schema_version", "2"),
            lambda d: None,
        ]
        for m in mutations:
            d = copy.deepcopy(VALID)
            m(d)
            ours = va.schema_errors(d, SCHEMA, SCHEMA)
            theirs = list(v.iter_errors(d))
            self.assertEqual(bool(ours), bool(theirs), (ours, [t.message for t in theirs]))


class SemanticTest(unittest.TestCase):
    def test_unresolved_reference(self) -> None:
        d = copy.deepcopy(VALID)
        d["failure_scenarios"][0]["evidence"] = ["E-9"]
        self.assertTrue(any("E-9" in x for x in errs(d)))

    def test_duplicate_ids(self) -> None:
        d = copy.deepcopy(VALID)
        d["evidence"].append(dict(d["evidence"][0]))
        self.assertTrue(any("duplicate" in x for x in errs(d)))

    def test_observed_defect_needs_verified_evidence(self) -> None:
        d = copy.deepcopy(VALID)
        d["evidence"][0]["status"] = "inferred"
        self.assertTrue(any("observed_defect" in x for x in errs(d)))

    def test_inferred_only_scenario_warns(self) -> None:
        d = copy.deepcopy(VALID)
        d["failure_scenarios"][0]["basis"] = "plausible_failure"
        d["failure_scenarios"][0]["evidence"] = ["E-1"]
        d["evidence"][0]["status"] = "inferred"
        e, w = va.validate(d, SCHEMA)
        self.assertEqual(e, [])
        self.assertTrue(any("inferred" in x for x in w))

    def test_passed_test_claim_needs_ci_or_command(self) -> None:
        d = copy.deepcopy(VALID)
        d["failure_scenarios"][0]["existing_verification"][0]["status"] = "ran_passed"
        self.assertTrue(any("ran_passed" in x for x in errs(d)))

    def test_ci_result_while_ci_unavailable(self) -> None:
        d = copy.deepcopy(VALID)
        d["evidence"].append({"id": "E-3", "kind": "ci_result", "claim": "green", "status": "verified"})
        d["failure_scenarios"][0]["existing_verification"][0].update(status="ran_passed", evidence=["E-3"])
        e = errs(d)
        self.assertTrue(any("ci_results is unavailable" in x for x in e))

    def test_command_output_allows_ran_passed(self) -> None:
        d = copy.deepcopy(VALID)
        d["evidence"].append({"id": "E-3", "kind": "command_output", "command": "pnpm test", "claim": "passed", "status": "verified"})
        d["failure_scenarios"][0]["existing_verification"][0].update(status="ran_passed", evidence=["E-3"])
        self.assertEqual(errs(d), [])

    def test_high_impact_needs_verification_and_mitigation(self) -> None:
        d = copy.deepcopy(VALID)
        fs = d["failure_scenarios"][0]
        fs["existing_verification"], fs["missing_verification"], fs["mitigation"] = [], [], "fix"
        e = errs(d)
        self.assertTrue(any("neither existing nor missing" in x for x in e))
        self.assertTrue(any("usable mitigation" in x for x in e))

    def test_confirmed_dependency_with_only_inferred_evidence(self) -> None:
        d = copy.deepcopy(VALID)
        d["evidence"].append({"id": "E-3", "kind": "code", "path": "x.ts", "claim": "probably imports", "status": "inferred"})
        d["affected_components"].append({"id": "AC-2", "name": "x", "kind": "module", "relationship": "confirmed", "how": "imports", "evidence": ["E-3"]})
        self.assertTrue(any("AC-2" in x for x in errs(d)))

    def test_insufficient_evidence_needs_limitation(self) -> None:
        d = copy.deepcopy(VALID)
        d["release_readiness"] = "insufficient_evidence"
        d["coverage_limitations"] = []
        self.assertTrue(any("insufficient_evidence" in x for x in errs(d)))

    def test_impact_below_worst_scenario_warns(self) -> None:
        d = copy.deepcopy(VALID)
        d["impact"] = "low"
        _, w = va.validate(d, SCHEMA)
        self.assertTrue(any("below the worst" in x for x in w))


class RepoCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        r = self.tmp.name
        g = lambda *a: subprocess.run(["git", "-C", r, *a], check=True, capture_output=True, text=True).stdout  # noqa: E731
        g("init", "-q")
        g("config", "user.email", "a@b")
        g("config", "user.name", "a")
        g("config", "commit.gpgsign", "false")
        Path(r, "src").mkdir()
        Path(r, "src/encrypt.ts").write_text("a\nif (x === null) return null\nb\n")
        Path(r, "src/encrypt.test.ts").write_text("t\n")
        g("add", ".")
        g("commit", "-qm", "base")
        self.base = g("rev-parse", "HEAD").strip()
        Path(r, "src/encrypt.ts").write_text("a\nb\n")
        g("commit", "-qam", "head")
        self.head = g("rev-parse", "HEAD").strip()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def doc(self) -> dict:
        d = copy.deepcopy(VALID)
        d["base_sha"], d["head_sha"] = self.base, self.head
        return d

    def test_paths_and_lines_resolve(self) -> None:
        self.assertEqual(va.validate(self.doc(), SCHEMA, self.tmp.name)[0], [])

    def test_line_beyond_file_at_cited_revision(self) -> None:
        d = self.doc()
        d["evidence"][0]["rev"] = "head"
        d["evidence"][0]["line_start"] = d["evidence"][0]["line_end"] = 3
        self.assertTrue(any("beyond end" in x for x in va.validate(d, SCHEMA, self.tmp.name)[0]))

    def test_missing_path(self) -> None:
        d = self.doc()
        d["evidence"][1]["path"] = "src/nope.ts"
        self.assertTrue(any("does not exist" in x for x in va.validate(d, SCHEMA, self.tmp.name)[0]))

    def test_unknown_commit(self) -> None:
        d = self.doc()
        d["head_sha"] = "3" * 40
        self.assertTrue(any("not a commit" in x for x in va.validate(d, SCHEMA, self.tmp.name)[0]))

    def test_cli_exit_codes(self) -> None:
        p = Path(self.tmp.name, "a.json")
        p.write_text(json.dumps(self.doc()))
        self.assertEqual(va.main([str(p), "--repo", self.tmp.name]), 0)
        p.write_text("{")
        self.assertEqual(va.main([str(p)]), 2)
        p.write_text(json.dumps({"schema_version": "1"}))
        self.assertEqual(va.main([str(p)]), 1)


if __name__ == "__main__":
    unittest.main()


class RenderTest(unittest.TestCase):
    def test_renders_fixture(self) -> None:
        import render_report
        text = render_report.render(VALID)
        self.assertIn("FS-1", text)
        self.assertIn("Changes or verification required", text)
        self.assertIn("`src/encrypt.ts:2` (base)", text)
