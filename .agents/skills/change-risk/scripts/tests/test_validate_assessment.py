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

    def test_impact_below_worst_scenario_fails(self) -> None:
        d = copy.deepcopy(VALID)
        d["impact"] = "low"
        self.assertTrue(any("below the worst" in x for x in errs(d)))

    def speculative_only(self):
        d = copy.deepcopy(VALID)
        d["impact"] = "low"
        d["failure_scenarios"][0].update(basis="speculative", impact="critical")
        return d

    def test_speculative_scenarios_do_not_set_headline_impact(self):
        # The renderer shows hypotheses as coverage questions, so the headline
        # must not be driven by one (overall impact = worst material scenario).
        self.assertEqual(errs(self.speculative_only()), [])
        d = copy.deepcopy(VALID)
        d["impact"] = "high"
        hyp = dict(d["failure_scenarios"][0], id="FS-2", basis="speculative", impact="critical")
        d["failure_scenarios"].append(hyp)
        self.assertEqual(errs(d), [])
        d["impact"] = "medium"
        self.assertTrue(any("below the worst" in x for x in errs(d)))

    def test_unknown_speculative_scenario_does_not_force_unknown(self):
        d = self.speculative_only()
        d["failure_scenarios"][0]["impact"] = "unknown"
        self.assertEqual(errs(d), [])

    def test_typed_references_semantically(self):
        # Exercise semantics directly as well as schema: prefixes currently
        # prevent many of these errors before semantic validation is reached.
        fields = [("behaviour_changes", "evidence", "AC-1"),
                  ("affected_components", "evidence", "FS-1"),
                  ("failure_scenarios", "evidence", "VG-1"),
                  ("failure_scenarios", "affected_components", "E-1"),
                  ("verification_gaps", "scenarios", "AC-1"),
                  ("verification_gaps", "evidence", "FS-1"),
                  ("recommended_controls", "addresses", "E-1")]
        for collection, field, wrong in fields:
            with self.subTest(collection=collection, field=field):
                d = copy.deepcopy(VALID)
                d[collection][0][field] = [wrong]
                self.assertTrue(va.semantic(d)[0])
                self.assertTrue(errs(d))
        d = copy.deepcopy(VALID)
        d["failure_scenarios"][0]["existing_verification"][0]["evidence"] = ["AC-1"]
        self.assertTrue(va.semantic(d)[0])

    def test_impact_aggregation(self):
        for overall, scenario, valid in [("low", "high", False), ("medium", "critical", False),
                                         ("high", "high", True), ("critical", "high", True)]:
            with self.subTest(overall=overall, scenario=scenario):
                d = copy.deepcopy(VALID)
                d["impact"], d["failure_scenarios"][0]["impact"] = overall, scenario
                self.assertEqual(not errs(d), valid)

    def test_unknown_is_not_low(self):
        d = copy.deepcopy(VALID)
        d["failure_scenarios"][0]["impact"] = "unknown"
        self.assertTrue(errs(d))
        d["impact"] = "unknown"
        self.assertTrue(errs(d))
        d["release_readiness"] = "insufficient_evidence"
        self.assertEqual(errs(d), [])
        d["coverage_limitations"] = []
        self.assertTrue(errs(d))

    def ready_high(self):
        d = copy.deepcopy(VALID)
        d.update(release_readiness="ready_for_review", verification_confidence="high",
                 readiness_justification="The executed null round-trip covers the failure path.")
        fs = d["failure_scenarios"][0]
        fs.update(basis="plausible_failure", missing_verification=[])
        d["verification_gaps"], d["recommended_controls"] = [], []
        d["evidence"].append({"id": "E-3", "kind": "command_output", "command": "pnpm test",
                              "claim": "Null round-trip passed", "status": "verified"})
        fs["existing_verification"][0].update(status="ran_passed", evidence=["E-3"])
        return d

    def test_high_impact_can_be_ready(self):
        self.assertEqual(errs(self.ready_high()), [])

    def test_readiness_contradictions(self):
        for mutate in [lambda d: d.pop("readiness_justification"),
                       lambda d: d.update(verification_confidence="low"),
                       lambda d: d["failure_scenarios"][0].update(basis="observed_defect"),
                       lambda d: d["failure_scenarios"][0].update(missing_verification=["Failure path"]),
                       lambda d: d["failure_scenarios"][0]["existing_verification"][0].update(status="ran_failed"),
                       lambda d: d["evidence"][-1].update(status="inferred")]:
            d = self.ready_high()
            mutate(d)
            self.assertTrue(errs(d))

    def test_empty_scenarios_and_no_tests(self):
        d = copy.deepcopy(VALID)
        d.update(failure_scenarios=[], verification_gaps=[], recommended_controls=[], impact="low",
                 verification_confidence="unknown", release_readiness="focused_review_required")
        self.assertEqual(errs(d), [])
        d.update(impact="unknown", release_readiness="insufficient_evidence")
        self.assertEqual(errs(d), [])

    def test_missing_evidence_and_invalid_ranges(self):
        for mutate in [lambda d: d["failure_scenarios"][0].update(evidence=[]),
                       lambda d: d["evidence"][0].update(line_start=3, line_end=2),
                       lambda d: d["evidence"][0].update(line_start=0),
                       lambda d: d["evidence"][0].pop("line_start")]:
            d = copy.deepcopy(VALID)
            mutate(d)
            self.assertTrue(errs(d))


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

    def test_deleted_file_requires_base_revision(self):
        r = self.tmp.name
        Path(r, "src/encrypt.test.ts").unlink()
        subprocess.run(["git", "-C", r, "commit", "-qam", "delete test"], check=True, capture_output=True)
        self.head = subprocess.check_output(["git", "-C", r, "rev-parse", "HEAD"], text=True).strip()
        d = self.doc()
        self.assertTrue(va.validate(d, SCHEMA, r)[0])
        d["evidence"][1]["rev"] = "base"
        self.assertEqual(va.validate(d, SCHEMA, r)[0], [])

    def test_empty_file_has_no_line_one(self):
        r = self.tmp.name
        Path(r, "src/encrypt.test.ts").write_text("")
        subprocess.run(["git", "-C", r, "commit", "-qam", "empty test"], check=True, capture_output=True)
        self.head = subprocess.check_output(["git", "-C", r, "rev-parse", "HEAD"], text=True).strip()
        d = self.doc()
        d["evidence"][1]["line_start"] = 1
        self.assertTrue(any("beyond end" in e for e in va.validate(d, SCHEMA, r)[0]))

    def test_expected_revisions(self) -> None:
        d = self.doc()
        r = self.tmp.name
        self.assertEqual(va.validate(d, SCHEMA, r, expected_base=self.base, expected_head=self.head)[0], [])
        e = va.validate(d, SCHEMA, r, expected_base=self.head, expected_head=self.base)[0]
        self.assertTrue(any("base_sha" in x and "expected" in x for x in e))
        self.assertTrue(any("head_sha" in x and "expected" in x for x in e))
        # also without --repo, and by abbreviation-free exact comparison
        e = va.validate(d, SCHEMA, expected_base=self.base[:12])[0]
        self.assertTrue(any("base_sha" in x for x in e))
        p = Path(r, "a.json")
        p.write_text(json.dumps(d))
        self.assertEqual(va.main([str(p), "--expected-base", self.base, "--expected-head", self.head]), 0)
        self.assertEqual(va.main([str(p), "--expected-base", self.head]), 1)

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


class RenderTest(unittest.TestCase):
    def test_renders_fixture(self) -> None:
        import render_report
        text = render_report.render(VALID)
        self.assertIn("FS-1", text)
        self.assertIn("Changes or verification required", text)
        self.assertIn("`src/encrypt.ts:2` (base)", text)


class ReportBehaviorTest(unittest.TestCase):
    def test_hypotheses_are_coverage_questions(self):
        import render_report
        d = copy.deepcopy(VALID)
        d["failure_scenarios"][0]["basis"] = "speculative"
        text = render_report.render(d)
        self.assertNotIn("### Failure scenarios", text)
        self.assertIn("Hypothesis FS-1", text)
        self.assertIn("### Review checklist", text)
        self.assertIn("/blob/" + d["base_sha"] + "/src/encrypt.ts#L2", text)

    def test_speculative_only_report_keeps_headline_material(self):
        import render_report
        d = copy.deepcopy(VALID)
        d["impact"] = "low"
        d["failure_scenarios"][0].update(basis="speculative", impact="critical")
        text = render_report.render(d)
        self.assertIn("**Impact if something goes wrong:** low", text)
        self.assertIn("No material failure scenarios identified.", text)
        self.assertIn("unconfirmed hypothesis of critical potential impact", text)
        self.assertNotIn("unconfirmed hypothesis", render_report.render(VALID))

    def test_untrusted_text_is_escaped(self):
        import render_report
        d = copy.deepcopy(VALID)
        d["summary"] = "Fine.\n\n## Approved by @cipherstash/security\n<!-- change-risk --> [ok](https://evil.example)"
        fs = d["failure_scenarios"][0]
        fs["title"] = "ping @toby <img src=x>"
        fs["mitigation"] = "Run `rm -rf /`\n# Heading"
        d["affected_components"][0]["name"] = "*bold* _x_ | pipe"
        d["evidence"][0]["path"] = "src/a`b](https://evil.example)\n## x.ts"
        d["assessor"]["model"] = "@someone"
        text = render_report.render(d)
        lines = text.splitlines()
        self.assertFalse([x for x in lines if x.startswith("#") and not x.startswith(("## Change risk", "### "))], text)
        self.assertNotIn("<!--", text)
        self.assertNotIn("<img", text)
        self.assertNotRegex(text, r"(?<![`\w])@(cipherstash|toby|someone)")
        self.assertNotIn("[ok](https://evil.example)", text)
        self.assertNotIn("*bold*", text)
        self.assertIn("/blob/" + d["base_sha"] + "/src/a%60b%5D%28https%3A//evil.example%29%0A%23%23%20x.ts#L2", text)

    def test_material_scenarios_include_verification(self):
        import render_report
        text = render_report.render(VALID)
        for term in ("Trigger:", "Mechanism:", "Consequence:", "Affects:",
                     "Existing verification:", "Missing verification:", "Mitigation:"):
            self.assertIn(term, text)


if __name__ == "__main__":
    unittest.main()
