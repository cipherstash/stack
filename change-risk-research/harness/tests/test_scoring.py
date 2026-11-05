import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from score_results import score


class ScoringTest(unittest.TestCase):
    def score_findings(self, findings):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'case.json').write_text(json.dumps({'case': 'case', 'findings': findings}))
            return score(Path(tmp), {1: {'known_defects': [], 'outcome': 'no_known_defect',
                                        'expert_impact': 'low', 'attention_warranted': False}},
                         {'case': {'pr': 1, 'split': 'holdout'}}, 'holdout')

    def test_unassessed_evidence_stays_in_coverage_denominator(self):
        r = self.score_findings([{'label': 'valid', 'evidence_ok': True},
                                 {'label': 'unsupported', 'evidence_ok': False},
                                 {'label': 'valid', 'evidence_ok': None},
                                 {'label': 'trivial', 'evidence_ok': True}])
        self.assertEqual(r['material_findings'], 3)
        self.assertEqual(r['evidence_checked'], 2)
        self.assertEqual(r['evidence_passed'], 1)
        self.assertEqual(r['evidence_failed'], 1)
        self.assertEqual(r['evidence_unassessed'], 1)
        self.assertEqual(r['evidence_verification_coverage']['n'], 3)
        self.assertEqual(r['evidence_correctness_checked']['n'], 2)
        self.assertEqual(r['scenario_validity_material']['k'], 2)

    def test_no_checked_evidence_is_not_perfect(self):
        r = self.score_findings([{'label': 'valid'}])
        self.assertIsNone(r['evidence_correctness_checked']['value'])
        self.assertEqual(r['evidence_unassessed'], 1)

    def test_v1_values_preserved(self):
        root = Path(__file__).resolve().parents[2] / 'eval'
        old = json.loads((root / 'results-summary.json').read_text())['evaluators']
        new = json.loads((root / 'results-summary-v2.json').read_text())['evaluators']
        for name, before in old.items():
            self.assertEqual(before['scenario_precision_material'], new[name]['scenario_validity_material'])
            self.assertEqual(before['known_defect_recall'], new[name]['known_defect_recall'])
            self.assertEqual(before['labels'], new[name]['labels'])
