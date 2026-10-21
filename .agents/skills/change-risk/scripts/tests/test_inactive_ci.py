"""Execute the proposed publish decision with the actual sparse filesystem layout."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]
WORKFLOW = ROOT / 'change-risk-research/docs/examples/change-risk-advisory.yml'
SKILL = ROOT / '.agents/skills/change-risk'


class PublishFixtureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.workflow = WORKFLOW.read_text()
        publish = self.workflow.split('\n  publish:', 1)[1]
        sparse = publish.split('          sparse-checkout: |\n', 1)[1].split('          sparse-checkout-cone-mode:', 1)[0]
        for line in sparse.splitlines():
            path = line.strip()
            shutil.copytree(ROOT / path, self.root / path, ignore=shutil.ignore_patterns('__pycache__'))
        body = publish.split('      - name: Decide outcome', 1)[1].split('      - name:', 1)[0]
        self.shell = '\n'.join(line[10:] for line in body.split('        run: |\n', 1)[1].splitlines())
        subprocess.run(['bash', '-n'], input=self.shell, text=True, check=True)
        (self.root / 'out').mkdir()
        self.doc = json.loads((SKILL / 'scripts/tests/fixtures/valid.json').read_text())
        (self.root / 'bin').mkdir()
        gh = self.root / 'bin/gh'
        gh.write_text('#!/bin/sh\nprintf "%s\\n" "$CURRENT_SHA"\n')
        gh.chmod(0o755)

    def decide(self, valid='true', current=None):
        (self.root / 'out/assessment.json').write_text(json.dumps(self.doc))
        output = self.root / 'outputs'
        output.write_text('')
        env = {**os.environ, 'PATH': str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
               'GITHUB_REPOSITORY': 'example/repo', 'PR': '1', 'GITHUB_OUTPUT': str(output),
               'ASSESSED_SHA': '2' * 40, 'CURRENT_SHA': current or '2' * 40, 'EVIDENCE_VALID': valid}
        if not shutil.which('jq'):
            self.skipTest('jq required by the inactive workflow')
        result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', self.shell], cwd=self.root,
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output.read_text()

    def test_publishing_layout_includes_default_schema_and_renders(self):
        self.assertIn('outcome=attention', self.decide())
        self.assertTrue((self.root / 'out/report.md').exists())

    def test_wrong_head_invalid_analysis_and_stale_are_not_published_as_success(self):
        self.doc['head_sha'] = '3' * 40
        self.assertIn('outcome=error', self.decide())
        self.doc['head_sha'] = '2' * 40
        self.assertIn('outcome=error', self.decide(valid='false'))
        self.assertIn('outcome=stale', self.decide(current='4' * 40))

    def test_invalid_structure_and_missing_schema(self):
        del self.doc['inputs']
        self.assertIn('outcome=error', self.decide())
        (self.root / '.agents/skills/change-risk/schemas/assessment.schema.json').unlink()
        self.assertIn('outcome=error', self.decide())

    def test_safety_properties_and_inactive_location(self):
        self.assertFalse((ROOT / '.github/workflows/change-risk-advisory.yml').exists())
        analysis, publish = self.workflow.split('\n  publish:', 1)
        self.assertNotIn('pull-requests: write', analysis)
        self.assertNotIn('checks: write', analysis)
        self.assertIn('ref: ${{ github.event.pull_request.head.sha }}', analysis)
        self.assertIn('ref: ${{ github.event.pull_request.base.sha }}', publish)
        self.assertIn('--max-budget-usd', analysis)
        self.assertIn('--max-turns', analysis)
        self.assertIn('timeout-minutes:', analysis)
        self.assertIn('conclusion=neutral', publish)
        self.assertNotIn('conclusion=failure', publish)
