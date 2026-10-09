"""Exercise the workflow driver against the pinned real CLI and Git histories."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

DRIVER = Path(__file__).resolve().parents[1] / 'impact-gate.py'


class ImpactWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.cache = self.repo / 'cache'
        self.summary = self.repo / 'summary.md'
        self.output = self.repo / 'output'
        self.git('init', '-b', 'main')
        self.git('config', 'user.email', 'test@example.com')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'commit.gpgsign', 'false')
        self.commit('README.md', 'fixture\n')
        self.commit('src/main.ts', 'export function count(x: number) {\n  return x + 1;\n}\n')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo, text=True).strip()

    def commit(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        self.git('add', name)
        self.git('commit', '-qm', name)
        return self.git('rev-parse', 'HEAD')

    def policy_copy(self, **files):
        # Policy is bound to the driver's checkout, so damage a copied checkout.
        root = Path(self.temp.name) / 'driver-checkout'
        shutil.copytree(DRIVER.parents[1] / '.github' / 'impact-gate',
                        root / '.github' / 'impact-gate')
        (root / 'scripts').mkdir()
        shutil.copy(DRIVER, root / 'scripts' / DRIVER.name)
        for name, content in files.items():
            (root / '.github' / 'impact-gate' / name).write_text(content)
        return root / 'scripts' / DRIVER.name

    def run_driver(self, command, *args, expect=0, driver=DRIVER):
        result = subprocess.run([sys.executable, str(driver), command,
                                 '--base', 'main', '--cache-dir', str(self.cache), *args],
                                cwd=self.repo, text=True, capture_output=True,
                                env={**os.environ, 'GITHUB_OUTPUT': str(self.output),
                                     'GITHUB_STEP_SUMMARY': str(self.summary)})
        self.assertEqual(result.returncode, expect, result.stdout + result.stderr)
        return result

    def test_cold_baseline_then_reuse_and_refresh(self):
        self.run_driver('prepare')
        self.assertIn('rebuilt=true', self.output.read_text())
        original = (self.cache / 'metadata.json').read_bytes()
        self.output.write_text('')
        self.run_driver('prepare')
        self.assertEqual(self.output.read_text(), 'rebuilt=false\n')
        self.assertEqual((self.cache / 'metadata.json').read_bytes(), original)
        self.run_driver('prepare', '--refresh')
        self.assertTrue(self.output.read_text().endswith('rebuilt=true\n'))
        self.git('checkout', '-qb', 'feature')
        self.commit('src/main.ts', 'export function count(x: number) {\n  if (x > 0) return x + 2;\n  return 0;\n}\n')
        self.run_driver('report')
        summary = self.summary.read_text()
        self.assertIn('Including test files', summary)
        self.assertIn('Excluding test files', summary)
        self.assertIn('Project observations: 1', summary)
        self.assertIn('src/main.ts', summary)

    def test_corrupt_pair_and_policy_mismatch_rebuild(self):
        self.run_driver('prepare')
        for damage in ('truncated', 'shape', 'policy'):
            with self.subTest(damage=damage):
                if damage == 'truncated':
                    (self.cache / 'all.json').write_text('{')
                elif damage == 'shape':
                    (self.cache / 'source.json').write_text('[]')
                else:
                    path = self.cache / 'metadata.json'
                    metadata = json.loads(path.read_text())
                    metadata['policy'] = 'old tool or measure policy'
                    path.write_text(json.dumps(metadata))
                self.output.write_text('')
                self.run_driver('prepare')
                self.assertEqual(self.output.read_text(), 'rebuilt=true\n')
                self.run_driver('report')

    def test_target_provenance_rejects_unrelated_history(self):
        self.run_driver('prepare')
        self.git('checkout', '--orphan', 'other')
        self.git('rm', '-rf', '--cached', '.')
        self.commit('other.ts', 'export function other() { return 2; }\n')
        self.git('branch', '-f', 'main', 'HEAD')
        self.output.write_text('')
        self.run_driver('prepare')
        self.assertEqual(self.output.read_text(), 'rebuilt=true\n')

    def test_ancestor_cache_reused_but_other_target_ref_rebuilds(self):
        self.run_driver('prepare')
        self.commit('src/next.go', 'package next\nfunc Next() int { return 1 }\n')
        self.output.write_text('')
        self.run_driver('prepare')
        self.assertEqual(self.output.read_text(), 'rebuilt=false\n')
        self.git('branch', 'release')
        self.output.write_text('')
        self.run_driver('prepare', '--base', 'release')
        self.assertEqual(self.output.read_text(), 'rebuilt=true\n')

    def test_production_fixture_catalog_survives_test_filter(self):
        self.run_driver('prepare')
        self.git('checkout', '-qb', 'feature')
        self.commit('packages/eql/crates/eql-domains/src/fixtures/catalog.rs',
                    'pub fn catalog() -> i32 { 1 }\n')
        self.commit('packages/test-kit/src/helper.ts', 'export function helper() { return 1; }\n')
        self.commit('pkg/generated_stash.go', 'package pkg\nfunc Generated() int { return 1 }\n')
        self.run_driver('report')
        including, excluding = self.summary.read_text().split('## Excluding test files')
        self.assertIn('catalog.rs', excluding)
        self.assertIn('helper.ts', including)
        self.assertNotIn('helper.ts', excluding)
        self.assertNotIn('generated_stash.go', including)

    def test_analysis_failure_is_not_hidden_by_summary(self):
        result = self.run_driver('prepare', '--base', 'missing-target', expect=128)
        self.assertIn('analysis failed', self.summary.read_text())
        self.assertNotIn('rebuilt=true', result.stdout)

    def test_malformed_policy_failure_reaches_summary(self):
        for content in ('ignore: [unclosed\n', '- a\n'):
            with self.subTest(content=content):
                shutil.rmtree(Path(self.temp.name) / 'driver-checkout', ignore_errors=True)
                self.summary.write_text('')
                driver = self.policy_copy(**{'all.yml': content})
                self.run_driver('prepare', '--refresh', expect=1, driver=driver)
                self.assertIn('ImpactGate analysis failed', self.summary.read_text())

    def test_score_failure_summary_includes_tool_stderr(self):
        self.run_driver('prepare')
        driver = self.policy_copy(**{'gate.yml': 'warn_percentile: 99\nblock_percentile: 50\n'})
        # The copied checkout has a different policy identity; rebuild its pair.
        self.run_driver('prepare', '--refresh', driver=driver)
        self.summary.write_text('')
        self.run_driver('report', expect=1, driver=driver)
        self.assertIn('warn_percentile must be <= block_percentile', self.summary.read_text())

    def test_scopes_and_empty_history(self):
        self.git('checkout', '-qb', 'feature')
        self.commit('src/main.test.ts', 'export function test() { return 3; }\n')
        self.run_driver('prepare')
        self.run_driver('report')
        including, excluding = self.summary.read_text().split('## Excluding test files')
        self.assertIn('main.test.ts', including)
        self.assertNotIn('main.test.ts', excluding)
        self.git('branch', '-f', 'main', 'HEAD~2')
        self.run_driver('prepare')
        self.summary.write_text('')
        self.run_driver('report')
        self.assertIn('Seed-only grading', self.summary.read_text())

    def test_no_eligible_source_and_mechanical_rename(self):
        self.run_driver('prepare')
        self.git('checkout', '-qb', 'feature')
        self.commit('generated/client.ts', 'export function generated() { return 3; }\n')
        self.commit('schema.sql', 'select 1;\n')
        self.commit('src/types.mts', 'export const value = 1;\n')
        self.run_driver('report')
        summary = self.summary.read_text()
        self.assertIn('No eligible source', summary)
        self.assertNotIn('generated/client.ts', summary)
        self.assertNotIn('schema.sql', summary)
        self.assertNotIn('src/types.mts', summary)
        self.git('mv', 'src/main.ts', 'src/renamed.ts')
        self.git('commit', '-qm', 'rename')
        self.summary.write_text('')
        self.run_driver('report')
        self.assertIn('mechanical renames', self.summary.read_text())

    def test_high_impact_is_advisory_and_local_policy_is_ignored(self):
        self.run_driver('prepare')
        self.git('checkout', '-qb', 'feature')
        self.commit('.impact-gate.yml', 'cognitive_max: 0\nenforcement: block\n')
        for index in range(12):
            self.commit(f'src/large{index}.ts', 'export function large(x: number) {\n'
                        + ''.join(f'  if (x === {i}) return {i};\n' for i in range(60))
                        + '  return x;\n}\n')
        self.run_driver('report')
        self.assertIn('large', self.summary.read_text())
        self.assertIn('WARN', self.summary.read_text())


if __name__ == '__main__':
    unittest.main()
