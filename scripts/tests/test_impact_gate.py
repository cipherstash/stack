"""Exercise the workflow driver against the pinned real CLI and Git histories."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

DRIVER = Path(__file__).resolve().parents[1] / 'impact-gate.py'
# lizard misses this function's closing brace (a ternary returning an object
# literal after an arrow callback) and runs its span on into whatever follows.
PICK = ('export function pick(xs: readonly string[], hint?: string) {\n'
        '  const hinted = xs.find((c) => c === hint)\n'
        "  return hinted ? { hinted, via: 'hint' } : null\n"
        '}\n')


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

    def pin(self, *args, expect=0):
        result = subprocess.run([sys.executable, str(DRIVER), 'pin',
                                 '--base', 'refs/remotes/origin/main', *args],
                                cwd=self.repo, text=True, capture_output=True,
                                env={**os.environ, 'GITHUB_OUTPUT': str(self.output),
                                     'GITHUB_STEP_SUMMARY': str(self.summary)})
        self.assertEqual(result.returncode, expect, result.stdout + result.stderr)
        return result

    def pull_request_merge(self):
        """Build GitHub's refs/pull/N/merge after main moved past the PR's base."""
        stale_base = self.git('rev-parse', 'main')
        self.git('checkout', '-qb', 'feature')
        pr_head = self.commit('src/feature.ts', 'export function feature() { return 1; }\n')
        self.git('checkout', '-q', 'main')
        landed = self.commit('src/landed.ts', 'export function landed() { return 2; }\n')
        self.git('checkout', '-q', '--detach', 'main')
        self.git('merge', '-q', '--no-ff', '-m', 'merge', 'feature')
        return stale_base, pr_head, landed

    def test_pull_request_scores_only_its_own_changes_when_main_moved_on(self):
        stale_base, pr_head, landed = self.pull_request_merge()
        # The event's recorded base, which the workflow used to pin: main's
        # newer commit then lands inside merge-base..HEAD as if the PR made it.
        self.git('update-ref', 'refs/remotes/origin/main', stale_base)
        self.run_driver('prepare', '--base', 'refs/remotes/origin/main')
        self.run_driver('report', '--base', 'refs/remotes/origin/main')
        self.assertIn('src/landed.ts', self.summary.read_text())

        self.output.write_text('')
        self.summary.write_text('')
        self.pin('--event-sha', stale_base, '--pr-head', pr_head)
        self.assertEqual(self.git('rev-parse', 'refs/remotes/origin/main'), landed)
        self.assertIn(f'sha={landed}\n', self.output.read_text())
        self.run_driver('prepare', '--base', 'refs/remotes/origin/main')
        self.run_driver('report', '--base', 'refs/remotes/origin/main')
        summary = self.summary.read_text()
        self.assertIn('src/feature.ts', summary)
        self.assertNotIn('src/landed.ts', summary)

    def test_push_pins_the_event_commit(self):
        head = self.git('rev-parse', 'HEAD')
        self.pin('--event-sha', head)
        self.assertEqual(self.git('rev-parse', 'refs/remotes/origin/main'), head)
        self.assertIn(f'sha={head}\n', self.output.read_text())

    def test_pull_request_pin_refuses_a_checkout_that_is_not_the_pr_merge(self):
        _, pr_head, _ = self.pull_request_merge()
        self.git('checkout', '-q', 'feature')
        result = self.pin('--event-sha', pr_head, '--pr-head', pr_head, expect=1)
        self.assertIn('not the merge of', self.summary.read_text())
        self.assertNotIn('sha=', result.stdout)

    def test_marks_cost_drivers_whose_function_span_lizard_misread(self):
        # lizard ends `pick` at the end of `after`: a ternary returning an
        # object literal after an arrow callback loses the closing brace. Edits
        # to `after` are then charged to `pick`, which the PR never touched.
        def branches(name, arg, result):
            return (f'export function {name}({arg}: number): number {{\n'
                    + ''.join(f'  if ({arg} === {i}) return {i};\n' for i in range(200))
                    + f'  return {result}\n}}\n')
        self.commit('src/pick.ts', 'export function third(y: number): number {\n  return y\n}\n\n'
                    + PICK + '\nexport function after(x: number): number {\n  return x + 1\n}\n')
        self.run_driver('prepare')
        self.git('checkout', '-qb', 'feature')
        self.commit('src/pick.ts', branches('third', 'y', 'y') + '\n' + PICK + '\n'
                    + branches('after', 'x', 'x + 1'))
        # The grade multiplies cost by files changed; the drivers table is only
        # printed above the warn percentile.
        for index in range(6):
            self.commit(f'src/extra{index}.ts', f'export function extra{index}() {{ return 1; }}\n')
        self.run_driver('report')
        rows = [line for line in self.summary.read_text().splitlines()
                if line.startswith('|') and 'src/pick.ts:' in line]
        pick_rows = [row for row in rows if 'src/pick.ts:pick`' in row]
        third_rows = [row for row in rows if 'src/pick.ts:third`' in row]
        self.assertTrue(pick_rows, self.summary.read_text())
        self.assertTrue(third_rows, self.summary.read_text())
        for row in pick_rows:
            self.assertIn('span may be misattributed', row)
        for row in third_rows:
            self.assertNotIn('span may be misattributed', row)
        self.assertIn('lizard read its line span', self.summary.read_text())

    def load_driver(self):
        """Import the driver with the fixture repository as the working directory."""
        cwd = os.getcwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, cwd)
        spec = importlib.util.spec_from_file_location('impact_gate_driver', DRIVER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_code_generating_template_literals_are_not_read_as_declarations(self):
        # A template that emits source puts `const`/`import` at column 0 inside
        # the string; that is not a declaration lizard ran into.
        self.commit('src/gen.ts', 'export function generate(name: string): string {\n'
                    '  return `\nimport { x } from "y"\nconst ${name} = x\n'
                    'export const client = ${name}\n`\n}\n')
        head = self.git('rev-parse', 'HEAD')
        self.assertEqual(self.load_driver().misread_functions([head], 'src/gen.ts'), set())

    def test_unindented_declarations_inside_a_function_body_are_not_top_level(self):
        # Column 0 alone is not top level: an unformatted body whose span
        # lizard read correctly must not be marked.
        self.commit('src/flat.ts', 'export function outer(): number {\nconst inner = 2\n'
                    'function nested() { return inner }\nreturn nested()\n}\n\n'
                    'export function sibling(): number {\n  return 3\n}\n')
        head = self.git('rev-parse', 'HEAD')
        self.assertEqual(self.load_driver().misread_functions([head], 'src/flat.ts'), set())

    def test_a_span_ending_on_a_one_line_declaration_swallows_it(self):
        # lizard ends `path` on the next declaration's first line. That is
        # harmless when only a signature is there, but a one-line declaration
        # is there whole, so edits to it are charged to `path`.
        path = ('export function path(segments: string[]): string {\n'
                '  return `$.${segments.join(".")}`\n}\n\n')
        self.commit('src/path.ts', path + 'export const LIMIT = 10\n')
        self.commit('src/boundary.ts', path + 'export function next(x: number): number {\n'
                    '  return x\n}\n')
        head = self.git('rev-parse', 'HEAD')
        driver = self.load_driver()
        self.assertEqual(driver.misread_functions([head], 'src/path.ts'), {('', 'path')})
        self.assertEqual(driver.misread_functions([head], 'src/boundary.ts'), set())

    def test_a_declaration_continued_on_the_next_line_is_not_whole(self):
        # A first line with no open bracket still continues after `=`, `=>`
        # or before a leading `|`, `&` or `.`; only a finished one is whole.
        cases = {
            "export type Foo =\n  | 'a'\n  | 'b'\n": False,
            'export const LIMIT =\n  10\n': False,
            'export const twice = (x: number) =>\n  x * 2\n': False,
            'export const chain = start\n  .next()\n': False,
            'export const LIMIT = 10\n': True,
            'export const LIMIT = 10 // a comment\n\nexport const MORE = 11\n': True,
            'export const x = foo(\n  1,\n)\n': False,
            'export type Row = Record<string, number>\nexport const y = 1\n': True,
            'export const value = input!\n\nexport const y = 1\n': True,
            'export const nested = new Map<string, Array<number>>()\nexport const y = 1\n': True,
            'export type Nested = Map<string, Array<number>>\nexport const y = 1\n': True,
            'export const large = value >\n  10\n': False,
            'export const off = !\n  enabled\n': False,
        }
        driver = self.load_driver()
        for source, whole in cases.items():
            with self.subTest(source=source):
                self.assertEqual(driver.declaration_lines('a.ts', source)[1], whole)

    def test_marks_a_function_above_a_removed_declaration(self):
        # At the base, `pick`'s span swallows `gone`; the PR deletes `gone`.
        self.commit('src/pick.ts', PICK + '\nexport function gone(x: number): number {\n'
                    '  return x\n}\n\nexport function kept(y: number): number {\n  return y\n}\n')
        base = self.git('rev-parse', 'HEAD')
        self.commit('src/pick.ts', PICK + '\nexport function kept(y: number): number {\n'
                    '  return y + 1\n}\n')
        found = self.load_driver().misread_functions([base, 'HEAD'], 'src/pick.ts')
        self.assertIn(('', 'pick'), found)
        self.assertNotIn(('', 'kept'), found)

    def test_marks_a_function_above_appended_code(self):
        # At the base `pick` ends the file; the PR appends after it.
        self.commit('src/pick.ts', 'export function edited(y: number): number {\n  return y\n}\n\n'
                    + PICK)
        base = self.git('rev-parse', 'HEAD')
        self.commit('src/pick.ts', 'export function edited(y: number): number {\n  return y + 1\n}\n\n'
                    + PICK + '\nexport function appended(x: number): number {\n  return x\n}\n')
        found = self.load_driver().misread_functions([base, 'HEAD'], 'src/pick.ts')
        self.assertIn(('', 'pick'), found)
        self.assertNotIn(('', 'edited'), found)

    def test_marking_failure_keeps_the_unmarked_report(self):
        report = '| 1 | `src/main.ts:count` | _file scope_ | 1 | 0 | mutation |'
        marked = self.load_driver().mark_misread_spans(report, 'missing-target')
        self.assertTrue(marked.startswith(report))
        self.assertIn('could not check function spans', marked)

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
