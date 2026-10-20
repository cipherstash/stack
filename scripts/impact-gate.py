#!/usr/bin/env python3
"""Prepare a compatible baseline pair and publish advisory ImpactGate reports.

Run from the Git checkout being assessed. Policy belongs to this script's checkout,
so tests can exercise the same workflow against isolated Git histories.
"""
import argparse
import bisect
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from impact_gate.baseline import build_baseline, save_baseline
from impact_gate.core.config import MeasureConfig
import lizard
from pygments.lexers import JavascriptLexer, TypeScriptLexer
from pygments.token import Comment, Keyword, Name, Operator, Punctuation

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / '.github' / 'impact-gate'
HISTORY_COMMITS = 200
SCOPES = {'all': 'Including test files', 'source': 'Excluding test files'}


def run(*args: str) -> str:
    # Capture stderr: CalledProcessError's message omits it, and the summary needs it.
    return subprocess.run(args, text=True, check=True, capture_output=True).stdout.strip()


def describe(error: Exception) -> str:
    if not isinstance(error, subprocess.CalledProcessError):
        return f'{type(error).__name__}: {error}'
    args = [str(arg) for arg in error.cmd]
    # Name the tool and subcommand, not the absolute-path argv.
    command = ' '.join(args[2:4] if args[1:2] == ['-m'] else args[:2])
    text = f'`{command}` exited with status {error.returncode}.'
    stderr = (error.stderr or '').strip()
    return text + (f'\n\n```\n{stderr}\n```' if stderr else '')


def cli(*args: str) -> str:
    return run(sys.executable, '-m', 'impact_gate', *args)


def identity() -> str:
    digest = hashlib.sha256(Path(__file__).read_bytes())
    for path in sorted(POLICY.glob('*')):
        if path.is_file():
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
    for package in ('impact-gate', 'lizard'):
        digest.update(importlib.metadata.version(package).encode())
    return digest.hexdigest()


def read_baseline(path: Path, head: str) -> int:
    data = json.loads(path.read_text())
    meta, values = data['_meta'], data['distribution']
    if (meta['tool'] != 'impact-gate' or meta['head'] != head
            or type(meta['n']) is not int or not isinstance(values, list)
            or meta['n'] != len(values)
            or any(type(v) is not int or v < 0 for v in values)
            or values != sorted(values)):
        raise ValueError(f'Invalid baseline: {path}')
    return meta['n']


def valid_pair(cache: Path, policy: str, base: str) -> dict | None:
    try:
        meta = json.loads((cache / 'metadata.json').read_text())
        if meta['policy'] != policy or meta['base_ref'] != base:
            return None
        # A fallback cache must come from this target's landed history.
        result = subprocess.run(['git', 'merge-base', '--is-ancestor', meta['head'], base],
                                capture_output=True)
        if result.returncode != 0:
            return None
        for scope in SCOPES:
            path = cache / f'{scope}.json'
            read_baseline(path, meta['head'])
            if hashlib.sha256(path.read_bytes()).hexdigest() != meta['hashes'][scope]:
                return None
        return meta
    except (OSError, ValueError, KeyError, TypeError):
        return None


def output(name: str, value: str) -> None:
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
            out.write(f'{name}={value}\n')
    print(f'{name}={value}')


def prepare(args: argparse.Namespace, policy: str, head: str) -> None:
    if not args.refresh and valid_pair(args.cache_dir, policy, args.base):
        output('rebuilt', 'false')
        return
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    # Stage both files: failed generation never advertises a usable half-pair.
    with tempfile.TemporaryDirectory(dir=args.cache_dir) as temporary:
        staged = Path(temporary)
        hashes = {}
        for scope in SCOPES:
            path = staged / f'{scope}.json'
            # Upstream's CLI rejects n=0. Its library distinguishes a valid empty
            # history from failures without matching stderr or masking exceptions.
            baseline = build_baseline('.', MeasureConfig.load(str(POLICY / f'{scope}.yml')),
                                      base_ref=head, max_commits=HISTORY_COMMITS)
            save_baseline(baseline, str(path))
            read_baseline(path, head)
            hashes[scope] = hashlib.sha256(path.read_bytes()).hexdigest()
        meta = {'policy': policy, 'base_ref': args.base, 'head': head,
                'max_commits': HISTORY_COMMITS, 'hashes': hashes}
        for scope in SCOPES:
            (staged / f'{scope}.json').replace(args.cache_dir / f'{scope}.json')
        (staged / 'metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
        (staged / 'metadata.json').replace(args.cache_dir / 'metadata.json')
    output('rebuilt', 'true')


def publish(text: str) -> None:
    print(text)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write(text + '\n')


def report(args: argparse.Namespace, policy: str) -> None:
    meta = valid_pair(args.cache_dir, policy, args.base)
    if meta is None:
        raise ValueError('Baseline pair is missing or incompatible; run prepare first.')
    publish('# Advisory change impact\n\n'
            'SQL and TypeScript .mts/.cts files are unsupported. No eligible source means '
            'no quality assessment. Excluding test files retains inline Rust tests. '
            'TypeScript function-span defects and mechanical renames can distort scores.\n\n'
            f'Baseline target: `{args.base}`; commit: `{meta["head"]}`. '
            f'History: latest {HISTORY_COMMITS} first-parent commits; recursively expanded '
            'merge observations may exceed this limit. p90/p98 are advisory; prior weight: 200.')
    spans: dict = {}  # Both scopes list the same functions.
    for scope, label in SCOPES.items():
        path = args.cache_dir / f'{scope}.json'
        n = read_baseline(path, meta['head'])
        publish(f'## {label}\n\nProject observations: {n}; project weight: {n / (n + 200):.4f}.'
                + (' **Seed-only grading: no eligible history observations.**' if n == 0 else ''))
        result = cli('score', '--config', str(POLICY / 'gate.yml'),
                     '--mode', 'range', '--base', args.base, '--curve',
                     '--enforcement', 'warn', '--format', 'markdown', '--warn-percentile', '90',
                     '--block-percentile', '98', '--curve-prior-weight', '200',
                     '--baseline-file', str(path), '--measure-config', str(POLICY / f'{scope}.yml'))
        publish(mark_misread_spans(result, args.base, spans))


# lizard's TypeScript reader sometimes misses a function's closing brace (an
# arrow callback followed by a ternary returning an object literal is one
# trigger) and runs the span on into the next top-level declaration. Edits to
# that neighbour are then charged to a function the PR never touched. In
# formatted code nothing inside a function body starts at column 0, so a
# top-level declaration strictly inside a span is the tell. Pygments decides
# what is code: a column-0 `const` inside a template literal is string text.
# Limit: when the misread makes lizard drop functions instead (the same
# trigger inside a class method reports only an `(anonymous)` function), the
# edits land on a row that has no span to check, and nothing is marked.
SPAN_SUFFIXES = ('.ts', '.tsx', '.js', '.jsx')
DECLARATION = re.compile(r'@|(export|import|declare|abstract|async|function|const|let|var'
                         r'|class|interface|type|enum)\b')
# Tokens that can only continue the previous line's expression. Unary
# operators (`-`, `!`) are left out: a line may begin a new statement with one.
LEADING = frozenset(('|', '&', '.', '?.', '?', ':', '=>', '&&', '||', '??', '=', ','))
LOCATION = re.compile(r'^\| [^|]* \| `(?P<path>[^`:]+):(?P<name>[^`]+)` \| '
                      r'(?:`(?P<owner>[^`]+)`|_file scope_) \|')
MISREAD = '⚠️ span may be misattributed'
MISREAD_NOTE = (f'{MISREAD}: lizard read its line span to include a later top-level '
                'declaration, so edits to that code are charged to this function. Check '
                'the diff before refactoring it. Scores and grades are unchanged.')


def declaration_lines(path: str, source: str) -> dict[int, bool]:
    """Line of each top-level declaration, mapped to whether it ends on that line."""
    lexer = TypeScriptLexer() if path.endswith(('.ts', '.tsx')) else JavascriptLexer()
    starts = [0]
    for line in source.split('\n')[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    # Column 0 is not top level in unformatted code, so count braces too.
    # Brackets of every kind decide whether a declaration closes on its line.
    declarations, depth, nesting, open_at_end = set(), 0, 0, {}
    first, last = {}, {}  # Each line's first and last code token.
    for offset, token, value in lexer.get_tokens_unprocessed(source):
        line = bisect.bisect_right(starts, offset)
        if value.strip() and token not in Comment:
            first.setdefault(line, (token, value))
            last[line] = (token, value, offset)
        if (depth == 0 and starts[line - 1] == offset
                and (token in Keyword or token in Name.Decorator)
                and DECLARATION.match(source, offset)):
            declarations.add(line)
        elif token in Punctuation:
            depth = max(0, depth + value.count('{') - value.count('}'))
            nesting = max(0, nesting + sum(map(value.count, '({[')) - sum(map(value.count, ')}]')))
            open_at_end[line] = nesting > 0
    # A balanced first line still continues when it ends on an operator
    # (`type T =`, `=>`) or the next code line leads with one (`| 'b'`, `.next()`).
    code_lines = sorted(first)

    def closes(line: int, value: str, offset: int) -> bool:
        # An operator that ends its operand: the `>` of a generic the line
        # opened, or a postfix `!`/`++`/`--` written against that operand.
        text = source[starts[line - 1]:offset + len(value)]
        if value.strip('>') == '':
            return text.count('<') >= text.count('>')
        return value in ('!', '++', '--') and re.match(r'[\w)\]]', source[offset - 1]) is not None

    def continues(line: int) -> bool:
        following = code_lines[bisect.bisect_right(code_lines, line):]
        token, value, offset = last.get(line, (None, '', 0))
        trails = ((token in Operator and not closes(line, value, offset))
                  or value in ('=>', ',', '.'))
        return trails or (bool(following) and first[following[0]][1] in LEADING)

    return {line: not open_at_end.get(line, False) and not continues(line)
            for line in declarations}


def misread_functions(revisions: list[str], path: str) -> set[tuple[str, str]]:
    """(owner, name) of each function whose span, in any revision, swallows a declaration."""
    found = set()
    for revision in revisions:
        shown = subprocess.run(['git', 'show', f'{revision}:{path}'], capture_output=True)
        if shown.returncode != 0:  # Added or deleted on one side.
            continue
        source = shown.stdout.decode('utf-8', errors='replace')
        declarations = declaration_lines(path, source)
        for function in lizard.analyze_file.analyze_source_code(path, source).function_list:
            owner, _, name = function.name.rpartition('::')
            # lizard often ends a span on the next declaration's first line.
            # That boundary is harmless unless the whole declaration is there.
            if name != '(anonymous)' and any(
                    function.start_line < n < function.end_line
                    or (n == function.end_line and whole)
                    for n, whole in declarations.items()):
                found.add((owner, name))
    return found


def mark_misread_spans(markdown: str, base: str, cache: dict | None = None) -> str:
    """Label function rows whose span lizard misread. Never fails the report."""
    cache = {} if cache is None else cache
    try:
        if 'revisions' not in cache:
            cache['revisions'] = [run('git', 'merge-base', base, 'HEAD'), 'HEAD']
        marked = False
        lines = markdown.split('\n')
        for index, line in enumerate(lines):
            match = LOCATION.match(line)
            if not match or not match['path'].endswith(SPAN_SUFFIXES):
                continue
            path = match['path']
            if path not in cache:
                cache[path] = misread_functions(cache['revisions'], path)
            if (match['owner'] or '', match['name']) in cache[path]:
                cell = f'`{path}:{match["name"]}`'
                lines[index] = line.replace(cell, f'{cell} {MISREAD}', 1)
                marked = True
        text = '\n'.join(lines)
        return text + f'\n\n{MISREAD_NOTE}' if marked else text
    except Exception as error:  # A cosmetic label must not cost the report.
        return markdown + f'\n\n_Note: could not check function spans ({describe(error)})._'


def pin(args: argparse.Namespace) -> None:
    """Point the target ref at the commit this run's change is measured from.

    A push measures from its own commit. A pull request checks out
    refs/pull/N/merge, GitHub's merge of the PR into the target branch's tip
    when the event fired (a re-run reuses it). The event's pull_request.base.sha
    is older whenever the target moved on after the PR last synced, and scoring
    from it counts the target's newer commits as the PR's. The merge's first
    parent is the tip it was built on, so HEAD^1..HEAD is exactly what the PR
    adds.
    """
    base = args.event_sha
    if args.pr_head:
        parents = run('git', 'rev-list', '--parents', '-n', '1', 'HEAD').split()[1:]
        if len(parents) != 2 or parents[1] != args.pr_head:
            raise ValueError(f'HEAD is not the merge of {args.pr_head} into the target; '
                             'check out refs/pull/N/merge.')
        base = parents[0]
    run('git', 'update-ref', args.base, base)
    output('sha', base)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('pin', 'prepare', 'report'))
    parser.add_argument('--base', required=True)
    parser.add_argument('--cache-dir', type=Path)
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--event-sha', help='pin: the commit the event was raised for')
    parser.add_argument('--pr-head', help='pin: the pull request head, on pull_request events')
    args = parser.parse_args()
    if args.command == 'pin':
        if not args.event_sha:
            parser.error('pin requires --event-sha')
    elif args.cache_dir is None:
        parser.error(f'{args.command} requires --cache-dir')
    else:
        args.cache_dir = args.cache_dir.resolve()
    try:
        if args.command == 'pin':
            pin(args)
            return 0
        head = run('git', 'rev-parse', '--verify', args.base + '^{commit}')
        policy = identity()
        if args.command == 'prepare':
            prepare(args, policy, head)
        else:
            report(args, policy)
    except subprocess.CalledProcessError as error:
        publish(f'**ImpactGate analysis failed:** {describe(error)}')
        return error.returncode
    except Exception as error:  # A broken policy file must still reach the summary.
        publish(f'**ImpactGate analysis failed:** {describe(error)}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
