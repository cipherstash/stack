#!/usr/bin/env python3
"""Prepare a compatible baseline pair and publish advisory ImpactGate reports.

Run from the Git checkout being assessed. Policy belongs to this script's checkout,
so tests can exercise the same workflow against isolated Git histories.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from impact_gate.baseline import build_baseline, save_baseline
from impact_gate.core.config import MeasureConfig

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / '.github' / 'impact-gate'
HISTORY_COMMITS = 200
SCOPES = {'all': 'Including test files', 'source': 'Excluding test files'}


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


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
        publish(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'report'))
    parser.add_argument('--base', required=True)
    parser.add_argument('--cache-dir', type=Path, required=True)
    parser.add_argument('--refresh', action='store_true')
    args = parser.parse_args()
    args.cache_dir = args.cache_dir.resolve()
    try:
        head = run('git', 'rev-parse', '--verify', args.base + '^{commit}')
        policy = identity()
        if args.command == 'prepare':
            prepare(args, policy, head)
        else:
            report(args, policy)
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError, TypeError,
            importlib.metadata.PackageNotFoundError) as error:
        publish(f'**ImpactGate analysis failed:** {error}')
        return error.returncode if isinstance(error, subprocess.CalledProcessError) else 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
