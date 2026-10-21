#!/usr/bin/env python3
"""Inventory retained transcripts and revalidate historical outputs without editing them."""
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT.parent / '.agents/skills/change-risk/scripts'))
from validate_assessment import DEFAULT_SCHEMA, validate


def main():
    schema = json.loads(DEFAULT_SCHEMA.read_text())
    assessments = []
    for p in sorted((ROOT / 'eval/change-risk/results').glob('*/*/assessment.json')):
        a = json.loads(p.read_text())
        errors, warnings = validate(a, schema)
        assessments.append({'path': str(p.relative_to(ROOT)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                            'base_sha': a['base_sha'], 'head_sha': a['head_sha'], 'assessor': a['assessor'],
                            'valid': not errors, 'errors': errors, 'warnings': warnings})
    patterns = {
        'github_token': re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{60,}'),
        'provider_key': re.compile(r'sk-ant-[A-Za-z0-9_-]{30,}|sk-proj-[A-Za-z0-9_-]{30,}'),
        'aws_access_id': re.compile(r'AKIA[A-Z0-9]{16}'),
        'private_key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        'jwt': re.compile(r'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'),
    }
    transcripts = []
    for p in sorted((ROOT / 'eval').rglob('*.gz')):
        raw = p.read_bytes()
        text = gzip.decompress(raw).decode('utf-8', errors='replace')
        matches = {name: len(pattern.findall(text)) for name, pattern in patterns.items()}
        transcripts.append({'path': str(p.relative_to(ROOT)), 'bytes': len(raw),
                            'sha256': hashlib.sha256(raw).hexdigest(),
                            'credential_pattern_counts': {k: v for k, v in matches.items() if v}})
    out = {'audit_version': '1', 'validator_revision': '1.1',
           'validation_scope': 'schema and semantics only; historical repository evidence not rechecked',
           'credential_scan_scope': 'heuristic token/private-key/JWT patterns; no proof of absence of sensitive data',
           'retention': 'retain unique transcripts in existing Git paths pending an approved accessible archive; no upload',
           'assessments': assessments, 'transcripts': transcripts}
    (ROOT / 'eval/record-audit.json').write_text(json.dumps(out, indent=2) + '\n')
    print(json.dumps({'assessments': len(assessments), 'valid': sum(a['valid'] for a in assessments),
                      'transcripts': len(transcripts), 'transcript_bytes': sum(t['bytes'] for t in transcripts),
                      'transcripts_with_pattern_matches': sum(bool(t['credential_pattern_counts']) for t in transcripts)}))


if __name__ == '__main__':
    main()
