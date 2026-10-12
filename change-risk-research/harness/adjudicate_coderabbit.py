#!/usr/bin/env python3
"""Write CodeRabbit adjudications from the labels recorded below.

    adjudicate_coderabbit.py

Reads eval/coderabbit/<pr>.json and writes eval/adjudication/coderabbit/original/stack-<pr>.json for
every holdout case CodeRabbit actually reviewed. Cases it did not review are not scored for it (its
coverage is reported separately). Rules, fixed before scoring:
  - "duplicate comment" entries repeat an earlier finding and are dropped.
  - Nitpicks are `trivial` unless a label below says otherwise.
  - Labels were assigned from the comment text, with the cited code spot-checked where a label
    depended on it (evidence_ok is true only where it was checked).
  - CodeRabbit reviewed intermediate commits as well as the final head; its findings are scored
    against the final head's known defects, which can favour or penalise it.
  - attention = at least one non-nitpick finding labelled match or valid.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# pr -> {finding id: (label, matches, evidence_ok, note)}
LABELS: dict[int, dict[str, tuple]] = {
    314: {
        "CR-1": ("trivial", [], None, "example app env guard"),
        "CR-2": ("trivial", [], None, "markdown lint"),
        "CR-3": ("trivial", [], None, "version string"),
        "CR-4": ("unsupported", [], None, "generic: no path from plaintext to this error message shown"),
        "CR-5": ("valid", [], None, "process.exit in an exported library function"),
        "CR-6": ("unsupported", [], None, "generic plaintext-in-logs claim with no source shown"),
        "CR-7": ("valid", [], None, "client not closed on connect failure; low impact in a CLI"),
        "CR-8": ("valid", [], None, "fetch without timeout; low"),
        "CR-9": ("incorrect", [], False, "Vite/Vitest inject __dirname into config files; not a ReferenceError"),
        "CR-10": ("valid", [], None, "changeset peer-bump policy change can skip coordinated releases"),
        "CR-11": ("trivial", [], None, "changeset wording"),
        "CR-12": ("incorrect", [], False, "tsup emits .d.cts for the cjs format in a type:module package"),
        "CR-13": ("valid", [], None, "shell interpolation of a CLI argument; local, low"),
        "CR-14": ("valid", [], None, "non-transactional config state transition"),
        "CR-15": ("trivial", [], None, "error message key name"),
        "CR-16": ("valid", [], None, "first export assumed to be the client; different mechanism from KD-1 (default-export interop)"),
        "CR-17": ("valid", [], None, "downloaded SQL without integrity check (docs)"),
        "CR-18": ("trivial", [], None, "docs restatement of CR-5"),
        "CR-19": ("trivial", [], None, "docs consistency"),
        "CR-20": ("valid", [], None, "schema drops declared optional fields"),
        "CR-21": ("valid", [], None, "client path resolved from cwd, not the config file location"),
        "CR-22": ("trivial", [], None, "example manifest engines"),
    },
    349: {
        "CR-1": ("trivial", [], None, "JSDoc wording"),
        "CR-2": ("valid", [], None, "credentials file written with default umask"),
        "CR-3": ("valid", [], None, "non-idempotent flush; minor"),
        "CR-4": ("valid", [], None, "skill install overwrites user files without saying so"),
        "CR-5": ("valid", [], None, "early return may skip the real migrations directory"),
        "CR-6": ("trivial", [], None, "duplicate report entries"),
        "CR-7": ("trivial", [], None, "help text"),
        "CR-8": ("valid", [], None, "non-superuser with grants downgraded to no-operator-family install"),
    },
    496: {
        "CR-1": ("valid", [], None, "new CI job without least-privilege permissions"),
        "CR-2": ("trivial", [], None, "example env file"),
        "CR-3": ("trivial", [], None, "example manifest engines"),
        "CR-4": ("trivial", [], None, "example README"),
        "CR-5": ("trivial", [], None, "example response shape"),
        "CR-6": ("valid", [], None, "example returns stack traces; minor"),
        "CR-7": ("trivial", [], None, "version-pin drift note"),
        "CR-8": ("valid", [], None, "wasm-inline subpath has no require export; repo rule says keep CJS (the entry is documented ESM-only later, so impact is low)"),
        "CR-9": ("valid", [], None, "public constructor accepts arbitrary objects"),
        "CR-10": ("valid", [], None, "JSON payload types narrower than the schema allows"),
        "CR-11": ("valid", [], None, "conflicting auth inputs silently resolved"),
    },
    547: {
        "CR-1": ("trivial", [], None, "changeset wording"),
        "CR-2": ("trivial", [], None, "changeset wording"),
        "CR-3": ("valid", [], None, "v3 install still runs the v2 permission check"),
        "CR-4": ("valid", [], None, "flag silently ignored on the v3 path"),
        "CR-5": ("valid", [], None, "TypeError on non-object lock context from JS callers; minor"),
        "CR-6": ("valid", [], None, "structured .or() still accepts storage-only encrypted columns at the type level"),
        "CR-7": ("trivial", [], None, "markdown lint"),
        "CR-8": ("trivial", [], None, "markdown lint"),
        "CR-9": ("trivial", [], None, "markdown lint"),
        "CR-10": ("valid", [], None, "raw v3 filter bypasses the like/ilike remap; wrong operator, not plaintext"),
        "CR-11": ("valid", [], None, "order() not mapped to DB column name"),
        "CR-14": ("trivial", [], None, "option aliasing"),
    },
    666: {
        "CR-1": ("trivial", [], None, "add E2E coverage"),
        "CR-2": ("valid", [], None, "alignment command misclassifies dev/prod packages"),
        "CR-3": ("valid", [], None, "alignment commands not printed in one path"),
        "CR-4": ("valid", [], None, "skill guidance checks only one package for skew; not the direction-less comparison of KD-1"),
        "CR-5": ("valid", [], None, "success reported while skew remains"),
    },
    823: {
        "CR-1": ("valid", [], None, "chmod-based test is a no-op as root, so the partial-progress path is untested in CI"),
        "CR-2": ("trivial", [], None, "missing outro"),
        "CR-3": ("trivial", [], None, "duplicate warning"),
        "CR-4": ("match", ["KD-3"], None, "non-object throw escapes the sweep's catch: KD-3 mechanism"),
        "CR-6": ("match", ["KD-3"], None, "same mechanism in the CLI copy (nitpick)"),
    },
    996: {"CR-1": ("valid", [], None, "public operation type widened in a non-major release")},
    562: {
        "CR-1": ("trivial", [], None, "deprecation warning skipped when both fields set"),
        "CR-2": ("trivial", [], None, "error message names the wrong field"),
    },
    676: {
        "CR-1": ("valid", [], None, "ope-only columns not handled by the WASM resolver"),
        "CR-2": ("trivial", [], None, "test assertion strictness"),
        "CR-3": ("valid", [], None, "test helper swallows unexpected errors, so tests can pass on infrastructure failures"),
    },
    1090: {
        "CR-1": ("valid", [], None, "failed engines occupy cache slots"),
        "CR-2": ("valid", [], None, "pending engine leaks on cancellation"),
        "CR-3": ("valid", [], None, "getJwt contract change under a minor bump"),
        "CR-4": ("trivial", [], None, "changeset wording"),
    },
    568: {
        "CR-1": ("unsupported", [], None, "withdrawn by CodeRabbit itself on the PR"),
        "CR-2": ("valid", [], None, "all failures treated as not authenticated; minor"),
    },
    330: {
        "CR-1": ("unsupported", [], None, "generic plaintext-in-logs claim for a subcommand name"),
        "CR-2": ("valid", [], None, "unhandled rejection leaves spinner running; minor"),
        "CR-3": ("trivial", [], None, "style of exit handling in a CLI helper"),
    },
    503: {f"CR-{i}": ("trivial", [], None, "bugs.url metadata") for i in range(1, 7)},
    840: {"CR-1": ("trivial", [], None, "README wording")},
    371: {"CR-1": ("trivial", [], None, "stale wording in AGENTS.md")},
}


def main() -> int:
    corpus = {c["pr"]: c for c in json.loads((ROOT / "eval/corpus.json").read_text())["cases"]}
    out = ROOT / "eval/adjudication/coderabbit/original"
    out.mkdir(parents=True, exist_ok=True)
    reviewed = skipped = 0
    for pr, case in sorted(corpus.items()):
        if case["split"] != "holdout":
            continue
        cr = json.loads((ROOT / f"eval/coderabbit/{pr}.json").read_text())
        if not cr["coderabbit_present"] or not (cr["findings"] or cr["summary_comment_present"]):
            skipped += 1
            continue
        reviewed += 1
        labels = LABELS.get(pr, {})
        findings = []
        for f in cr["findings"]:
            if "duplicate" in (f.get("severity_label") or ""):
                continue
            label, matches, ev, note = labels.get(f["id"], ("trivial" if f["is_nitpick"] else None, [], None, "nitpick"))
            if label is None:
                raise SystemExit(f"unlabelled {pr} {f['id']}")
            findings.append({"id": f["id"], "title": f["claim"][:160], "nitpick": f["is_nitpick"], "label": label,
                             "matches": matches, "evidence_ok": ev,
                             "actionable": True if label in ("match", "valid") else None, "note": note})
        attention = any(x["label"] in ("match", "valid") and not x["nitpick"] for x in findings)
        (out / f"{case['id']}.json").write_text(json.dumps({
            "case": case["id"], "evaluator": "coderabbit/original", "run": 1, "overall_impact": None,
            "attention": attention, "findings": findings, "cost_usd": None, "wall_seconds": None}, indent=2) + "\n")
    print(f"reviewed {reviewed}, not reviewed {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
