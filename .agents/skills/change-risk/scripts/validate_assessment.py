#!/usr/bin/env python3
"""Validate a change-risk assessment: schema, references, and evidence rules.

    validate_assessment.py assessment.json [--repo PATH] [--schema PATH]
                           [--expected-base SHA] [--expected-head SHA] [--json]

Exit 0: valid (warnings may be printed). Exit 1: errors. Exit 2: unusable input.

Checks, in order:
  1. JSON Schema (the subset of Draft 2020-12 the schema uses; standard library only).
  2. Identifiers are unique and every cross-reference resolves.
  3. Evidence rules: a scenario called an observed defect cites verified evidence;
     a test result is claimed only with CI or command evidence, and never when
     CI results are marked unavailable; high/critical scenarios name missing
     verification or existing verification, and a mitigation.
  4. With --repo: every cited path exists at the cited revision and line numbers
     fall inside the file.
  5. Strict impact aggregation and readiness consistency (see risk-model.md).
     Overall impact aggregates material scenarios only; a speculative
     hypothesis is reported as a coverage question and does not set it.
  6. With --expected-base/--expected-head: the assessment names exactly the
     revisions the caller asked about.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "assessment.schema.json"
IMPACT_ORDER = {"unknown": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}


# ---------------------------------------------------------------------------
# minimal JSON Schema (subset used by assessment.schema.json)

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def schema_errors(instance, schema: dict, root: dict, path: str = "$") -> list[str]:
    errs: list[str] = []
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            return [f"{path}: unsupported $ref {ref}"]
        target = root
        for part in ref[2:].split("/"):
            target = target[part]
        return schema_errors(instance, target, root, path)
    if "const" in schema and instance != schema["const"]:
        errs.append(f"{path}: expected {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errs.append(f"{path}: {instance!r} not one of {schema['enum']}")
    t = schema.get("type")
    if t:
        py = _TYPES[t]
        ok = isinstance(instance, py) and not (t in ("integer", "number") and isinstance(instance, bool))
        if not ok:
            return errs + [f"{path}: expected {t}"]
    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            errs.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errs.append(f"{path}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errs.append(f"{path}: {instance!r} does not match {schema['pattern']}")
    if isinstance(instance, int) and not isinstance(instance, bool) and "minimum" in schema:
        if instance < schema["minimum"]:
            errs.append(f"{path}: below minimum {schema['minimum']}")
    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            errs.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errs.append(f"{path}: more than {schema['maxItems']} items")
        if "items" in schema:
            for i, item in enumerate(instance):
                errs += schema_errors(item, schema["items"], root, f"{path}[{i}]")
    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errs.append(f"{path}: missing required property {req!r}")
        props = schema.get("properties", {})
        for k, v in instance.items():
            if k in props:
                errs += schema_errors(v, props[k], root, f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                errs.append(f"{path}: unexpected property {k!r}")
    return errs


# ---------------------------------------------------------------------------
# semantic rules


def semantic(a: dict) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    def ids(coll: str) -> list[str]:
        return [x.get("id") for x in a.get(coll, [])]

    for coll in ("behaviour_changes", "affected_components", "failure_scenarios", "verification_gaps",
                 "recommended_controls", "coverage_limitations", "evidence"):
        seen = ids(coll)
        dupes = {i for i in seen if seen.count(i) > 1}
        if dupes:
            errors.append(f"{coll}: duplicate ids {sorted(dupes)}")
    evidence = {e["id"]: e for e in a.get("evidence", [])}

    def check_refs(where: str, refs: list[str], *collections: str) -> None:
        allowed = {i for coll in collections for i in ids(coll)}
        for r in refs:
            if r not in allowed:
                errors.append(f"{where}: reference {r} does not resolve to {', '.join(collections)}")

    for bc in a.get("behaviour_changes", []):
        check_refs(bc["id"], bc.get("evidence", []), "evidence")
        if bc.get("certainty") == "observed" and not bc.get("evidence"):
            errors.append(f"{bc['id']}: certainty 'observed' with no evidence")
    for ac in a.get("affected_components", []):
        check_refs(ac["id"], ac.get("evidence", []), "evidence")
        if ac.get("relationship") in ("confirmed", "changed") and not ac.get("evidence"):
            errors.append(f"{ac['id']}: relationship '{ac['relationship']}' with no evidence")
        if ac.get("relationship") == "confirmed" and ac.get("evidence") and all(
            evidence.get(e, {}).get("status") == "inferred" for e in ac["evidence"]
        ):
            errors.append(f"{ac['id']}: 'confirmed' dependency supported only by inferred evidence; use 'likely'")

    ci_unavailable = a.get("inputs", {}).get("ci_results", {}).get("status") == "unavailable"
    worst = -1
    for fs in a.get("failure_scenarios", []):
        sid = fs["id"]
        check_refs(sid, fs.get("evidence", []), "evidence")
        check_refs(sid, fs.get("affected_components", []), "affected_components")
        if fs.get("basis") != "speculative":
            worst = max(worst, IMPACT_ORDER.get(fs.get("impact"), -1))
        evs = [evidence[e] for e in fs.get("evidence", []) if e in evidence]
        if fs.get("basis") == "observed_defect" and not any(e.get("status") == "verified" for e in evs):
            errors.append(f"{sid}: basis 'observed_defect' needs at least one verified evidence item")
        if evs and all(e.get("status") == "inferred" for e in evs) and fs.get("basis") != "speculative":
            warnings.append(f"{sid}: every evidence item is inferred; consider basis 'speculative'")
        for i, v in enumerate(fs.get("existing_verification", [])):
            check_refs(f"{sid}.existing_verification[{i}]", v.get("evidence", []), "evidence")
            if v.get("status") in ("ran_passed", "ran_failed"):
                kinds = {evidence.get(e, {}).get("kind") for e in v.get("evidence", [])
                         if evidence.get(e, {}).get("status") == "verified"}
                if not kinds & {"ci_result", "command_output"}:
                    errors.append(f"{sid}.existing_verification[{i}]: '{v['status']}' needs verified ci_result or command_output evidence")
                if ci_unavailable and "command_output" not in kinds:
                    errors.append(f"{sid}.existing_verification[{i}]: '{v['status']}' while inputs.ci_results is unavailable")
        if fs.get("impact") in ("high", "critical"):
            if not fs.get("missing_verification") and not fs.get("existing_verification"):
                errors.append(f"{sid}: {fs['impact']} impact with neither existing nor missing verification")
            if len(fs.get("mitigation", "").strip()) < 10:
                errors.append(f"{sid}: {fs['impact']} impact needs a usable mitigation")
    for vg in a.get("verification_gaps", []):
        check_refs(vg["id"], vg.get("scenarios", []), "failure_scenarios")
        check_refs(vg["id"], vg.get("evidence", []), "evidence")
    for rc in a.get("recommended_controls", []):
        check_refs(rc["id"], rc.get("addresses", []), "failure_scenarios", "verification_gaps")

    for e in a.get("evidence", []):
        if e.get("kind") in ("code", "diff", "test", "documentation") and not e.get("path"):
            errors.append(f"{e['id']}: kind '{e['kind']}' needs a path")
        if e.get("kind") == "history_signal" and not e.get("signal"):
            errors.append(f"{e['id']}: history_signal needs a signal")
        if e.get("kind") == "command_output" and not e.get("command"):
            errors.append(f"{e['id']}: command_output needs the command")
        if "line_end" in e and e.get("line_end", 0) < e.get("line_start", 0):
            errors.append(f"{e['id']}: line_end before line_start")
        if "line_end" in e and "line_start" not in e:
            errors.append(f"{e['id']}: line_end without line_start")
        if e.get("kind") == "ci_result" and ci_unavailable:
            errors.append(f"{e['id']}: ci_result evidence while inputs.ci_results is unavailable")

    overall = IMPACT_ORDER.get(a.get("impact"), -1)
    scenarios = a.get("failure_scenarios", [])
    unknown_scenario = any(fs["impact"] == "unknown" and fs["basis"] != "speculative" for fs in scenarios)
    # Unknown retains uncertainty; known scenarios still record a lower bound.
    if unknown_scenario and a["impact"] != "unknown":
        errors.append("unknown scenario impact requires overall impact unknown")
    if a["impact"] != "unknown" and worst > overall:
        errors.append(f"overall impact '{a['impact']}' is below the worst scenario impact")
    readiness = a["release_readiness"]
    confidence = a["verification_confidence"]
    if a["impact"] == "unknown" and readiness != "insufficient_evidence":
        errors.append("impact unknown requires insufficient_evidence")
    if readiness == "insufficient_evidence" and not a.get("coverage_limitations"):
        errors.append("insufficient_evidence verdict with no coverage limitation recorded")
    verifications = [v for fs in scenarios for v in fs["existing_verification"]]
    if confidence == "high" and not (
        any(v["status"] == "ran_passed" for v in verifications) or
        (not scenarios and any(e["kind"] in ("ci_result", "command_output")
                               and e["status"] == "verified" for e in evidence.values()))
    ):
        errors.append("high verification confidence requires executed passing verification")
    if readiness == "ready_for_review":
        if confidence == "unknown":
            errors.append("ready_for_review with unknown verification confidence")
        if any(fs["basis"] == "observed_defect" for fs in scenarios):
            errors.append("ready_for_review with an observed defect")
        if any(v["status"] == "ran_failed" for v in verifications):
            errors.append("ready_for_review with failed verification")
        if overall >= 2:
            if confidence != "high":
                errors.append("ready_for_review with high impact requires high verification confidence")
            if not a.get("readiness_justification", "").strip():
                errors.append("ready_for_review with high impact requires readiness_justification")
            if a["verification_gaps"] or any(fs["missing_verification"] for fs in scenarios):
                errors.append("ready_for_review with high impact has unresolved verification gaps")
            for fs in scenarios:
                if fs["impact"] in ("high", "critical") and not any(
                    v["status"] == "ran_passed" for v in fs["existing_verification"]
                ):
                    errors.append(f"{fs['id']}: high-impact ready_for_review needs passing verification")
    return errors, warnings


def repo_checks(a: dict, repo: str) -> list[str]:
    errors = []
    revs = {"base": a.get("base_sha"), "head": a.get("head_sha")}
    for name, sha in revs.items():
        r = subprocess.run(["git", "-C", repo, "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True)
        if r.returncode != 0:
            return [f"{name}_sha {sha} is not a commit in {repo}"]
    cache: dict[tuple[str, str], int | None] = {}
    for e in a.get("evidence", []):
        if not e.get("path"):
            continue
        rev = revs[e.get("rev", "head")]
        key = (rev, e["path"])
        if key not in cache:
            r = subprocess.run(["git", "-C", repo, "show", f"{rev}:{e['path']}"], capture_output=True)
            if r.returncode != 0:
                cache[key] = None
            else:
                data = r.stdout
                if data.startswith(b"tree "):  # a directory
                    cache[key] = 0
                else:
                    cache[key] = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
        n = cache[key]
        if n is None:
            errors.append(f"{e['id']}: {e['path']} does not exist at {e.get('rev', 'head')}")
        elif e.get("line_start", 0) > n:
            errors.append(f"{e['id']}: line {e['line_start']} beyond end of {e['path']} ({n} lines)")
        elif e.get("line_end", 0) > n:
            errors.append(f"{e['id']}: line {e['line_end']} beyond end of {e['path']} ({n} lines)")
    return errors


def revision_errors(a: dict, expected_base: str | None, expected_head: str | None) -> list[str]:
    errors = []
    for name, want in (("base_sha", expected_base), ("head_sha", expected_head)):
        if want is not None and a.get(name) != want:
            errors.append(f"{name} {a.get(name)} is not the expected revision {want}")
    return errors


def validate(a: dict, schema: dict, repo: str | None = None,
             expected_base: str | None = None, expected_head: str | None = None) -> tuple[list[str], list[str]]:
    errors = schema_errors(a, schema, schema)
    if errors:  # semantic checks assume the shape is right
        return errors, []
    sem_errors, warnings = semantic(a)
    errors += sem_errors
    errors += revision_errors(a, expected_base, expected_head)
    if repo:
        errors += repo_checks(a, repo)
    return errors, warnings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("assessment")
    ap.add_argument("--repo")
    ap.add_argument("--schema", default=str(DEFAULT_SCHEMA))
    ap.add_argument("--expected-base", help="full SHA the assessment's base_sha must equal")
    ap.add_argument("--expected-head", help="full SHA the assessment's head_sha must equal")
    ap.add_argument("--json", action="store_true", help="print a JSON result")
    args = ap.parse_args(argv)
    try:
        a = json.loads(Path(args.assessment).read_text())
        schema = json.loads(Path(args.schema).read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"validate-assessment: cannot read input: {e}", file=sys.stderr)
        return 2
    errors, warnings = validate(a, schema, args.repo, args.expected_base, args.expected_head)
    if args.json:
        print(json.dumps({"valid": not errors, "errors": errors, "warnings": warnings}, indent=2))
    else:
        for e in errors:
            print(f"error: {e}")
        for w in warnings:
            print(f"warning: {w}")
        print("valid" if not errors else f"invalid: {len(errors)} error(s)")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
