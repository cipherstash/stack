#!/usr/bin/env python3
#MISE hide=true
"""
Doxygen XML -> structured JSON manifest for EQL's SQL API.

A machine-readable companion to xml-to-markdown.py. Same Doxygen XML, same
SQL-via-Doxygen quirk handling (parameter name/type swap, operator names in
brief text, RETURNS extraction) — this emits JSON instead of Markdown, for
downstream consumers: docs generation, agents, and drift checks against the
hand-written reference.

Reuses the extraction in xml-to-markdown.py so the manifest and the Markdown
reference can never diverge in how they read the XML.

Doxygen does not extract CREATE DOMAIN, so the manifest reads the encrypted
domain/variant matrix (the core of the EQL v3 surface) straight from the Rust
catalog via `eql-codegen dump-catalog` — authoritative type names + operators.

Usage: xml-to-json.py <xml_dir> [output_dir] [version] [catalog_json]
"""

import importlib.util
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# xml-to-markdown.py has a hyphen in its name, so it can't be `import`ed
# normally; load it by path and reuse process_function verbatim.
_spec = importlib.util.spec_from_file_location(
    "eql_xml_to_markdown", Path(__file__).parent / "xml-to-markdown.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
process_function = _mod.process_function


def _strip_ticks(value):
    return value.strip("`").strip() if value else ""


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_entry(func):
    """Shape one extracted function into a manifest entry."""
    return {
        "name": func["name"],
        "signature": func["signature"],
        "visibility": "private" if func["is_private"] else "public",
        "brief": func["brief"],
        "description": func["detailed"],
        "params": func["params"],  # [{name, type, description}]
        "returns": {
            "type": _strip_ticks(func["return_type"]),
            "description": func["return_desc"],
        },
        "throws": func["exceptions"],
        "notes": func["notes"],
        "warnings": func["warnings"],
        "seeAlso": func["see_also"],
        "source": {"file": func["source"], "line": _int_or_none(func["line"])},
    }


# ── Encrypted domains (from the Rust catalog) ────────────────────────────────
# The domain/variant matrix is the core of the EQL v3 surface. Rather than parse
# the generated SQL (one step removed, format-fragile), read it straight from the
# source of truth: `eql-codegen dump-catalog` serializes eql_domains::CATALOG —
# authoritative type tokens plus the exact SQL operators each domain supports.
def _capabilities_from_ops(ops):
    caps = []
    if any(o in ops for o in ("=", "<>")):
        caps.append("equality")
    if any(o in ops for o in ("<", "<=", ">", ">=")):
        caps.append("order")
    # Text fuzzy match is `@@`. It was spelled `@>` / `<@` until EQL 3.0.1
    # renamed it; testing the old operators here meant NO domain could be
    # assigned `match` any more. `text_match` (whose only operator is `@@`)
    # matched no branch at all and fell through to the `storage` default,
    # describing the fuzzy-match domain as storage-only, and `text_search`
    # silently lost `match` from its capability list.
    if "@@" in ops:
        caps.append("match")
    # Containment on encrypted JSON keeps `@>` / `<@`; it is a distinct
    # capability from text fuzzy match, not a spelling of it.
    if any(o in ops for o in ("@>", "<@")):
        caps.append("containment")
    return caps or ["storage"]


def _term_functions(terms):
    """Qualified extractor functions for a domain's terms (e.g. eql_v3.ord_term)."""
    return [f"eql_v3.{t['extractor']}" for t in terms]


def load_domains(catalog_path: Path) -> list:
    """Map `eql-codegen dump-catalog` JSON into manifest domain entries."""
    if not catalog_path.exists():
        print(f"Warning: catalog dump not found: {catalog_path}; skipping domains", file=sys.stderr)
        return []

    catalog = json.loads(catalog_path.read_text())
    domains = []

    # Scalar families: capability + operators + extractor functions.
    for type_entry in catalog.get("types", []):
        token = type_entry["token"]
        for dom in type_entry["domains"]:
            suffix = dom.get("suffix", "")
            ops = dom.get("supported_ops", [])
            domains.append({
                # v3 user domains live in the `public` schema (public-domain
                # migration on eql_v3); the dump's `typname` is the installed
                # unqualified name, carrying the eql_v3_ version prefix
                #.
                "name": f"public.{dom['typname']}",
                "type": token,
                "variant": suffix.lstrip("_"),
                "base": "jsonb",
                "capabilities": _capabilities_from_ops(ops),
                "supportedOperators": ops,
                "termFunctions": _term_functions(dom.get("terms", [])),
            })

    # The json family: hand-written SQL, catalog inventory only. The column-type
    # domains (`eql_v3_json`, `eql_v3_json_search`, `eql_v3_json_entry`) live in
    # `public`; the containment needle (`query_json`) is a query operand, never a
    # column type, and lives in `eql_v3`. Extractor functions are eql_v3.
    #
    # The family is mixed. Its bare `public.eql_v3_json` is a storage-only scalar
    # domain — it stores and decrypts, and carries no query surface — so it must
    # not inherit the SteVec `json` capability that the searchable document,
    # entry, and needle domains carry.
    for entry in catalog.get("stevec", []):
        schema = "eql_v3" if entry["full_name"].startswith("query_") else "public"
        is_scalar = entry.get("scalar", False)
        domain = {
            "name": f"{schema}.{entry['typname']}",
            "type": "jsonb",
            "variant": "",
            "base": "jsonb",
            "capabilities": ["storage"] if is_scalar else ["json"],
            "supportedOperators": [],
            "termFunctions": _term_functions(entry.get("terms", [])),
        }
        if not is_scalar:
            domain["shape"] = "stevec"
        domains.append(domain)

    domains.sort(key=lambda d: (d["type"], d["name"]))
    return domains


def build_manifest(xml_dir: Path, version: str, catalog_path: Path = Path("docs/api/json/eql-catalog.json")) -> dict:
    functions = []
    for xml_file in sorted(xml_dir.glob("*.xml")):
        if xml_file.name in ("index.xml", "Doxyfile.xml"):
            continue
        try:
            root = ET.parse(xml_file).getroot()
        except ET.ParseError as exc:
            print(f"Warning: failed to parse {xml_file.name}: {exc}", file=sys.stderr)
            continue
        for memberdef in root.findall('.//memberdef[@kind="function"]'):
            func = process_function(memberdef)
            if func:
                functions.append(func)

    functions.sort(key=lambda f: (f["is_private"], f["name"], f["signature"]))
    domains = load_domains(catalog_path)

    return {
        "$schema": "https://schemas.cipherstash.com/eql/manifest/v1.json",
        "name": "eql",
        "version": version,
        "generatedFrom": "doxygen-xml + catalog",
        "counts": {
            "functions": len(functions),
            "public": sum(1 for f in functions if not f["is_private"]),
            "private": sum(1 for f in functions if f["is_private"]),
            "domains": len(domains),
        },
        "functions": [_to_entry(f) for f in functions],
        "domains": domains,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: xml-to-json.py <xml_dir> [output_dir] [version] [catalog_json]")
        sys.exit(1)

    xml_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("docs/api/json")
    version = sys.argv[3] if len(sys.argv) > 3 else "DEV"
    catalog_path = (
        Path(sys.argv[4]) if len(sys.argv) > 4 else Path("docs/api/json/eql-catalog.json")
    )

    if not xml_dir.exists():
        print(f"Error: XML directory not found: {xml_dir}")
        sys.exit(1)

    manifest = build_manifest(xml_dir, version, catalog_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "eql-manifest.json"
    output_file.write_text(json.dumps(manifest, indent=2) + "\n")

    counts = manifest["counts"]
    print(f"✓ Generated JSON manifest: {output_file}")
    print(
        f"  Functions: {counts['functions']} "
        f"({counts['public']} public, {counts['private']} private)"
    )
    print(f"  Domains: {counts['domains']}")


if __name__ == "__main__":
    main()
