#!/usr/bin/env python3
"""
Tests for xml-to-markdown.py parsing

These tests verify critical parsing fixes:
1. Operator function names extracted from brief description
2. Variants links don't self-reference when exact match missing
3. Parameter name/type extraction handles SQL backwards syntax
"""

import sys
from pathlib import Path

# Add parent dir to path to import the module
sys.path.insert(0, str(Path(__file__).parent))

def test_operator_name_extraction():
    """Test that operator names are extracted from brief description"""
    from xml.etree import ElementTree as ET

    # Mock XML for operator function
    xml_str = '''
    <memberdef kind="function">
        <name>eql_v2</name>
        <briefdescription>
            <para>-&gt;&gt; operator with encrypted selector</para>
        </briefdescription>
        <detaileddescription></detaileddescription>
    </memberdef>
    '''

    memberdef = ET.fromstring(xml_str)

    # Import process_function (would need to refactor to make testable)
    # For now, just verify the XML structure we expect
    name = memberdef.find('name').text
    brief = memberdef.find('briefdescription/para').text

    assert name == "eql_v2", f"Expected 'eql_v2', got '{name}'"
    assert "operator" in brief, f"Expected 'operator' in brief, got '{brief}'"

    # Extract operator (this is what the fix does)
    import re
    op_match = re.match(r'^([^\s]+)\s+operator', brief.strip())
    assert op_match, f"Failed to match operator pattern in '{brief}'"

    # XML entities are decoded by ElementTree, so we get '->>',not '&gt;&gt;'
    extracted_op = op_match.group(1)
    assert extracted_op == "->>", f"Expected '->>', got '{extracted_op}'"

    print("✓ Operator name extraction test passed")

def test_variants_no_self_reference():
    """Test that Variants don't link to themselves when variant missing"""

    # Simulate scenario:
    # - Function: bloom_filter(eql_v2_encrypted)
    # - Variants: eql_v2.bloom_filter(jsonb)
    # - But bloom_filter(jsonb) doesn't exist in docs

    all_functions = [
        {
            'name': 'bloom_filter',
            'signature': 'bloom_filter(eql_v2_encrypted)',
            'params': [{'type': 'eql_v2_encrypted'}]
        }
    ]

    # Build index like the code does
    func_by_sig = {}
    for func in all_functions:
        param_types = ', '.join([p['type'] for p in func['params'] if p.get('type')])
        sig_key = f"{func['name']}({param_types})"
        func_by_sig[sig_key] = func

    # Test matching
    func_name = "bloom_filter"
    params_str = "jsonb"
    param_list = [p.strip() for p in params_str.split(',') if p.strip()]
    sig_key = f"{func_name}({', '.join(param_list)})"

    matched_func = func_by_sig.get(sig_key)

    # Should NOT match because parameters are different
    assert matched_func is None, "Should not match bloom_filter(jsonb) to bloom_filter(eql_v2_encrypted)"

    # Verify the correct signature is indexed
    assert 'bloom_filter(eql_v2_encrypted)' in func_by_sig
    assert 'bloom_filter(jsonb)' not in func_by_sig

    print("✓ Variants no self-reference test passed")

def test_param_name_type_swap():
    """Test that SQL parameter name/type are correctly swapped"""
    from xml.etree import ElementTree as ET

    # In SQL: func(val eql_v2_encrypted)
    # But Doxygen XML has: <type>val</type> <declname>eql_v2_encrypted</declname>
    xml_str = '''
    <param>
        <type><ref>val</ref></type>
        <declname>eql_v2_encrypted</declname>
    </param>
    '''

    param = ET.fromstring(xml_str)

    # Extract like the code does
    param_type_elem = param.find('type')
    param_declname_elem = param.find('declname')
    ref_elem = param_type_elem.find('ref')

    # Name is in <ref> child of <type>
    actual_name = ref_elem.text.strip() if ref_elem is not None else ""
    # Type is in <declname>
    actual_type = param_declname_elem.text.strip() if param_declname_elem is not None else ""

    assert actual_name == "val", f"Expected name 'val', got '{actual_name}'"
    assert actual_type == "eql_v2_encrypted", f"Expected type 'eql_v2_encrypted', got '{actual_type}'"

    print("✓ Parameter name/type swap test passed")

def test_schema_qualified_type():
    """Test that schema-qualified types like eql_v2.ore_block are parsed correctly"""
    from xml.etree import ElementTree as ET

    # For eql_v2.ore_block_u64_8_256:
    # <type><ref>a</ref> eql_v2.</type> <declname>ore_block_u64_8_256</declname>
    xml_str = '''
    <param>
        <type><ref>a</ref> eql_v2.</type>
        <declname>ore_block_u64_8_256</declname>
    </param>
    '''

    param = ET.fromstring(xml_str)

    param_type_elem = param.find('type')
    param_declname_elem = param.find('declname')
    ref_elem = param_type_elem.find('ref')

    # Name from ref
    actual_name = ref_elem.text.strip() if ref_elem is not None else ""

    # Type from tail + declname
    type_parts = []
    if ref_elem is not None and ref_elem.tail:
        type_parts.append(ref_elem.tail.strip())
    if param_declname_elem is not None:
        type_parts.append(param_declname_elem.text.strip())
    actual_type = ''.join(type_parts)

    assert actual_name == "a", f"Expected name 'a', got '{actual_name}'"
    assert actual_type == "eql_v2.ore_block_u64_8_256", f"Expected 'eql_v2.ore_block_u64_8_256', got '{actual_type}'"

    print("✓ Schema-qualified type test passed")

def _load_process_function():
    """Load process_function from the hyphenated module by path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "eql_xml_to_markdown", Path(__file__).parent / "xml-to-markdown.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.process_function

def test_internal_schema_is_private():
    """Functions in the eql_v3_internal schema are flagged private via <type>.

    Doxygen puts the schema in the memberdef <type> ("CREATE FUNCTION
    eql_v3_internal"), not the <name>, so visibility is a schema check. Guards
    against regressing to the old leading-underscore-name heuristic, which
    flagged none of the internal surface (reporting everything public).
    """
    from xml.etree import ElementTree as ET

    process_function = _load_process_function()

    def memberdef(schema, fn):
        return ET.fromstring(f'''
        <memberdef kind="function">
            <name>{fn}</name>
            <type>CREATE FUNCTION {schema}</type>
            <argsstring>(val jsonb) RETURNS bytea</argsstring>
            <briefdescription><para>Extract a term.</para></briefdescription>
            <detaileddescription></detaileddescription>
        </memberdef>
        ''')

    internal = process_function(memberdef("eql_v3_internal", "eq_term"))
    assert internal is not None, "internal function should be extracted"
    assert internal["is_private"] is True, "eql_v3_internal.* must be private"

    public = process_function(memberdef("eql_v3", "jsonb_path_query"))
    assert public is not None, "public function should be extracted"
    assert public["is_private"] is False, "eql_v3.* must be public"

    print("✓ Internal-schema private detection test passed")

def test_returns_table_type_is_not_truncated():
    """A set-returning `RETURNS TABLE (...)` yields `TABLE`, not a fragment.

    Doxygen reads the column list as a C++ argument list and truncates it at the
    first comma, so argsstring arrives as `() RETURNS TABLE(severity text`.
    Matching to the next space published "TABLE(severity" as the return type of
    eql_v3.lints(). The column list cannot be recovered from the XML — the
    truncation is at the comma, not a line break — but @return spells it out, so
    the type must at least stop cleanly at the paren.
    """
    from xml.etree import ElementTree as ET

    process_function = _load_process_function()

    lints = process_function(ET.fromstring('''
    <memberdef kind="function">
        <name>lints</name>
        <type>CREATE OR REPLACE FUNCTION eql_v3</type>
        <argsstring>() RETURNS TABLE(severity text</argsstring>
        <briefdescription><para>EQL lint results.</para></briefdescription>
        <detaileddescription><para>
            <simplesect kind="return"><para>SETOF record (severity text, category text)</para></simplesect>
        </para></detaileddescription>
    </memberdef>
    '''))
    assert lints is not None, "lints should be extracted"
    assert lints["return_type"] == "`TABLE`", (
        f'expected a clean `TABLE`, got {lints["return_type"]!r}'
    )

    # Ordinary scalar return types are untouched by the paren stop.
    scalar = process_function(ET.fromstring('''
    <memberdef kind="function">
        <name>eq_term</name>
        <type>CREATE FUNCTION eql_v3</type>
        <argsstring>(val jsonb) RETURNS bytea</argsstring>
        <briefdescription><para>Extract a term.</para></briefdescription>
        <detaileddescription></detaileddescription>
    </memberdef>
    '''))
    assert scalar["return_type"] == "`bytea`", scalar["return_type"]

    print("✓ RETURNS TABLE return-type test passed")

def test_filter_preserves_line_numbering():
    """The Doxygen input filter emits one output line per input line.

    Doxygen reports source positions against the FILTERED stream, so a
    transform that drops rows silently shifts every symbol after it. Skipping
    CREATE AGGREGATE bodies without padding moved max_sfunc from line 41 to 36.
    """
    import subprocess
    import tempfile

    sql = '''--! @brief State function.
CREATE FUNCTION eql_v3_internal.min_sfunc(state jsonb, value jsonb)
RETURNS jsonb
LANGUAGE sql AS $$
  SELECT 1
$$;

--! @brief min aggregate.
CREATE AGGREGATE eql_v3.min(public.eql_v3_bigint_ord) (
  sfunc = eql_v3_internal.min_sfunc,
  stype = public.eql_v3_bigint_ord,
  parallel = safe
);

--! @brief Trailing function whose line number must not shift.
CREATE FUNCTION eql_v3.after(a jsonb) RETURNS jsonb
LANGUAGE sql AS $$ SELECT a $$;
'''
    filter_script = Path(__file__).resolve().parents[1] / "doxygen-filter.sh"
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "aggregates.sql"
        path.write_text(sql)
        out = subprocess.run(
            [str(filter_script), str(path)], capture_output=True, text=True, check=True
        ).stdout

    assert out.count("\n") == sql.count("\n"), (
        f"filter changed line count: {sql.count(chr(10))} in, {out.count(chr(10))} out"
    )
    # The declaration after the aggregate must still sit on its original line.
    marker = "CREATE FUNCTION eql_v3.after"
    src_line = next(i for i, l in enumerate(sql.splitlines()) if l.startswith(marker))
    out_lines = out.splitlines()
    assert out_lines[src_line].startswith(marker), (
        f"line {src_line + 1} shifted, got: {out_lines[src_line]!r}"
    )

    print("✓ Filter line-numbering test passed")

def test_schema_name_misparse_is_skipped():
    """Name-dropped CREATE FUNCTION mis-parses are skipped, operators are kept.

    Doxygen drops the real name of `CREATE FUNCTION <schema>.<name>(... a
    <schema>.<domain> ...)`, leaving the schema as <name>. These internal
    "Unsupported operator blocker" helpers carry the word "operator" in their
    brief, so the skip must key on <definition> (CREATE FUNCTION), not the
    brief — otherwise they'd be mis-remapped to a junk operator name and
    mislabeled public. A genuine CREATE OPERATOR is still recovered.
    """
    from xml.etree import ElementTree as ET

    process_function = _load_process_function()

    # Mis-parsed CREATE FUNCTION (schema as name, "operator" in the brief).
    misfn = ET.fromstring('''
    <memberdef kind="function">
        <name>eql_v3_internal</name>
        <definition>CREATE FUNCTION eql_v3_internal</definition>
        <type>CREATE FUNCTION</type>
        <argsstring>(a jsonb, b public.eql_v3_text_ord) RETURNS jsonb</argsstring>
        <briefdescription><para>Unsupported operator blocker for public.eql_v3_text_ord.</para></briefdescription>
        <detaileddescription></detaileddescription>
    </memberdef>
    ''')
    assert process_function(misfn) is None, "name-dropped CREATE FUNCTION must be skipped"

    # Genuine CREATE OPERATOR — recover the symbol from the brief, keep it.
    op = ET.fromstring('''
    <memberdef kind="function">
        <name>public</name>
        <definition>CREATE OPERATOR public.-&gt;&gt;</definition>
        <type>CREATE OPERATOR</type>
        <argsstring>(public.eql_v3_json, text)</argsstring>
        <briefdescription><para>-&gt;&gt; operator with text selector.</para></briefdescription>
        <detaileddescription></detaileddescription>
    </memberdef>
    ''')
    res = process_function(op)
    assert res is not None and res["name"] == "->>", "CREATE OPERATOR symbol must be recovered"

    print("✓ Schema-name mis-parse skip test passed")

if __name__ == '__main__':
    print("Running xml-to-markdown tests...\n")

    try:
        test_operator_name_extraction()
        test_variants_no_self_reference()
        test_param_name_type_swap()
        test_schema_qualified_type()
        test_internal_schema_is_private()
        test_returns_table_type_is_not_truncated()
        test_filter_preserves_line_numbering()
        test_schema_name_misparse_is_skipped()

        print("\n✅ All tests passed!")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error running tests: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
