#!/usr/bin/env python3
#MISE hide=true
"""
Simple Doxygen XML to Markdown converter for SQL function documentation.

Extracts function documentation from Doxygen XML and generates clean Markdown files.
This is a lightweight alternative to doxybook2/moxygen focused on SQL functions.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
import sys
import re

def clean_text(text):
    """Remove extra whitespace and normalize text"""
    if not text:
        return ""
    return re.sub(r'\s+', ' ', text.strip())

def generate_anchor(signature):
    """Generate GitHub-compatible anchor ID from function signature"""
    # GitHub converts headings to anchors by:
    # 1. Lowercasing
    # 2. Removing backticks and other special chars
    # 3. Replacing spaces and underscores with hyphens
    # 4. Collapsing multiple hyphens
    anchor = signature.lower()
    # Remove parentheses and commas, replace spaces/underscores with hyphens
    anchor = anchor.replace('(', '').replace(')', '').replace(',', '')
    anchor = anchor.replace('_', '-').replace(' ', '-')
    # Clean up any special characters that might cause issues
    anchor = re.sub(r'[^a-z0-9-]', '', anchor)
    # Collapse multiple hyphens
    anchor = re.sub(r'-+', '-', anchor)
    # Remove leading/trailing hyphens
    anchor = anchor.strip('-')
    return anchor

def extract_code_text(element):
    """Verbatim text of a <programlisting>, preserving significant whitespace.

    Doxygen encodes each space inside a code block as an empty <sp/> element
    and each source line as a <codeline>, so the text has to be reassembled
    rather than read off. No clean_text here — that is what the caller applies
    once, folding the line breaks into a single readable line.
    """
    parts = []
    if element.text:
        parts.append(element.text)
    for child in element:
        parts.append(' ' if child.tag == 'sp' else extract_code_text(child))
        if child.tail:
            parts.append(child.tail)
    return ''.join(parts)


def extract_para_text(element):
    """Extract text from para elements, including nested content"""
    if element is None:
        return ""

    parts = []
    if element.text:
        parts.append(element.text)

    for child in element:
        if child.tag == 'ref':
            # Keep references as plain text (will be wrapped in backticks by caller if needed)
            if child.text:
                parts.append(child.text)
        elif child.tag == 'computeroutput':
            if child.text:
                parts.append(child.text)
        elif child.tag == 'programlisting':
            # An @code block. Walk it verbatim rather than recursing: the
            # generic path calls clean_text on every nested fragment, which
            # strips the boundary spaces between <highlight> runs and welds the
            # code together ("SELECTeql_v3.grouped_value(...)").
            parts.append(extract_code_text(child))
        else:
            parts.append(extract_para_text(child))

        if child.tail:
            parts.append(child.tail)

    result = ''.join(parts)
    # Clean up cases where we have back-to-back backticks with no content between
    # This happens when ref elements are adjacent (e.g., eql_v2.blake3 -> `eql_v2`.`blake3`)
    result = re.sub(r'`(\s*)`', r'\1', result)
    return clean_text(result)

def extract_parameter_list(desc_element):
    """Extract structured parameter list from detaileddescription"""
    if desc_element is None:
        return []

    params = []
    for paramlist in desc_element.findall('.//parameterlist[@kind="param"]'):
        for item in paramlist.findall('parameteritem'):
            name_elem = item.find('.//parametername')
            desc_elem = item.find('.//parameterdescription/para')

            if name_elem is not None and name_elem.text:
                param_desc = extract_para_text(desc_elem) if desc_elem is not None else ""

                # Parse "type description" format
                # Doxygen puts "@param name type description" → description = "type description"
                # Need to split on first word (type) and rest (description)
                param_type = ""
                param_text = ""

                if param_desc:
                    parts = param_desc.split(None, 1)  # Split on first whitespace
                    if len(parts) == 2:
                        param_type = parts[0]
                        param_text = parts[1]
                    elif len(parts) == 1:
                        # Only type, no description
                        param_type = parts[0]
                        param_text = ""
                    else:
                        param_text = param_desc

                params.append({
                    'name': name_elem.text,
                    'type': param_type,
                    'description': param_text
                })

    return params

def extract_simplesects(desc_element):
    """Extract simplesect elements (return, note, warning, see, etc.)"""
    if desc_element is None:
        return {}

    sections = {}
    for simplesect in desc_element.findall('.//simplesect'):
        kind = simplesect.get('kind')
        if kind:
            para = simplesect.find('para')
            if para is not None:
                sections[kind] = extract_para_text(para)

    return sections

def extract_exceptions(desc_element):
    """Extract exception/throws documentation from parameterlist[@kind='exception']"""
    if desc_element is None:
        return []

    exceptions = []
    for paramlist in desc_element.findall('.//parameterlist[@kind="exception"]'):
        for item in paramlist.findall('parameteritem'):
            desc_elem = item.find('.//parameterdescription/para')
            if desc_elem is not None:
                exception_text = extract_para_text(desc_elem)
                if exception_text:
                    exceptions.append(exception_text)

    return exceptions

def extract_description(desc_element):
    """Extract description from briefdescription or detaileddescription, excluding parameterlist/simplesect"""
    if desc_element is None:
        return ""

    lines = []

    # Find all para elements that are NOT inside parameterlist or simplesect
    for para in desc_element.findall('para'):
        # Skip if this para is inside a parameterlist or simplesect
        parent = para
        while parent is not None:
            if parent.tag in ['parameterlist', 'simplesect']:
                break
            parent = list(desc_element.iter()).__contains__(parent)  # Check if still in tree
            parent = None  # Simple approach: only check direct parent
            break

        # Check if para has parameterlist or simplesect children
        if para.find('parameterlist') is not None or para.find('simplesect') is not None:
            # Extract only the text before these elements
            text_parts = []
            if para.text:
                text_parts.append(para.text)
            for child in para:
                if child.tag in ['parameterlist', 'simplesect']:
                    break
                if child.tag == 'ref' and child.text:
                    text_parts.append(f"`{child.text}`")
                if child.tail:
                    text_parts.append(child.tail)
            text = clean_text(''.join(text_parts))
        else:
            text = extract_para_text(para)

        if text:
            lines.append(text)

    return '\n\n'.join(lines)

def extract_aggregate_params(memberdef, param_docs):
    """Parameters of a CREATE AGGREGATE, read from the declaration.

    Doxygen's C++ parse of an aggregate's argument list is unreliable — a
    schema-qualified type splits into a bogus name/type pair, and a bare one is
    dropped — but <argsstring> keeps the list verbatim ("(public.eql_v3_json)").
    Aggregate argument lists are positional and unnamed in SQL, so take the
    types from there and the names/descriptions from the @param tags in order.
    """
    argsstring = memberdef.find('argsstring')
    text = (argsstring.text or '').strip() if argsstring is not None else ''
    if text.startswith('(') and text.endswith(')'):
        text = text[1:-1]

    params = []
    for i, arg_type in enumerate([a.strip() for a in text.split(',') if a.strip()]):
        doc = param_docs[i] if i < len(param_docs) else None
        params.append({
            'name': doc['name'] if doc else '',
            'type': arg_type,
            'description': doc['description'] if doc else '',
        })
    return params


def process_function(memberdef):
    """Extract function documentation from memberdef element"""
    name = memberdef.find('name')
    if name is None or not name.text:
        return None

    func_name = name.text

    # Skip SQL intrinsics that Doxygen incorrectly identifies as functions
    # These are actually part of CREATE CAST, CREATE TYPE ... AS, CREATE OPERATOR statements
    sql_intrinsics = ['AS', 'CAST', 'CHECK', 'EXISTS', 'OPERATOR', 'TYPE', 'INDEX', 'CONSTRAINT']
    if func_name.upper() in sql_intrinsics:
        return None

    # Doxygen puts a SCHEMA where the function name should be in two cases,
    # told apart by the <definition> (CREATE OPERATOR vs CREATE FUNCTION):
    #   1. CREATE OPERATOR — Doxygen names it by schema and puts the operator
    #      symbol in the brief ("->> operator with ..."); recover it.
    #   2. CREATE FUNCTION <schema>.<name>(... <schema>.<domain> ...) where a
    #      schema-qualified operand type derails the C++ parser: it drops the
    #      real name, leaving the schema as <name>. Unrecoverable, and these are
    #      the internal "Unsupported operator blocker" helpers — skip them.
    #      NB their brief contains the word "operator" ("Unsupported operator
    #      blocker for ..."), so the skip must key on <definition>, NOT the
    #      brief, or they'd be mis-remapped to a junk operator name. Left in,
    #      ~hundreds surface as bogus `eql_v3_internal` functions mislabeled
    #      public.
    brief_elem = memberdef.find('briefdescription')
    if func_name in ['eql_v2', 'eql_v3', 'eql_v3_internal', 'public']:
        definition = extract_para_text(memberdef.find('definition'))
        if definition.upper().startswith('CREATE FUNCTION'):
            return None  # name-dropped CREATE FUNCTION mis-parse
        brief_para = brief_elem.find('para') if brief_elem is not None else None
        op_match = (
            re.match(r'^([^\s]+)\s+operator', brief_para.text.strip())
            if brief_para is not None and brief_para.text
            else None
        )
        if op_match:
            func_name = op_match.group(1)  # CREATE OPERATOR: use the operator symbol
        else:
            return None  # unrecoverable schema-named mis-parse

    # Check if this is a private/internal function.
    # Internal functions live in the `eql_v3_internal` schema. Doxygen puts the
    # schema in the memberdef <type> (e.g. "CREATE FUNCTION eql_v3_internal"),
    # not the <name>, so a schema check is required — the older bare
    # leading-underscore convention alone flags none of them (which left the
    # whole surface reported as public). Keep the underscore check too.
    type_elem = memberdef.find('type')
    type_text = extract_para_text(type_elem) if type_elem is not None else ''
    is_private = func_name.startswith('_') or 'eql_v3_internal' in type_text

    # CREATE AGGREGATE has no C++ analogue. Once the Doxygen input filter has
    # stripped the definition body the name and argument list survive, but the
    # C++ parse still cannot tell a SQL argument TYPE from a parameter NAME
    # (`(public.eql_v3_bigint_ord)` arrives as a parameter *named* `public.`),
    # and it leaves "CREATE AGGREGATE <schema>" sitting in <type> where a return
    # type belongs. Both are unambiguous in the source, so for aggregates read
    # the argument types off the declaration and the return type off @return
    # rather than trusting the C++ parse.
    is_aggregate = type_text.upper().startswith('CREATE AGGREGATE')

    # Extract descriptions
    brief = extract_description(memberdef.find('briefdescription'))
    detailed_elem = memberdef.find('detaileddescription')
    detailed = extract_description(detailed_elem)

    # Skip if no documentation
    if not brief and not detailed:
        return None

    # Extract parameter descriptions from @param tags in detaileddescription
    param_docs = extract_parameter_list(detailed_elem)

    # Extract params from function signature (for actual types)
    # Merge with documentation descriptions
    # NOTE: Doxygen parses SQL parameters backwards!
    # SQL syntax: (name type) but C++ syntax: (type name)
    # So in the XML: <type> = SQL param name, <declname> = SQL param type
    params = []
    for param in memberdef.findall('.//param'):
        param_type_elem = param.find('type')  # Actually contains the param NAME in SQL (in <ref> child)
        param_declname_elem = param.find('declname')  # Actually contains part of the param TYPE in SQL

        if param_type_elem is not None:
            # Extract just the parameter name from <ref> child
            ref_elem = param_type_elem.find('ref')
            if ref_elem is not None and ref_elem.text:
                actual_name = ref_elem.text.strip()
            else:
                # Fallback to full text if no ref
                actual_name = extract_para_text(param_type_elem).strip()

            # Build the full type by combining tail text from <type> and <declname>
            # For schema-qualified types like eql_v2.ore_block_u64_8_256:
            #   <type><ref>a</ref> eql_v2.</type> <declname>ore_block_u64_8_256</declname>
            type_parts = []
            if param_type_elem is not None and ref_elem is not None and ref_elem.tail:
                type_parts.append(ref_elem.tail.strip())
            if param_declname_elem is not None:
                declname_text = extract_para_text(param_declname_elem).strip()
                if declname_text:
                    type_parts.append(declname_text)
            actual_type = ''.join(type_parts)

            if actual_name:  # Only add if we got a name
                # Look for matching description in param_docs
                # First try matching by parameter name
                param_doc = next((p for p in param_docs if p['name'] == actual_name), None)

                # Fallback: match by type (common doc error: @param type description instead of @param name description)
                if not param_doc and actual_type:
                    param_doc = next((p for p in param_docs if p['name'] == actual_type), None)

                # Use description from docs, but name and type from signature
                param_info = {
                    'name': actual_name,
                    'type': actual_type,
                    'description': param_doc['description'] if param_doc else ''
                }
                params.append(param_info)

    if is_aggregate:
        params = extract_aggregate_params(memberdef, param_docs)

    # Extract simplesects (return, note, warning, see, etc.)
    simplesects = extract_simplesects(detailed_elem)

    # Extract exceptions
    exceptions = extract_exceptions(detailed_elem)

    # Extract return type
    # For SQL functions, the return type might be in the argsstring element after "RETURNS"
    argsstring = memberdef.find('argsstring')
    return_type_text = ''

    if argsstring is not None and argsstring.text:
        # Look for RETURNS keyword in argsstring.
        #
        # Stop at "(" as well as whitespace. A set-returning `RETURNS TABLE (col
        # type, ...)` reaches Doxygen as a C++ argument list, which it truncates
        # at the first comma — `() RETURNS TABLE(severity text` — so matching to
        # the next space published the fragment "TABLE(severity" as the return
        # type. The column list is unrecoverable from the XML (joining the
        # declaration onto one line does not help; the truncation is at the
        # comma, not the line break), but it is spelled out in full by the
        # @return tag that lands in `return_desc`.
        returns_match = re.search(r'RETURNS\s+([^\s(]+)', argsstring.text)
        if returns_match:
            return_type_text = returns_match.group(1)
            # Debug: Check if already has backticks from XML
            if return_type_text.startswith('`'):
                # Already formatted with backticks, just store it
                pass
            # Debug print
            #print(f"DEBUG: Extracted from argsstring: {return_type_text}")

    # An aggregate declares no RETURNS clause, and its <type> holds
    # "CREATE AGGREGATE <schema>" rather than a type. @return carries it.
    if is_aggregate and not return_type_text:
        return_desc = simplesects.get('return', '').strip()
        return_type_text = return_desc.split()[0] if return_desc else ''

    # Fallback to type element if not found in argsstring
    if not return_type_text:
        return_type = memberdef.find('type')
        return_type_text = extract_para_text(return_type) if return_type is not None else ''
        # Clean up return type - remove CREATE FUNCTION prefix if present
        # Remove common SQL DDL prefixes that shouldn't be in return type
        # Handle cases with backticks between words (e.g., "CREATE `FUNCTION` `eql_v2`")
        # First, remove the CREATE FUNCTION part even with backticks
        return_type_text = re.sub(r'^CREATE\s+(`?FUNCTION`?\s*)+', '', return_type_text)
        return_type_text = re.sub(r'^CREATE\s+OR\s+REPLACE\s+(`?FUNCTION`?\s*)+', '', return_type_text)
        # Also handle case where CREATE and FUNCTION are in separate backticks
        return_type_text = re.sub(r'^`?CREATE`?\s+`?FUNCTION`?\s*', '', return_type_text)
        # Clean up any leftover backticks that shouldn't be there
        # Handle case where we have multiple backticks like `eql_v2`.`blake3` -> `eql_v2.blake3`
        return_type_text = re.sub(r'`\s*\.\s*`', '.', return_type_text)
        # Handle back-to-back backticks with whitespace: `eql_v2` `blake3` -> `eql_v2.blake3`
        return_type_text = re.sub(r'`\s+`', '.', return_type_text)
    return_type_text = re.sub(r'`\s+`', '.', return_type_text)
    # Clean up and ensure proper backtick formatting
    return_type_text = return_type_text.strip()

    # If already has backticks, clean up doubles
    if '`' in return_type_text:
        # Clean up double backticks: ``something`` -> `something`
        return_type_text = re.sub(r'``+', '`', return_type_text)
        # Remove backticks for now to re-add them properly
        return_type_text = return_type_text.replace('`', '')

    # Wrap in single backticks if it looks like a type name
    if return_type_text and re.match(r'^[a-zA-Z_][a-zA-Z0-9_.]*(\[\])?$', return_type_text):
        return_type_text = f'`{return_type_text}`'

    # Extract location
    location = memberdef.find('location')
    source_file = location.get('file') if location is not None else ''
    line_num = location.get('line') if location is not None else ''

    # Build function signature
    param_types = []
    for param in params:
        if param.get('type'):
            param_types.append(param['type'])

    signature = f"{func_name}({', '.join(param_types)})" if param_types else f"{func_name}()"

    return {
        'name': func_name,
        'signature': signature,
        'is_private': is_private,
        'brief': brief,
        'detailed': detailed,
        'params': params,
        'return_type': return_type_text,
        'return_desc': simplesects.get('return', ''),
        'exceptions': exceptions,
        'notes': simplesects.get('note', ''),
        'warnings': simplesects.get('warning', ''),
        'see_also': simplesects.get('see', ''),
        'source': source_file,
        'line': line_num
    }

def build_type_lookup_map(all_functions):
    """Build a map of type names to function anchors for linking

    Note: Only maps function names, not SQL types like eql_v2.bloom_filter,
    because types are not extracted as separate documented entities by Doxygen.
    """
    type_map = {}
    for func in all_functions:
        name = func['name']
        # Only map exact function name matches (not schema-qualified type names)
        # This prevents linking types like "eql_v2.bloom_filter" to functions
        type_map[name] = generate_anchor(func['signature'])
    return type_map

def linkify_type(type_text, type_map):
    """Convert type reference to markdown link if it matches a documented function

    Only links to actual documented functions, not SQL types.
    SQL types like eql_v2.bloom_filter are not extracted by Doxygen as
    separate entities, so they should remain as plain text.
    """
    if not type_text:
        return ""

    # Remove existing backticks
    clean_type = type_text.strip('`').strip()

    # Built-in PostgreSQL types that should not be linked
    builtin_types = {
        'boolean', 'text', 'jsonb', 'integer', 'bytea', 'void',
        'smallint', 'bigint', 'real', 'double precision',
        'BOOLEAN', 'TEXT', 'JSONB', 'INTEGER', 'BYTEA', 'SETOF', 'TABLE',
        'uuid', 'timestamp', 'date', 'time'
    }

    # Handle array types (remove [] suffix)
    is_array = clean_type.endswith('[]')
    base_type = clean_type.rstrip('[]')

    # Handle composite types like TABLE(...)
    if base_type.startswith('TABLE') or base_type.startswith('SETOF'):
        return f"`{type_text.strip('`')}`"

    # Check if it's a built-in type
    if base_type in builtin_types:
        return f"`{type_text.strip('`')}`"

    # Don't link schema-qualified type names (e.g., eql_v2.bloom_filter)
    # These are SQL types, not documented functions
    if '.' in base_type:
        return f"`{type_text.strip('`')}`"

    # Try to find a matching function (without schema prefix)
    if base_type in type_map:
        anchor = type_map[base_type]
        if is_array:
            return f"[`{base_type}`](#{anchor})[]"
        else:
            return f"[`{base_type}`](#{anchor})"

    # No match found, return with backticks
    return f"`{type_text.strip('`')}`"

def convert_variants_to_links(variants_text, all_functions):
    """Convert function references in 'Variants' to markdown links

    Only creates links for functions that actually exist in the documentation.
    References to missing overloaded functions are kept as plain text.
    Strips schema prefix to match function title format.
    """
    if not variants_text:
        return ""

    # Build a comprehensive map of functions by name and signature
    func_map = {}  # name -> [functions]
    func_by_sig = {}  # "name(types)" -> function

    for func in all_functions:
        name = func['name']
        if name not in func_map:
            func_map[name] = []
        func_map[name].append(func)

        # Also index by simplified signature for matching
        param_types = ', '.join([p['type'] for p in func['params'] if p.get('type')])
        sig_key = f"{name}({param_types})"
        func_by_sig[sig_key] = func

    lines = []
    # Split by newlines and process each reference
    for line in variants_text.strip().split('\n'):
        line = line.strip()
        if not line:
            continue

        # Try to parse function reference like "eql_v2.blake3(jsonb)" or "`eql_v2`.\"->\""
        import re
        # Match patterns: schema.function(params) or function(params)
        match = re.match(r'(?:`?([^`\s]+)`?\.)?`?"?([^`"\s(]+)"?`?\(([^)]*)\)?', line)
        if match:
            func_name = match.group(2)
            params_str = match.group(3) if match.group(3) else ""

            # Look for exact match by name and parameter types
            param_list = [p.strip() for p in params_str.split(',') if p.strip()]
            sig_key = f"{func_name}({', '.join(param_list)})"

            matched_func = func_by_sig.get(sig_key)

            # If no exact match and no params specified, try matching by name only
            if not matched_func and not param_list:
                candidates = func_map.get(func_name, [])
                if len(candidates) == 1:
                    # Only auto-match if there's exactly one function with this name
                    # and no specific parameters were requested
                    matched_func = candidates[0]

            if matched_func:
                anchor = generate_anchor(matched_func['signature'])
                # Use signature without schema prefix to match title format
                lines.append(f"- [`{matched_func['signature']}`](#{anchor})")
            else:
                # Keep original text if function not found (likely missing from Doxygen output)
                # But strip schema prefix to match title format
                display_sig = f"{func_name}({params_str})" if params_str else f"{func_name}()"
                lines.append(f"- `{display_sig}`")
        else:
            # Keep original if pattern doesn't match
            lines.append(f"- {line}")

    return '\n'.join(lines)

def generate_markdown(func, all_functions=None, type_map=None):
    """Generate Markdown for a function"""
    lines = []

    # Function name as heading (h3, with signature)
    lines.append(f"### `{func['signature']}`")
    lines.append("")

    # Brief description
    if func['brief']:
        lines.append(func['brief'])
        lines.append("")

    # Detailed description
    if func['detailed'] and func['detailed'] != func['brief']:
        lines.append(func['detailed'])
        lines.append("")

    # Parameters
    if func['params']:
        lines.append("#### Parameters")
        lines.append("")
        lines.append("| Name | Type | Description |")
        lines.append("|------|------|-------------|")
        for param in func['params']:
            name = f"`{param['name']}`"
            # Link parameter types if type_map is available
            if param.get('type'):
                if type_map:
                    param_type = linkify_type(param['type'], type_map)
                else:
                    param_type = f"`{param['type']}`"
            else:
                param_type = ""
            description = param.get('description', '')
            lines.append(f"| {name} | {param_type} | {description} |")
        lines.append("")

    # Return value
    if func['return_desc']:
        lines.append("#### Returns")
        lines.append("")
        if func['return_type']:
            # Link return type if type_map is available
            if type_map:
                linked_type = linkify_type(func['return_type'], type_map)
                lines.append(f"**Type:** {linked_type}")
            else:
                # Don't add backticks if return_type already has them
                if func['return_type'].startswith('`') and func['return_type'].endswith('`'):
                    lines.append(f"**Type:** {func['return_type']}")
                else:
                    lines.append(f"**Type:** `{func['return_type']}`")
            lines.append("")
        lines.append(func['return_desc'])
        lines.append("")

    # Notes
    if func.get('notes'):
        lines.append("#### Note")
        lines.append("")
        lines.append(func['notes'])
        lines.append("")

    # Exceptions
    if func.get('exceptions'):
        lines.append("#### Exceptions")
        lines.append("")
        for exc in func['exceptions']:
            lines.append(f"- {exc}")
        lines.append("")

    # Warnings
    if func.get('warnings'):
        lines.append("#### ⚠️ Warning")
        lines.append("")
        lines.append(func['warnings'])
        lines.append("")

    # Variants - convert references to links
    if func.get('see_also'):
        lines.append("#### Variants")
        lines.append("")
        if all_functions:
            lines.append(convert_variants_to_links(func['see_also'], all_functions))
        else:
            lines.append(func['see_also'])
        lines.append("")

    # Source reference - removed as relative links don't work

    lines.append("---")
    lines.append("")

    return '\n'.join(lines)

def main():
    if len(sys.argv) < 2:
        print("Usage: xml-to-markdown.py <xml_dir> [output_dir] [version]")
        sys.exit(1)

    xml_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('docs/api/markdown')
    version = sys.argv[3] if len(sys.argv) > 3 else 'DEV'

    if not xml_dir.exists():
        print(f"Error: XML directory not found: {xml_dir}")
        sys.exit(1)

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Process all XML files
    functions = []
    xml_files = list(xml_dir.glob('*.xml'))

    print(f"Processing {len(xml_files)} XML files...")

    for xml_file in xml_files:
        if xml_file.name in ['index.xml', 'Doxyfile.xml']:
            continue

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Find all function members
            for memberdef in root.findall('.//memberdef[@kind="function"]'):
                func = process_function(memberdef)
                if func:
                    functions.append(func)
        except ET.ParseError as e:
            print(f"Warning: Failed to parse {xml_file.name}: {e}")
            continue

    if not functions:
        print("No documented functions found!")
        return

    # Separate public and private functions
    public_functions = [f for f in functions if not f['is_private']]
    private_functions = [f for f in functions if f['is_private']]

    # Sort by name
    public_functions.sort(key=lambda f: f['name'])
    private_functions.sort(key=lambda f: f['name'])

    # Generate frontmatter and index
    index_lines = [
        "---",
        "title: EQL API Reference",
        "description: Complete API reference for the Encrypt Query Language (EQL) PostgreSQL extension.",
        f"version: {version}",
        "---",
        "",
        "Complete API reference for the Encrypt Query Language (EQL) PostgreSQL extension.",
        "",
        "## Functions",
        ""
    ]
    # Add public functions to index
    for func in public_functions:
        anchor = generate_anchor(func['signature'])
        index_lines.append(f"- [`{func['signature']}`](#{anchor}) - {func['brief']}")

    # Add private functions section to index
    if private_functions:
        index_lines.append("")
        index_lines.append("### Private Functions")
        index_lines.append("")
        for func in private_functions:
            anchor = generate_anchor(func['signature'])
            index_lines.append(f"- [`{func['signature']}`](#{anchor}) - {func['brief']}")

    index_lines.append("")
    index_lines.append("---")
    index_lines.append("")

    # Add all public function docs
    all_funcs = public_functions + private_functions
    type_map = build_type_lookup_map(all_funcs)

    index_lines.append("")
    index_lines.append("## Functions")
    index_lines.append("")
    for func in public_functions:
        index_lines.append(generate_markdown(func, all_funcs, type_map))

    # Add private function docs at the end
    if private_functions:
        index_lines.append("")
        index_lines.append("## Private Functions")
        index_lines.append("")
        for func in private_functions:
            index_lines.append(generate_markdown(func, all_funcs, type_map))

    # Write output
    output_file = output_dir / 'API.md'
    output_file.write_text('\n'.join(index_lines))

    print(f"✓ Generated Markdown documentation: {output_file}")
    print(f"  Functions documented: {len(functions)}")

if __name__ == '__main__':
    main()
