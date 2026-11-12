"""Compile ``_declaration_cases.py`` with pytest's assertion rewriting.

The cases run through ``exec``, so pytest does not rewrite their ``assert``
statements as it rewrites a test module's. A failure would then show a bare
``AssertionError`` with no values. This applies the same rewrite to the
parsed source first. ``rewrite_asserts`` is in pytest's private ``_pytest``
package, so a pytest release can change it; a change fails both declaration
test modules at import.
"""

import ast
import pathlib
from types import CodeType

from _pytest.assertion.rewrite import rewrite_asserts

CASES = pathlib.Path(__file__).with_name("_declaration_cases.py")


def compiled_cases(flags: int = 0) -> CodeType:
    """The cases, with their asserts rewritten, compiled with ``flags``."""
    source = CASES.read_bytes()
    tree = ast.parse(source, filename=str(CASES))
    rewrite_asserts(tree, source, str(CASES))
    return compile(tree, str(CASES), "exec", flags=flags, dont_inherit=True)
