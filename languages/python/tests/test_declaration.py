"""The declaration tests, with annotations evaluated as written.

The tests themselves are in ``_declaration_cases.py``, compiled here without
``from __future__ import annotations``.
"""

import pathlib

_CASES = pathlib.Path(__file__).with_name("_declaration_cases.py")
exec(compile(_CASES.read_text(), str(_CASES), "exec", dont_inherit=True), globals())
