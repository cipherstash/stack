"""The declaration tests, compiled with ``from __future__ import annotations``.

Under that import every annotation is a string until the decorator resolves
it, which is the case a real model module with the import is in.
"""

import __future__
import pathlib

_CASES = pathlib.Path(__file__).with_name("_declaration_cases.py")
exec(
    compile(
        _CASES.read_text(),
        str(_CASES),
        "exec",
        flags=__future__.annotations.compiler_flag,
        dont_inherit=True,
    ),
    globals(),
)
