"""The declaration tests, compiled with ``from __future__ import annotations``.

Under that import every annotation is a string until the decorator resolves
it, which is the case a real model module with the import is in. The asserts
are rewritten as pytest rewrites a test module's (``_compiled_cases.py``).
"""

import __future__

from _compiled_cases import compiled_cases

exec(compiled_cases(__future__.annotations.compiler_flag), globals())
