"""The declaration tests, with annotations evaluated as written.

The tests themselves are in ``_declaration_cases.py``, compiled here without
``from __future__ import annotations``, with their asserts rewritten as
pytest rewrites a test module's (``_compiled_cases.py``).
"""

from _compiled_cases import compiled_cases

exec(compiled_cases(), globals())
