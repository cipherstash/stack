"""The exception types the shell raises, re-exported from the extension.

`StackEncryptError` is the one base to catch. The three below it say where
the refusal came from:

- `DeclarationError` — a class's annotations are wrong. Raised by Python.
- `PlanError` — the engine refused the plan, or a kind name is not one.
- `EngineError` — a value was refused, or an operation failed.
"""

from stackencrypt._engine import (
    DeclarationError,
    EngineError,
    PlanError,
    StackEncryptError,
)

__all__ = [
    "StackEncryptError",
    "DeclarationError",
    "PlanError",
    "EngineError",
]
