"""Searchable encryption for Python, over the CipherStash Stack engine.

Tracer. The public names here are meant to continue into the real SDK; the
code behind them is not.
"""

from stackencrypt import _engine
from stackencrypt._markers import (
    EQL,
    Bool,
    Bytes,
    Equality,
    Float32,
    Float64,
    Int32,
    Int64,
    Kind,
    Match,
    Ope,
    Ore,
    Passthrough,
    Text,
    UInt32,
    UInt64,
)
from stackencrypt.cipher import Cipher
from stackencrypt.plan import Plan, PlanSpec

__all__ = [
    "engine_version",
    # Width types: the field's plaintext kind.
    "Kind",
    "Text",
    "Int32",
    "Int64",
    "UInt32",
    "UInt64",
    "Float32",
    "Float64",
    "Bool",
    "Bytes",
    # Indexes: what a query against the field may do.
    "Equality",
    "Match",
    "Ore",
    "Ope",
    # What the field produces.
    "EQL",
    "Passthrough",
    # The declaration itself.
    "Plan",
    "PlanSpec",
    # The call site.
    "Cipher",
]


def engine_version() -> str:
    """The version of the native shell this package was built with."""
    return _engine.version()
