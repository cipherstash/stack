"""Searchable encryption for Python, over the CipherStash Stack engine.

Tracer. The public names here are meant to continue into the real SDK; the
code behind them is not.
"""

from stackencrypt import _engine

__all__ = ["engine_version"]


def engine_version() -> str:
    """The version of the native shell this package was built with."""
    return _engine.version()
