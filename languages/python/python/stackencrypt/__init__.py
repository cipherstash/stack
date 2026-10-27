"""Searchable encryption for Python, over the CipherStash Stack engine.

Walking skeleton. The package loads its native extension, ``_engine``, and
exposes two facts about the build. Nothing encrypts yet.
"""

from stackencrypt import _engine

# The distribution's version, and the commit of the engine it was built from.
__version__: str
__engine__: str
__version__, __engine__ = _engine.build_info()

__all__ = ["__engine__", "__version__"]
