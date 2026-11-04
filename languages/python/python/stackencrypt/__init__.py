"""Searchable encryption for Python, over the CipherStash Stack engine.

Walking skeleton. The package loads its native extension, ``_engine``, exposes
two facts about the build, and exports the markers a model's fields are
declared with. Nothing encrypts yet.
"""

from stackencrypt import _engine, _eql
# The markers for the EQL types the engine produces today. `_eql.__all__`
# lists them; a marker the engine cannot produce yet stays in `_eql` only.
from stackencrypt._eql import *  # noqa: F403
from stackencrypt._markers import Ignore, Passthrough

# The distribution's version, and the commit of the engine it was built from.
__version__: str
__engine__: str
__version__, __engine__ = _engine.build_info()

__all__ = ["Ignore", "Passthrough", "__engine__", "__version__"]
__all__ += _eql.__all__
