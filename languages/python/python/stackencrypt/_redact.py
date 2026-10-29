"""Redaction: ``repr`` and ``str`` of a declared class show no plaintext.

The decorator replaces the class's ``__repr__`` and ``__str__``. Every sealed
field shows ``[sealed]``, a passthrough field shows its value, and an
``Ignore`` field is left out. Nothing else is covered: ``dataclasses.asdict``,
Pydantic's ``model_dump`` and ``vars`` still return plaintext.

A generated ``__repr__`` (dataclass, attrs, Pydantic, ``NamedTuple``) is
replaced. A hand-written one is refused unless the decorator is given
``redact=False``, because replacing it would silently drop the user's code.
"""

import dataclasses
import os
import reprlib
from typing import Callable, Sequence, Tuple

SEALED = "[sealed]"

# The files a generated __repr__ reports as its own. A dataclass's __repr__ is
# wrapped for recursion, and the wrapper is in reprlib.py on 3.14 and in
# dataclasses.py on 3.9. attrs reports a "<attrs generated ...>" name.
_GENERATOR_FILES = frozenset(
    os.path.realpath(module.__file__)
    for module in (dataclasses, reprlib)
    if module.__file__ is not None
)

METHODS = ("__repr__", "__str__")


def hand_written(cls: type, name: str) -> bool:
    """Whether the first ``name`` method on ``cls`` was written by hand in the
    class's own module.

    A generated method comes from a generator's file or a ``<...>`` name, or
    belongs to another module, such as ``pydantic.main``. ``object``'s own
    method is not hand-written.
    """
    for base in cls.__mro__:
        if base is object:
            return False
        if name in vars(base):
            method = vars(base)[name]
            code = getattr(method, "__code__", None)
            if code is None or getattr(method, "__module__", None) != cls.__module__:
                return False
            filename = code.co_filename
            return (
                not filename.startswith("<")
                and os.path.realpath(filename) not in _GENERATOR_FILES
            )
    return False


def install(
    cls: type, fields: Sequence[Tuple[str, bool]]
) -> Tuple[Callable[[object], str], Callable[[object], str]]:
    """Replace ``__repr__`` and ``__str__`` on ``cls``.

    ``fields`` is ``(name, in_clear)`` per plan field, in order. Returns the two
    functions, so that ``Cipher`` can check that they are still in place.
    """
    shown = tuple(fields)

    def __repr__(self: object) -> str:
        parts = ", ".join(
            f"{name}={_value(self, name) if in_clear else SEALED}"
            for name, in_clear in shown
        )
        return f"{type(self).__name__}({parts})"

    def __str__(self: object) -> str:
        return __repr__(self)

    for method in (__repr__, __str__):
        method.__qualname__ = f"{cls.__qualname__}.{method.__name__}"
        setattr(cls, method.__name__, method)
    return __repr__, __str__


def _value(instance: object, name: str) -> str:
    try:
        return repr(getattr(instance, name))
    except AttributeError:
        return "<unset>"
