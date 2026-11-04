"""``Cipher``: encrypts and decrypts the instances of one declared class.

It checks the class and the credentials, and builds the model's plan once.
``encrypt`` is here. ``decrypt`` and ``query`` come in later tickets.
"""

from typing import Dict, List, Sequence

from stackencrypt import _engine
from stackencrypt._markers import Passthrough
from stackencrypt._declaration import Declaration, check_unchanged, declaration_of
from stackencrypt._errors import AuthenticationError, DeclarationError


class Cipher:
    """The cipher for one class declared with ``stackencrypt.model``::

        users = stackencrypt.Cipher(User)

    The class must be declared itself: a subclass of a declared class is not.
    The class must also be as it was when declared. The credentials come from
    ``CS_CLIENT_ACCESS_KEY`` and ``CS_WORKSPACE_CRN``, or from the profile
    that ``stash auth login`` writes. Building a cipher makes no request.

    Every cipher in the process shares one engine client. It is built on the
    first ``encrypt`` of any cipher, which loads the default keyset once.
    """

    def __init__(self, cls: type) -> None:
        # The type check comes first: declaration_of reads the class's own
        # __dict__, and a string or an instance with __slots__ has none.
        declaration = declaration_of(cls) if isinstance(cls, type) else None
        if declaration is None:
            raise _not_decorated(cls)
        check_unchanged(cls, declaration)
        refused = _engine.detect_credentials()
        if refused is not None:
            code, message, field, reason = refused
            raise AuthenticationError(code, message, field=field, reason=reason)
        self._cls = cls
        self._declaration = declaration
        self._plan = _engine.build_plan(
            declaration.table,
            [
                (
                    field.name,
                    None if field.marker is Passthrough else field.marker.name,
                    None if field.marker is Passthrough else field.marker.plaintext,
                    field.value_type,
                )
                for field in declaration.fields
            ],
        )

    def encrypt(self, models: Sequence[object]) -> List[Dict[str, object]]:
        """Encrypt ``models``, instances of the declared class.

        Returns one dict per model, from column name to column value: the
        EQL JSON as a ``str`` for a sealed field, which psycopg inserts with
        a plain ``%s``, and the value itself for a passthrough field. An
        ``Ignore`` field is left out.

        Every value is checked first, by exact type and range. A value that
        does not fit raises ``InvalidValueError`` naming the field, and no
        request is made. An empty list makes no request at all.
        """
        return _engine.encrypt(self._plan, list(models))

    @property
    def declaration(self) -> Declaration:
        """What the decorator read from the class."""
        return self._declaration

    def __repr__(self) -> str:
        return f"Cipher({self._cls.__qualname__})"


def _not_decorated(cls: object) -> DeclarationError:
    if not isinstance(cls, type):
        return DeclarationError(
            "declaration_not_decorated",
            f"Cipher takes a class declared with stackencrypt.model, not {cls!r}.",
        )
    declared = next((b for b in cls.__mro__[1:] if declaration_of(b)), None)
    if declared is not None:
        detail = (
            f"It is a subclass of {declared.__name__!r}, and a subclass is not "
            "declared by its base."
        )
    else:
        detail = "It has no stackencrypt.model decorator."
    return DeclarationError(
        "declaration_not_decorated",
        f"class {cls.__name__!r} is not declared. {detail} Apply "
        f'@stackencrypt.model("...") to {cls.__name__!r} itself.',
    )
