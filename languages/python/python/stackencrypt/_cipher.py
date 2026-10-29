"""``Cipher``: encrypts and decrypts the instances of one declared class.

Today it checks the class and the credentials, and stores the declaration.
``encrypt``, ``decrypt`` and ``query`` come in later tickets.
"""

from stackencrypt import _engine
from stackencrypt._declaration import Declaration, check_unchanged, declaration_of
from stackencrypt._errors import AuthenticationError, DeclarationError


class Cipher:
    """The cipher for one class declared with ``stackencrypt.model``::

        users = stackencrypt.Cipher(User)

    The class must be declared itself: a subclass of a declared class is not.
    The class must also be as it was when declared. The credentials come from
    ``CS_CLIENT_ACCESS_KEY`` and ``CS_WORKSPACE_CRN``, or from the profile
    that ``stash auth login`` writes. Building a cipher makes no request.
    """

    def __init__(self, cls: type) -> None:
        declaration = declaration_of(cls)
        if declaration is None:
            raise _not_decorated(cls)
        check_unchanged(cls, declaration)
        refused = _engine.detect_credentials()
        if refused is not None:
            code, message, field, reason = refused
            raise AuthenticationError(code, message, field=field, reason=reason)
        self._cls = cls
        self._declaration = declaration

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
