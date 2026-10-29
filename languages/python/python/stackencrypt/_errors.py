"""The exceptions the SDK raises.

Every error carries the same four fields, whoever raised it: ``code`` (a fixed
lower_snake_case token), ``message`` (prose for a person), ``reason`` (a fixed
lower_snake_case token or ``None``) and ``field`` (the field name, or
``None``). The code's prefix tells where the error came from. An engine
error's code is the engine's diagnostic code with ``::`` replaced by ``_``.
"""

from typing import Optional


class StashError(Exception):
    """The base of every SDK error, and the one to catch for all of them."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        field: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        # The code and message are the exception's args, so that pickle, which
        # rebuilds an exception as cls(*args), can rebuild this one. The other
        # attributes come back from __dict__.
        super().__init__(code, message)
        self.code = code
        self.message = message
        self.field = field
        self.reason = reason

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class DeclarationError(StashError):
    """A model class that cannot be declared, raised at its class statement."""


class AuthenticationError(StashError):
    """The credentials are missing, malformed or refused.

    The code is the engine's, such as ``stack_auth_not_authenticated``.
    """
