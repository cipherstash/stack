"""``Cipher(cls)``: the class checks and the credentials. No request is made."""

import dataclasses
from typing import Annotated

import pytest

import stackencrypt
from stackencrypt import (
    AuthenticationError,
    Cipher,
    DeclarationError,
    Passthrough,
    StashError,
    TextEq,
)

ACCESS_KEY = "CSAKtestKeyId.testKeySecret"
WORKSPACE_CRN = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"


@pytest.fixture(autouse=True)
def no_credentials(monkeypatch, tmp_path):
    """No credentials in the environment, and an empty profile store."""
    for name in ("CS_CLIENT_ACCESS_KEY", "CS_WORKSPACE_CRN", "CS_CLIENT_ID", "CS_CLIENT_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CS_CONFIG_PATH", str(tmp_path / "no-profile"))


@pytest.fixture
def credentials(monkeypatch):
    monkeypatch.setenv("CS_CLIENT_ACCESS_KEY", ACCESS_KEY)
    monkeypatch.setenv("CS_WORKSPACE_CRN", WORKSPACE_CRN)


def declared():
    @stackencrypt.model("users")
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]

    return User


def refusal(build):
    with pytest.raises(StashError) as raised:
        build()
    return raised.value


def test_a_cipher_is_built_for_a_declared_class(credentials):
    User = declared()

    users = Cipher(User)

    assert users.declaration.table == "users"
    assert [f.name for f in users.declaration.fields] == ["email", "age"]


def test_an_undecorated_class_is_refused():
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]

    error = refusal(lambda: Cipher(User))
    assert isinstance(error, DeclarationError)
    assert error.code == "declaration_not_decorated"


def test_a_subclass_of_a_declared_class_is_refused():
    User = declared()

    @dataclasses.dataclass
    class Admin(User):
        level: Annotated[int, Passthrough] = 0

    error = refusal(lambda: Cipher(Admin))
    assert error.code == "declaration_not_decorated"
    assert "subclass of 'User'" in str(error)


def test_an_instance_is_refused():
    User = declared()

    error = refusal(lambda: Cipher(User(email="a", age=1)))
    assert error.code == "declaration_not_decorated"


def test_the_class_checks_come_before_the_credentials():
    # No credentials are set, and the class error is the one raised.
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]

    assert refusal(lambda: Cipher(User)).code == "declaration_not_decorated"


def test_an_annotation_added_after_decoration_is_refused(credentials):
    User = declared()
    User.__annotations__["nickname"] = Annotated[str, TextEq]

    error = refusal(lambda: Cipher(User))
    assert error.code == "declaration_class_changed"
    assert error.reason == "fields"
    assert error.field == "nickname"


def test_a_replaced_repr_is_refused(credentials):
    User = declared()
    User.__repr__ = lambda self: self.email

    error = refusal(lambda: Cipher(User))
    assert error.code == "declaration_class_changed"
    assert error.reason == "methods"


def test_a_replaced_constructor_is_refused(credentials):
    User = declared()

    def __init__(self, email):
        self.email = email

    User.__init__ = __init__

    error = refusal(lambda: Cipher(User))
    assert error.code == "declaration_class_changed"
    assert error.reason == "constructor"


def test_no_credentials_is_an_authentication_error_from_the_engine():
    User = declared()

    error = refusal(lambda: Cipher(User))
    assert isinstance(error, AuthenticationError)
    assert error.code == "stack_auth_not_authenticated"
    assert "CS_CLIENT_ACCESS_KEY" in error.message


def test_a_malformed_access_key_is_an_authentication_error(monkeypatch):
    monkeypatch.setenv("CS_CLIENT_ACCESS_KEY", "not-an-access-key")
    monkeypatch.setenv("CS_WORKSPACE_CRN", WORKSPACE_CRN)
    User = declared()

    error = refusal(lambda: Cipher(User))
    assert isinstance(error, AuthenticationError)
    assert error.code.startswith("stack_auth_")
    assert "not-an-access-key" not in str(error)
