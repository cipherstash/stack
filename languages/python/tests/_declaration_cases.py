"""The declaration tests, compiled twice: as written, and with
``from __future__ import annotations``. See ``test_declaration.py`` and
``test_declaration_future_annotations.py``.

The classes the tests declare refer only to module-level names, because
under the future import a hint is resolved from the module's globals.
"""

import dataclasses
import datetime
import decimal
import pickle
import uuid
from typing import Annotated, ClassVar, Final, List, NamedTuple, Optional

import attrs
import pydantic
import pytest
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import ForeignKey

import stackencrypt
from stackencrypt import (
    BigintEq,
    Boolean,
    DateEq,
    DeclarationError,
    DoubleEq,
    Ignore,
    IntegerEq,
    JsonSearch,
    NumericEq,
    Passthrough,
    RealEq,
    SmallintEq,
    Text,
    TextEq,
    TimestampEq,
)
from stackencrypt import _eql
from stackencrypt._declaration import _KIND_TYPES, declaration_of

EXPECTED_FIELDS = [("email", TextEq), ("age", Passthrough)]


def planned(cls):
    declaration = declaration_of(cls)
    assert declaration is not None, "the class was not declared"
    return [(field.name, field.marker) for field in declaration.fields]


def refusal(build):
    with pytest.raises(DeclarationError) as raised:
        build()
    return raised.value


# The five class kinds, each with one TextEq, one Passthrough and one Ignore.


def test_a_dataclass_declares():
    @stackencrypt.model("users")
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]
        note: Annotated[str, Ignore] = ""

    assert planned(User) == EXPECTED_FIELDS
    assert declaration_of(User).table == "users"


def test_an_attrs_class_declares():
    @stackencrypt.model("users")
    @attrs.define
    class User:
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]
        note: Annotated[str, Ignore] = ""

    assert planned(User) == EXPECTED_FIELDS


def test_a_pydantic_model_declares():
    @stackencrypt.model("users")
    class User(pydantic.BaseModel):
        email: Annotated[str, TextEq]
        age: Annotated[int, Passthrough]
        note: Annotated[str, Ignore] = ""

    assert planned(User) == EXPECTED_FIELDS


class UserTuple(NamedTuple):
    email: Annotated[str, TextEq]
    age: Annotated[int, Passthrough]
    note: Annotated[str, Ignore] = ""


def test_a_named_tuple_declares():
    declared = stackencrypt.model("users")(UserTuple)

    assert declared is UserTuple
    assert planned(UserTuple) == EXPECTED_FIELDS


class Base(DeclarativeBase):
    pass


class Post(Base):
    __tablename__ = "posts"
    id: Mapped[Annotated[int, Passthrough]] = mapped_column(primary_key=True)
    user_id: Mapped[Annotated[int, Passthrough]] = mapped_column(ForeignKey("users.id"))


@stackencrypt.model("users")
class User(Base):
    __tablename__ = "users"
    id: Mapped[Annotated[int, Passthrough]] = mapped_column(primary_key=True)
    email: Mapped[Annotated[str, TextEq]]
    age: Mapped[Annotated[int, Passthrough]]
    posts: Mapped[Annotated[List["Post"], Ignore]] = relationship()


def test_a_sqlalchemy_class_declares_through_mapped():
    assert planned(User) == [("id", Passthrough)] + EXPECTED_FIELDS


def test_a_relationship_marked_ignore_is_not_in_the_plan():
    assert "posts" not in [name for name, _ in planned(User)]


def test_sqlalchemy_still_maps_every_column_it_was_given():
    assert set(User.__table__.columns.keys()) == {"id", "email", "age"}


# Rule A and its codes.


def test_a_field_without_a_marker_is_refused():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq]
            age: int

    error = refusal(build)
    assert error.code == "declaration_no_marker"
    assert error.field == "age"
    assert "declaration_no_marker" in str(error)
    assert "'age'" in str(error)


def test_annotated_metadata_from_another_library_is_not_a_marker():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, "not a marker"]

    assert refusal(build).code == "declaration_no_marker"


def test_a_field_with_two_markers_is_refused():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq, Text]

    error = refusal(build)
    assert error.code == "declaration_two_markers"
    assert error.field == "email"
    assert "declaration_two_markers" in str(error)
    assert "'email'" in str(error)


def test_ignore_with_another_marker_is_two_markers():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq, Ignore]

    assert refusal(build).code == "declaration_two_markers"


def test_a_wrapper_inside_the_marker_annotated_is_refused():
    # A plain class, whose fields come from its hints as a SQLAlchemy class's
    # do. On a mapped class SQLAlchemy refuses this order itself, with
    # MappedAnnotationError, before the decorator runs.
    def build():
        @stackencrypt.model("users")
        class User:
            email: Annotated[Mapped[str], TextEq]

    error = refusal(build)
    assert error.code == "declaration_marker_not_outermost"
    assert error.field == "email"
    assert error.reason == "rule_a"
    assert "Mapped[Annotated[str, TextEq]]" in str(error)


def test_the_remedy_names_the_inner_type_as_written():
    def build():
        @stackencrypt.model("users")
        class User:
            email: Annotated[Mapped[Optional[str]], TextEq]

    message = str(refusal(build))
    assert "Union" not in message
    assert (
        "Mapped[Annotated[Optional[str], TextEq]]" in message
        or "Mapped[Annotated[str | None, TextEq]]" in message
    )


class KeywordConstructor:
    """A plain class whose fields come from its hints, as a SQLAlchemy
    class's do, with a constructor that takes any keyword argument."""

    def __init__(self, **kwargs):
        vars(self).update(kwargs)


def test_a_collection_value_type_is_not_a_misplaced_wrapper():
    @stackencrypt.model("users")
    class User(KeywordConstructor):
        email: Annotated[str, TextEq]
        tags: Annotated[List[str], Ignore]

    assert planned(User) == [("email", TextEq)]


@pytest.mark.parametrize("kind", ["dataclass", "plain"])
def test_a_marker_inside_a_list_or_final_is_refused(kind):
    def build_list():
        class User:
            tags: List[Annotated[str, TextEq]]

        if kind == "dataclass":
            User = dataclasses.dataclass(User)
        stackencrypt.model("users")(User)

    def build_final():
        class User:
            email: Final[Annotated[str, TextEq]]

        if kind == "dataclass":
            User = dataclasses.dataclass(User)
        stackencrypt.model("users")(User)

    for build in (build_list, build_final):
        error = refusal(build)
        assert error.code == "declaration_marker_not_outermost"
        assert error.reason == "rule_a"


def test_a_marker_inside_another_type_is_refused():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Optional[Annotated[str, TextEq]]

    error = refusal(build)
    assert error.code == "declaration_marker_not_outermost"
    assert error.field == "email"


class MyText(TextEq):
    """A user's subclass of a marker, which is not a marker."""


def test_a_subclass_of_a_marker_is_not_a_marker():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, MyText]

    assert refusal(build).code == "declaration_no_marker"


def test_an_unresolved_hint_is_refused_with_its_field():
    # "Undefined" is a forward reference that never resolves, as a
    # relationship to a class written later does.
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq]
            posts: Annotated[List["Undefined"], Ignore] = dataclasses.field(  # noqa: F821
                default_factory=list
            )

    error = refusal(build)
    assert error.code == "declaration_hints_unresolved"
    assert error.field == "posts"
    assert "'posts'" in str(error)
    assert isinstance(error.__cause__, NameError)


class LaterBase(DeclarativeBase):
    pass


def test_a_relationship_to_a_class_defined_later_is_refused_with_its_field():
    # Author is defined after Book, as a relationship target often is.
    def build():
        @stackencrypt.model("books")
        class Book(LaterBase):
            __tablename__ = "books"
            id: Mapped[Annotated[int, Passthrough]] = mapped_column(primary_key=True)
            title: Mapped[Annotated[str, TextEq]]
            authors: Mapped[Annotated[List["Author"], Ignore]] = relationship()  # noqa: F821

    error = refusal(build)
    assert error.code == "declaration_hints_unresolved"
    assert error.field == "authors"
    assert isinstance(error.__cause__, NameError)


def test_a_class_is_declared_once():
    def build():
        @stackencrypt.model("users")
        @stackencrypt.model("accounts")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq]

    error = refusal(build)
    assert error.code == "declaration_already_declared"
    assert "'accounts'" in str(error)


def test_a_declaration_error_survives_pickle():
    error = DeclarationError("declaration_no_marker", "no marker", field="age", reason="rule_a")

    copy = pickle.loads(pickle.dumps(error))

    assert type(copy) is DeclarationError
    assert (copy.code, copy.message, copy.field, copy.reason) == (
        "declaration_no_marker",
        "no marker",
        "age",
        "rule_a",
    )
    assert str(copy) == str(error) == "declaration_no_marker: no marker"


def test_class_level_names_are_not_fields():
    @stackencrypt.model("users")
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]
        registry: ClassVar[dict] = {}

    assert planned(User) == [("email", TextEq)]


def test_a_subclass_is_not_declared_until_it_is_decorated():
    @stackencrypt.model("users")
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]

    @dataclasses.dataclass
    class Admin(User):
        level: Annotated[int, Passthrough] = 0

    assert declaration_of(Admin) is None


def test_model_needs_the_table_name():
    with pytest.raises(TypeError, match="table name"):

        @stackencrypt.model
        class User:
            email: Annotated[str, TextEq]


def test_model_refuses_an_empty_table_name():
    with pytest.raises(TypeError, match="table name"):
        stackencrypt.model("")


def test_declaring_a_class_needs_no_credentials(monkeypatch):
    for name in ("CS_WORKSPACE_CRN", "CS_CLIENT_ID", "CS_CLIENT_KEY", "CS_CLIENT_ACCESS_KEY"):
        monkeypatch.delenv(name, raising=False)

    @stackencrypt.model("users")
    @dataclasses.dataclass
    class User:
        email: Annotated[str, TextEq]

    assert planned(User) == [("email", TextEq)]


# The value type against the marker's kind.


@pytest.mark.parametrize(
    "value_type, marker",
    [
        (str, TextEq),
        (int, SmallintEq),
        (int, IntegerEq),
        (int, BigintEq),
        (float, RealEq),
        (float, DoubleEq),
        (bool, Boolean),
        (decimal.Decimal, NumericEq),
        (datetime.date, DateEq),
        (datetime.datetime, TimestampEq),
    ],
)
def test_each_kind_takes_its_one_python_type(value_type, marker):
    User = dataclasses.make_dataclass("User", [("value", Annotated[value_type, marker])])

    assert planned(stackencrypt.model("users")(User)) == [("value", marker)]


def test_every_producible_kind_but_json_has_a_python_type():
    # A new kind in the catalog fails here until the table names its type.
    # JSON has no Python type in v1 on purpose (#1341, Out of Scope).
    kinds = {marker.plaintext for marker in _eql.TYPES if marker.producible}
    assert kinds - set(_KIND_TYPES) == {"json"}


def test_a_value_type_that_is_not_the_kinds_is_refused():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[int, TextEq]

    error = refusal(build)
    assert error.code == "declaration_type_mismatch"
    assert error.field == "email"
    assert error.reason == "string"
    assert "'email'" in str(error)
    assert "TextEq" in str(error)
    assert "Annotated[str, TextEq]" in str(error)


@pytest.mark.parametrize(
    "value_type, marker",
    [
        (Optional[str], TextEq),
        (bool, IntegerEq),
        (datetime.datetime, DateEq),
        (int, DoubleEq),
    ],
)
def test_a_value_type_must_be_exactly_the_kinds(value_type, marker):
    User = dataclasses.make_dataclass("User", [("value", Annotated[value_type, marker])])

    error = refusal(lambda: stackencrypt.model("users")(User))
    assert error.code == "declaration_type_mismatch"


@pytest.mark.parametrize(
    "value_type",
    [str, int, float, bool, bytes, datetime.date, datetime.datetime, decimal.Decimal],
)
def test_a_passthrough_field_takes_the_eight_types(value_type):
    User = dataclasses.make_dataclass("User", [("value", Annotated[value_type, Passthrough])])

    assert planned(stackencrypt.model("users")(User)) == [("value", Passthrough)]


def test_a_passthrough_uuid_is_refused():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            id: Annotated[uuid.UUID, Passthrough]
            email: Annotated[str, TextEq]

    error = refusal(build)
    assert error.code == "declaration_type_mismatch"
    assert error.field == "id"
    assert error.reason == "passthrough"


def test_a_json_field_has_no_python_type_yet():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            profile: Annotated[str, JsonSearch]

    error = refusal(build)
    assert error.code == "declaration_type_mismatch"
    assert error.reason == "json"


def test_an_unproducible_marker_is_refused_with_the_catalog_reason():
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            profile: Annotated[str, _eql.Json]

    error = refusal(build)
    assert error.code == "declaration_unproducible"
    assert error.field == "profile"
    assert _eql.Json.reason in str(error)


# The constructor.


def test_the_decorator_below_dataclass_is_refused():
    def build():
        @dataclasses.dataclass
        @stackencrypt.model("users")
        class User:
            email: Annotated[str, TextEq]

    error = refusal(build)
    assert error.code == "declaration_not_outermost"
    assert error.field == "email"
    assert "above @dataclass" in str(error)


def test_the_decorator_below_attrs_is_refused():
    def build():
        @attrs.define
        @stackencrypt.model("users")
        class User:
            email: Annotated[str, TextEq]

    assert refusal(build).code == "declaration_not_outermost"


def build_without_the_field_in_the_constructor(kind):
    if kind == "init=False field":

        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq] = dataclasses.field(init=False)

    elif kind == "init=False class":

        @stackencrypt.model("users")
        @dataclasses.dataclass(init=False)
        class User:
            email: Annotated[str, TextEq]

    elif kind == "attrs private name":

        @stackencrypt.model("users")
        @attrs.define
        class User:
            _email: Annotated[str, TextEq]

    elif kind == "pydantic alias":

        @stackencrypt.model("users")
        class User(pydantic.BaseModel):
            email: Annotated[str, TextEq] = pydantic.Field(alias="Email")

    else:

        @stackencrypt.model("users")
        class User(pydantic.BaseModel):
            model_config = pydantic.ConfigDict(extra="allow")
            email: Annotated[str, TextEq] = pydantic.Field(alias="Email")


@pytest.mark.parametrize(
    "kind",
    [
        "init=False field",
        "init=False class",
        "attrs private name",
        "pydantic alias",
        "pydantic alias with extra=allow",
    ],
)
def test_a_field_the_constructor_does_not_take_is_refused(kind):
    error = refusal(lambda: build_without_the_field_in_the_constructor(kind))
    assert error.code == "declaration_constructor_missing_field"
    assert "above @dataclass" not in str(error)


def test_a_pydantic_alias_is_accepted_when_the_name_is_taken_too():
    @stackencrypt.model("users")
    class User(pydantic.BaseModel):
        model_config = pydantic.ConfigDict(populate_by_name=True)
        email: Annotated[str, TextEq] = pydantic.Field(alias="Email")

    assert planned(User) == [("email", TextEq)]


def build_with_a_required_ignore(kind):
    if kind == "dataclass":

        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            email: Annotated[str, TextEq]
            note: Annotated[str, Ignore]

    elif kind == "attrs":

        @stackencrypt.model("users")
        @attrs.define
        class User:
            email: Annotated[str, TextEq]
            note: Annotated[str, Ignore]

    else:

        @stackencrypt.model("users")
        class User(pydantic.BaseModel):
            email: Annotated[str, TextEq]
            note: Annotated[str, Ignore]


@pytest.mark.parametrize("kind", ["dataclass", "attrs", "pydantic"])
def test_a_required_ignore_field_is_refused(kind):
    error = refusal(lambda: build_with_a_required_ignore(kind))
    assert error.code == "declaration_ignore_required"
    assert error.field == "note"
    assert "default" in str(error)


def test_an_ignore_field_the_constructor_does_not_name_is_omittable():
    @stackencrypt.model("users")
    class User(KeywordConstructor):
        email: Annotated[str, TextEq]
        note: Annotated[str, Ignore]

    assert planned(User) == [("email", TextEq)]


# The engine's own check of the plan.


def test_a_plan_the_engine_refuses_is_a_declaration_error():
    # Every field is Ignore, so the plan has no field, and the engine refuses
    # an empty plan.
    def build():
        @stackencrypt.model("users")
        @dataclasses.dataclass
        class User:
            note: Annotated[str, Ignore] = ""

    error = refusal(build)
    assert error.code == "stack_encrypt_dynamic_plan"
    assert error.reason == "no_fields"
