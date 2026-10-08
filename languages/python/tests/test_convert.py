"""The value codec, with no encryption and no credentials.

Every kind name here is vitaminc's own (`ValueKind::name`): lowercase
`"string"`, `"int64"`, `"float64"`, `"bool"`. The engine parses the data
plan's `"type"` key with `ValueKind: FromStr` over exactly those, so the
names are not ours to choose.
"""

import pytest

from stackencrypt import _engine
from stackencrypt.errors import EngineError, PlanError


def test_text_roundtrips():
    assert _engine.roundtrip("bob@example.com", "string") == "bob@example.com"


def test_int_roundtrips_as_int_not_float():
    result = _engine.roundtrip(34, "int64")
    assert result == 34
    assert isinstance(result, int)
    assert not isinstance(result, float)


def test_float_roundtrips_as_float():
    result = _engine.roundtrip(34.0, "float64")
    assert isinstance(result, float)
    assert result == 34.0


def test_bytes_roundtrip():
    assert _engine.roundtrip(b"\x00\xff", "bytes") == b"\x00\xff"


def test_bool_roundtrips():
    assert _engine.roundtrip(True, "bool") is True


# Review Focus 1: a Python int has no width, so the shell is the last place
# that can refuse an out-of-range one. The engine would otherwise take
# whatever tag arrived and derive a term for it.
def test_int_over_the_declared_width_is_refused():
    with pytest.raises(EngineError, match="int64"):
        _engine.roundtrip(2**63, "int64")


def test_negative_int_under_the_declared_width_is_refused():
    with pytest.raises(EngineError, match="int64"):
        _engine.roundtrip(-(2**63) - 1, "int64")


def test_int_over_the_declared_int32_width_is_refused():
    with pytest.raises(EngineError, match="int32"):
        _engine.roundtrip(2**31, "int32")


# Review Focus 3: a str where an int64 is declared.
def test_wrong_python_type_for_the_declared_kind_is_refused():
    with pytest.raises(EngineError, match="int64"):
        _engine.roundtrip("34", "int64")


def test_a_float_for_a_declared_int_is_refused():
    # 34.0 and 34 derive different ORE terms. Converting one to the other
    # silently is the bug the declared kind exists to stop.
    with pytest.raises(EngineError, match="int64"):
        _engine.roundtrip(34.0, "int64")


def test_bool_is_not_an_int():
    # `isinstance(True, int)` is True in Python, so a bool reaches an int64
    # field unless the conversion checks bool first.
    with pytest.raises(EngineError, match="int64"):
        _engine.roundtrip(True, "int64")


# Review Focus 4: the spec is silent on None. It must be refused by name
# against a declared kind, not sealed as something else.
def test_none_against_a_declared_kind_is_refused():
    with pytest.raises(EngineError, match="string"):
        _engine.roundtrip(None, "string")


def test_an_unknown_kind_name_is_a_plan_error():
    # Not an EngineError: a kind name no ValueKind has is a declaration
    # defect, and it is the plan that carries declarations.
    with pytest.raises(PlanError, match="Utf8Str"):
        _engine.roundtrip("x", "Utf8Str")


def test_a_python_type_with_no_encoding_is_refused():
    with pytest.raises(EngineError, match="complex"):
        _engine.roundtrip(1 + 2j, "string")
