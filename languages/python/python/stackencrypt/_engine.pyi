"""Type stub for the native extension. Kept by hand, beside the Rust source."""

from typing import Any, Dict, List, Optional, Sequence, Tuple, final

def build_info() -> tuple[str, str]:
    """``(version, engine_commit)`` as recorded at build time."""

def check_plan(
    table: str, fields: List[Tuple[str, Optional[str]]]
) -> Optional[Tuple[str, str, Optional[str], Optional[str]]]:
    """The engine's check of a model's plan: ``None``, or its refusal as
    ``(code, message, field, reason)``."""

def detect_credentials() -> Optional[Tuple[str, str, Optional[str], Optional[str]]]:
    """Find the credentials, with no request: ``None``, or the refusal as
    ``(code, message, field, reason)``."""

@final
class Plan:
    """A model's plan, built once by ``Cipher``. Opaque."""

def build_plan(
    table: str, fields: List[Tuple[str, Optional[str], Optional[str], type]]
) -> Plan:
    """The plan for a model stored in ``table``: ``(name, eql_type, kind,
    value_type)`` per field, ``eql_type`` and ``kind`` ``None`` for a
    passthrough."""

def encrypt(plan: Plan, models: Sequence[Any]) -> List[Dict[str, object]]:
    """One dict per model: EQL JSON as ``str`` for a sealed field, the value
    for a passthrough. Raises ``InvalidValueError`` before any request."""

def decrypt(plan: Plan, cls: type, rows: Sequence[Any]) -> List[Any]:
    """One instance of ``cls`` per row, built with the plan's fields as
    keyword arguments. Raises ``DecryptError`` or ``InvalidValueError``
    before any request for what the rows themselves can answer."""

def query(plan: Plan, field: str, value: Any) -> str:
    """The equality query term for ``value`` on the sealed field ``field``.
    Raises ``InvalidValueError`` before any request for a value that does
    not fit the field."""

def client_builds() -> int:
    """How many times the shared engine client has been built. For tests."""

def request_count() -> int:
    """How many requests the shared client has sent to ZeroKMS. For tests."""

def keyset_loads() -> int:
    """How many times the default keyset loaded; a failed load is not
    counted. For tests."""
