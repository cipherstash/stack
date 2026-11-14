"""Type stub for the native extension. Kept by hand, beside the Rust source."""

from typing import Any, Dict, List, Optional, Sequence, Tuple, final

def build_info() -> tuple[str, str]:
    """``(version, engine_commit)`` as recorded at build time."""

def check_plan(
    table: str, fields: List[Tuple[str, Optional[str], bool]]
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
    table: str, fields: List[Tuple[str, Optional[str], Optional[str], type, bool]]
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

def query(plan: Plan, field: str, operator: str, value: Any) -> str:
    """The query term for the operator named ``operator``, such as
    ``"eq"`` or ``"gte"``, and ``value`` on the sealed field ``field``.
    Raises ``InvalidValueError`` before any request for a value that does
    not fit the field."""

def operators(plan: Plan, field: str) -> List[str]:
    """The names of the operators the engine supports on the field
    ``field``, from the plan, with no request. A passthrough field has
    none."""

def verify(plan: Plan, field: str, text: str, values: List[str]) -> List[bool]:
    """For each value, whether it holds every token of the match text
    ``text`` on the match field ``field``. No key and no request."""

def target_limit(
    plan: Plan,
    field: str,
    term: str,
    want: int,
    rows: int,
    histogram: Optional[List[Tuple[int, int]]] = None,
    confidence: Optional[float] = None,
) -> Optional[int]:
    """The rows to fetch so that ``want`` of them verify, or ``None`` when
    no finite number can be promised. No key and no request."""

def client_builds() -> int:
    """How many times the shared engine client has been built. For tests."""

def request_count() -> int:
    """How many requests the shared client has sent to ZeroKMS. For tests."""

def requests() -> Dict[str, int]:
    """The requests the shared client has sent to ZeroKMS, by endpoint,
    such as ``load-keyset``. For tests."""
