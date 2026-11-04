"""Type stub for the native extension. Kept by hand, beside the Rust source."""

from typing import List, Optional, Tuple

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
