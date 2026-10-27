"""Type stub for the native extension. Kept by hand, beside the Rust source."""

def build_info() -> tuple[str, str]:
    """``(version, engine_commit)`` as recorded at build time."""
