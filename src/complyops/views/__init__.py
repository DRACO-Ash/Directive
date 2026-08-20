"""Flask blueprints, one per functional area."""

from .health import health_bp

__all__ = ["health_bp"]
