"""The release version, surfaced by the diagnostics read-out.

Held here rather than read through package metadata: the container copies the source
and sets PYTHONPATH rather than installing the project, so importlib.metadata would
find nothing at runtime. A test asserts this matches pyproject.toml so the two cannot
drift.
"""

__version__ = "2.1"
