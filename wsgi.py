"""Container entrypoint.

The port comes from the environment, defaulting to 8080, and the bind address is
0.0.0.0, because the platform probes the container on its own injected port and a
loopback bind is unreachable from outside the container.
"""

from __future__ import annotations

from complyops import create_app
from complyops.config import port

app = create_app()

if __name__ == "__main__":  # pragma: no cover - the container runs gunicorn, not this
    app.run(host="0.0.0.0", port=port())  # noqa: S104 - the platform requires 0.0.0.0
