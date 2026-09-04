"""The operator console: the interface Ash actually uses.

Server-rendered shell, with the register data fetched from the API. The look follows the
v1 prototype, which the flight plan names as the reference: dark, dense, Bluestaq amber as
the only brand colour, everything else functional.

Every value the browser renders is escaped by Jinja's autoescaping or by `textContent` in
the page's own script. Nothing here builds markup from a record field by concatenation.
"""

from __future__ import annotations

from flask import Blueprint, render_template

from .. import auth, records

console_bp = Blueprint("console", __name__)


@console_bp.get("/console")
@auth.required
def dashboard() -> str:
    """Render the console shell."""
    return render_template(
        "console.html",
        actor=auth.current_actor(),
        verified=auth.actor_is_verified(),
        banner=auth.development_banner(),
        registers=records.REGISTERS,
    )
