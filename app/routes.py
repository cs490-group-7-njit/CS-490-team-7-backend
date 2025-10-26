"""HTTP routes for the CS-490 Team 7 backend."""
from __future__ import annotations

from flask import Blueprint, jsonify

bp = Blueprint("api", __name__)


@bp.get("/health")
def health_check() -> tuple[dict[str, str], int]:
    """Expose a simple uptime check endpoint."""
    return jsonify({"status": "ok"}), 200
