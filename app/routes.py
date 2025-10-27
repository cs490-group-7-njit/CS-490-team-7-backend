"""HTTP routes for the CS-490 Team 7 backend."""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from .extensions import db

bp = Blueprint("api", __name__)


@bp.get("/health")
def health_check() -> tuple[dict[str, str], int]:
    """Expose a simple uptime check endpoint."""
    return jsonify({"status": "ok"}), 200


@bp.get("/db-health")
def database_health() -> tuple[dict[str, str], int]:
    """Check connectivity to the configured database."""
    try:
        db.session.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        current_app.logger.exception("Database connectivity check failed", exc_info=exc)
        return jsonify({"database": "unavailable"}), 500

    return jsonify({"database": "ok"}), 200
