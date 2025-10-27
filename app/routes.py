"""HTTP routes for the CS-490 Team 7 backend."""
from __future__ import annotations

from flask import Blueprint, current_app, jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload

from .extensions import db
from .models import Salon

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


@bp.get("/salons")
def list_salons() -> tuple[dict[str, list[dict[str, object]]], int]:
    """Return a list of published salons with associated vendor information."""
    try:
        salons = (
            Salon.query.options(joinedload(Salon.vendor))
            .filter(Salon.is_published.is_(True))
            .order_by(Salon.created_at.desc())
            .limit(12)
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch salons", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

    payload = {"salons": [salon.to_dict() for salon in salons]}
    return jsonify(payload), 200
