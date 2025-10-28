"""HTTP routes for the CS-490 Team 7 backend."""
from __future__ import annotations

from datetime import UTC, datetime

from flask import Blueprint, current_app, jsonify, request
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
from werkzeug.security import check_password_hash

from .extensions import db
from .models import AuthAccount, Salon, User

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


@bp.get("/users/verify")
def verify_user() -> tuple[dict[str, object], int]:
    """Check if a user exists by email and return basic details."""
    email = (request.args.get("email") or "").strip().lower()

    if not email:
        return jsonify({"error": "invalid_query", "message": "email query parameter is required"}), 400

    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({"error": "not_found", "message": "user not found"}), 404

    return jsonify({"user": user.to_dict_basic()}), 200


def _build_token(payload: dict[str, object]) -> str:
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="auth-token")
    return serializer.dumps(payload)


@bp.post("/auth/login")
def login() -> tuple[dict[str, object], int]:
    """Authenticate a vendor by email/password and return an access token."""
    payload = request.get_json(silent=True) or {}

    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""

    if not email or not password:
        return (
            jsonify({"error": "invalid_payload", "message": "email and password are required"}),
            400,
        )

    record = (
        db.session.query(User, AuthAccount)
        .join(AuthAccount, AuthAccount.user_id == User.user_id)
        .filter(User.email == email)
        .first()
    )

    if not record:
        return jsonify({"error": "unauthorized", "message": "invalid email or password"}), 401

    user, auth_account = record

    if user.role != "vendor":
        return jsonify({"error": "forbidden", "message": "account is not a vendor"}), 403

    if not check_password_hash(auth_account.password_hash, password):
        return jsonify({"error": "unauthorized", "message": "invalid email or password"}), 401

    auth_account.last_login_at = datetime.now(UTC)

    try:
        db.session.add(auth_account)
        db.session.commit()
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update last login timestamp", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

    token = _build_token({"user_id": user.user_id, "role": user.role})

    return jsonify({"token": token, "user": user.to_dict_basic()}), 200
