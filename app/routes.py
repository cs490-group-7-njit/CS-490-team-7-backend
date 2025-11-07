"""HTTP routes for the CS-490 Team 7 backend."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
from werkzeug.security import check_password_hash, generate_password_hash

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
            # .filter(Salon.is_published.is_(True))
            .order_by(Salon.created_at.desc())
            .limit(12)
            .all()
        )
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch salons", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

    payload = {"salons": [salon.to_dict() for salon in salons]}
    return jsonify(payload), 200


@bp.post("/salons")
def create_salon() -> tuple[dict[str, object], int]:
    """Create a new salon entry (restricted to authenticated vendors)."""
    payload = request.get_json(silent=True) or {}

    # Extract required and optional fields
    name = (payload.get("name") or "").strip()
    vendor_id = payload.get("vendor_id")
    address_line1 = (payload.get("address_line1") or "").strip() or None
    address_line2 = (payload.get("address_line2") or "").strip() or None
    city = (payload.get("city") or "").strip() or None
    description = (payload.get("description") or "").strip() or None
    state = (payload.get("state") or "").strip() or None
    postal_code = (payload.get("postal_code") or "").strip() or None
    phone = (payload.get("phone") or "").strip() or None

    # Basic validation
    if not name or not vendor_id:
        return (
            jsonify({
                "error": "invalid_payload",
                "message": "name and vendor_id are required"
            }),
            400,
        )

    # Check vendor existence and role
    vendor = User.query.get(vendor_id)
    if not vendor or vendor.role != "vendor":
        return (
            jsonify({
                "error": "invalid_vendor",
                "message": "vendor_id must correspond to a valid vendor account"
            }),
            400,
        )

    try:
        # Create salon (verification_status defaults to 'pending')
        new_salon = Salon(
            name=name,
            vendor_id=vendor_id,
            address_line1=address_line1,
            address_line2=address_line2,
            city=city,
            description=description,
            state=state,
            postal_code=postal_code,
            phone=phone,
            is_published=False,  # not published until admin approves
            verification_status="pending",
        )

        db.session.add(new_salon)
        db.session.commit()

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to create new salon", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

    return jsonify({"salon": new_salon.to_dict()}), 201


@bp.put("/salons/<int:salon_id>")
def update_salon_details(salon_id: int) -> tuple[dict[str, object], int]:
    """Update salon details (for vendors managing their salon)."""
    payload = request.get_json(silent=True) or {}

    # Extract fields that can be updated
    name = (payload.get("name") or "").strip()
    description = (payload.get("description") or "").strip()
    business_type = (payload.get("business_type") or "").strip() or None

    # ! TODO: Implement proper authentication
    # # The vendor_id should come from the authenticated user (for now, accept from payload)
    # vendor_id = payload.get("vendor_id")

    # if not vendor_id:
    #     return jsonify({
    #         "error": "invalid_payload",
    #         "message": "vendor_id is required"
    #     }), 400

    if not name:
        return jsonify({
            "error": "invalid_payload",
            "message": "name cannot be blank"
        }), 400

    try:
        # Fetch the salon
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({
                "error": "not_found",
                "message": f"salon_id {salon_id} does not exist"
            }), 404

        # # Verify ownership
        # if salon.vendor_id != vendor_id:
        #     return jsonify({
        #         "error": "forbidden",
        #         "message": "you are not authorized to modify this salon"
        #     }), 403

        # Update allowed fields
        salon.name = name
        salon.description = description
        salon.business_type = business_type
        salon.updated_at = datetime.now(timezone.utc)

        db.session.add(salon)
        db.session.commit()

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update salon details", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

    return jsonify({
        "message": "Salon details updated successfully",
        "salon": salon.to_dict()
    }), 200


@bp.post("/auth/register")
def register_user() -> tuple[dict[str, object], int]:
    """Register a new client or vendor user."""
    payload = request.get_json(silent=True) or {}

    # Extract and validate required fields
    name = (payload.get("name") or "").strip()
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    role = (payload.get("role") or "client").strip().lower()
    phone = (payload.get("phone") or "").strip() or None  # Handle empty string

    if not name or not email or not password:
        return (
            jsonify({"error": "invalid_payload", "message": "name, email, and password are required"}),
            400,
        )

    # Security: Only allow 'client' or 'vendor' registration via this public endpoint
    if role not in ["client", "vendor"]:
        return (
            jsonify({"error": "invalid_role", "message": "role must be 'client' or 'vendor'"}),
            400,
        )

    # Alternative Flow 1: Check if data is invalid (email already exists)
    if User.query.filter_by(email=email).first():
        return (
            jsonify({"error": "conflict", "message": "email address is already in use"}),
            409,  # 409 Conflict is more specific than 400
        )

    # Ideal Flow: Create user and auth account
    try:
        password_hash = generate_password_hash(password)

        # Create the User
        new_user = User(name=name, email=email, role=role, phone=phone)
        db.session.add(new_user)
        db.session.flush()  # Get the new user_id before creating the AuthAccount

        # Create the associated AuthAccount
        new_account = AuthAccount(user_id=new_user.user_id, password_hash=password_hash)
        db.session.add(new_account)

        db.session.commit()

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to register new user", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

    # Ideal Flow (Step 5): Return confirmation and log user in by issuing a token
    token = _build_token({"user_id": new_user.user_id, "role": new_user.role})

    return jsonify({"token": token, "user": new_user.to_dict_basic()}), 201  # 201 Created


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
    """Authenticate a user by email/password and return an access token."""
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

    # Allow login for all valid user roles (client, vendor, admin)
    valid_roles = ["client", "vendor", "admin"]
    if user.role not in valid_roles:
        return jsonify({"error": "forbidden", "message": f"invalid user role: {user.role}"}), 403

    if not check_password_hash(auth_account.password_hash, password):
        return jsonify({"error": "unauthorized", "message": "invalid email or password"}), 401

    auth_account.last_login_at = datetime.now(timezone.utc)

    try:
        db.session.add(auth_account)
        db.session.commit()
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update last login timestamp", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

    token = _build_token({"user_id": user.user_id, "role": user.role})

    return jsonify({"token": token, "user": user.to_dict_basic()}), 200