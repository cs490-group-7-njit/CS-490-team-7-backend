"""HTTP routes for the CS-490 Team 7 backend."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import text, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db
from .models import AuthAccount, Salon, User, Staff, Service, Review, Appointment, ClientLoyalty, StaffRating, Notification, Message, LoyaltyRedemption, DiscountAlert, Product, ProductPurchase, Transaction

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
def list_salons() -> tuple[dict[str, object], int]:
    """Return a list of published salons with search/filter support (UC 2.7).
    
    Query Parameters:
    - query: Search by salon name (partial match, case-insensitive)
    - city: Filter by city (exact match)
    - business_type: Filter by business type (exact match)
    - sort: Sort field (name, created_at) - default: created_at
    - order: Sort order (asc, desc) - default: desc
    - page: Page number (default: 1)
    - limit: Results per page (default: 12, max: 50)
    """
    try:
        # Get query parameters
        query = request.args.get("query", "").strip()
        city = request.args.get("city", "").strip()
        business_type = request.args.get("business_type", "").strip()
        sort_field = request.args.get("sort", "created_at").strip()
        sort_order = request.args.get("order", "desc").strip().lower()
        page = max(1, int(request.args.get("page", 1)))
        limit = min(50, max(1, int(request.args.get("limit", 12))))
        
        # Validate sort parameters
        if sort_field not in ["name", "created_at"]:
            sort_field = "created_at"
        if sort_order not in ["asc", "desc"]:
            sort_order = "desc"
        
        # Build base query with vendor relationships
        salon_query = Salon.query.options(joinedload(Salon.vendor))
        
        # Apply filters
        if query:
            salon_query = salon_query.filter(
                Salon.name.ilike(f"%{query}%")
            )
        
        if city:
            salon_query = salon_query.filter(Salon.city.ilike(city))
        
        if business_type:
            salon_query = salon_query.filter(
                Salon.business_type.ilike(business_type)
            )
        
        # Filter to only published salons
        salon_query = salon_query.filter(Salon.is_published.is_(True))
        
        # Apply sorting
        if sort_field == "name":
            order_by = Salon.name.asc() if sort_order == "asc" else Salon.name.desc()
        else:
            order_by = Salon.created_at.asc() if sort_order == "asc" else Salon.created_at.desc()
        
        salon_query = salon_query.order_by(order_by)
        
        # Get total count for pagination
        total_count = salon_query.count()
        
        # Apply pagination
        salons = salon_query.limit(limit).offset((page - 1) * limit).all()
        
        # Build response with pagination metadata
        payload = {
            "salons": [salon.to_dict() for salon in salons],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total_count,
                "pages": (total_count + limit - 1) // limit,
            },
            "filters": {
                "query": query,
                "city": city,
                "business_type": business_type,
                "sort": sort_field,
                "order": sort_order,
            }
        }
        return jsonify(payload), 200
        
    except (ValueError, TypeError) as exc:
        current_app.logger.warning(f"Invalid pagination parameters: {exc}")
        return jsonify({"error": "invalid_parameters"}), 400
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch salons", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/salons/<int:salon_id>")
def get_salon_details(salon_id: int) -> tuple[dict[str, object], int]:
    """Get full salon details including services and staff (UC 2.6)."""
    try:
        # Fetch salon with vendor details
        salon = (
            Salon.query.options(joinedload(Salon.vendor))
            .filter(Salon.salon_id == salon_id)
            .first()
        )
        
        if not salon:
            return jsonify({"error": "salon_not_found"}), 404
        
        # Fetch all services for this salon
        services = Service.query.filter(Service.salon_id == salon_id).all()
        
        # Fetch all staff members for this salon
        staff_members = (
            Staff.query.options(joinedload(Staff.user))
            .filter(Staff.salon_id == salon_id)
            .all()
        )
        
        # Build response with salon details
        salon_data = salon.to_dict()
        salon_data["services"] = [service.to_dict() for service in services]
        salon_data["staff"] = [member.to_dict() for member in staff_members]
        
        # Placeholder for ratings (reviews not yet implemented)
        salon_data["average_rating"] = 4.5
        salon_data["total_reviews"] = 0
        
        return jsonify({"salon": salon_data}), 200
        
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch salon details", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


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


@bp.put("/salons/<int:salon_id>/verify")
def submit_for_verification(salon_id: int):
    """Vendor submits their salon for verification."""
    payload = request.get_json(silent=True) or {}
    business_tin = (payload.get("business_tin") or "").strip()

    if not business_tin:
        return jsonify({"error": "invalid_payload", "message": "business_tin is required"}), 400

    salon = Salon.query.get(salon_id)
    if not salon:
        return jsonify({"error": "not_found", "message": "Salon not found"}), 404

    # In production: ensure current user matches salon.vendor_id
    try:
        salon.business_tin = business_tin
        salon.verification_status = "pending"
        db.session.commit()
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to submit for verification", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

    return jsonify({
        "message": "Verification request submitted successfully.",
        "salon": salon.to_dict(),
    }), 200


# --- BEGIN: Client Use Case 2.1 ---


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


# --- END: Client Use Case 2.1 ---

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


# --- BEGIN: Vendor Use Case 1.6 - Staff Management ---

@bp.get("/salons/<int:salon_id>/staff")
def list_staff(salon_id: int) -> tuple[dict[str, list[dict[str, object]]], int]:
    """Get all staff members for a specific salon."""
    try:
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({"error": "not_found", "message": "Salon not found"}), 404

        staff_members = Staff.query.filter_by(salon_id=salon_id).all()
        payload = {"staff": [member.to_dict() for member in staff_members]}
        return jsonify(payload), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch staff members", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.post("/salons/<int:salon_id>/staff")
def create_staff(salon_id: int) -> tuple[dict[str, object], int]:
    """Create a new staff member for a salon."""
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or "").strip()

    if not title:
        return (
            jsonify({"error": "invalid_payload", "message": "title is required"}),
            400,
        )

    # Verify salon exists
    salon = Salon.query.get(salon_id)
    if not salon:
        return jsonify({"error": "not_found", "message": "Salon not found"}), 404

    try:
        new_staff = Staff(
            salon_id=salon_id,
            user_id=payload.get("user_id"),
            title=title,
        )
        db.session.add(new_staff)
        db.session.commit()

        return jsonify({"staff": new_staff.to_dict()}), 201

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to create staff member", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.put("/salons/<int:salon_id>/staff/<int:staff_id>")
def update_staff(salon_id: int, staff_id: int) -> tuple[dict[str, object], int]:
    """Update a staff member."""
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or "").strip()

    if not title:
        return (
            jsonify({"error": "invalid_payload", "message": "title is required"}),
            400,
        )

    try:
        staff = Staff.query.filter_by(staff_id=staff_id, salon_id=salon_id).first()
        if not staff:
            return jsonify({"error": "not_found", "message": "Staff member not found"}), 404

        staff.title = title
        if "user_id" in payload:
            staff.user_id = payload.get("user_id")

        db.session.commit()

        return jsonify({"staff": staff.to_dict()}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update staff member", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.delete("/salons/<int:salon_id>/staff/<int:staff_id>")
def delete_staff(salon_id: int, staff_id: int) -> tuple[dict[str, str], int]:
    """Delete a staff member."""
    try:
        staff = Staff.query.filter_by(staff_id=staff_id, salon_id=salon_id).first()
        if not staff:
            return jsonify({"error": "not_found", "message": "Staff member not found"}), 404

        db.session.delete(staff)
        db.session.commit()

        return jsonify({"message": "Staff member deleted successfully"}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to delete staff member", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.put("/salons/<int:salon_id>/staff/<int:staff_id>/schedule")
def update_staff_schedule(salon_id: int, staff_id: int) -> tuple[dict[str, object], int]:
    """Update a staff member's schedule."""
    payload = request.get_json(silent=True) or {}
    schedule = payload.get("schedule")

    if schedule is None:
        return (
            jsonify({"error": "invalid_payload", "message": "schedule is required"}),
            400,
        )

    try:
        staff = Staff.query.filter_by(staff_id=staff_id, salon_id=salon_id).first()
        if not staff:
            return jsonify({"error": "not_found", "message": "Staff member not found"}), 404

        staff.schedule = schedule
        db.session.commit()

        return jsonify({"staff": staff.to_dict()}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update staff schedule", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

# --- END: Vendor Use Case 1.6 - Staff Management ---


# --- BEGIN: Vendor Use Case 1.7 - Set Staff Schedules ---

@bp.get("/staff/<int:staff_id>/schedules")
def get_staff_schedules(staff_id: int) -> tuple[dict[str, list[dict[str, object]]], int]:
    """Get all weekly schedules for a staff member."""
    try:
        staff = Staff.query.get(staff_id)
        if not staff:
            return jsonify({"error": "not_found", "message": "Staff member not found"}), 404

        from .models import Schedule
        schedules = Schedule.query.filter_by(staff_id=staff_id).all()
        payload = {"schedules": [schedule.to_dict() for schedule in schedules]}
        return jsonify(payload), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch schedules", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.post("/staff/<int:staff_id>/schedules")
def create_staff_schedule(staff_id: int) -> tuple[dict[str, object], int]:
    """Create a new weekly schedule entry for a staff member."""
    payload = request.get_json(silent=True) or {}
    day_of_week = payload.get("day_of_week")
    start_time = payload.get("start_time")
    end_time = payload.get("end_time")

    if day_of_week is None or not start_time or not end_time:
        return (
            jsonify({
                "error": "invalid_payload",
                "message": "day_of_week, start_time, and end_time are required"
            }),
            400,
        )

    try:
        staff = Staff.query.get(staff_id)
        if not staff:
            return jsonify({"error": "not_found", "message": "Staff member not found"}), 404

        from datetime import datetime
        from .models import Schedule

        # Parse time strings (format: "HH:MM")
        start_dt = datetime.strptime(start_time, "%H:%M")
        end_dt = datetime.strptime(end_time, "%H:%M")

        new_schedule = Schedule(
            staff_id=staff_id,
            day_of_week=day_of_week,
            start_time=start_dt.time(),
            end_time=end_dt.time(),
        )
        db.session.add(new_schedule)
        db.session.commit()

        return jsonify({"schedule": new_schedule.to_dict()}), 201

    except ValueError:
        return (
            jsonify({
                "error": "invalid_format",
                "message": "Time format must be HH:MM"
            }),
            400,
        )
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to create schedule", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.put("/staff/<int:staff_id>/schedules/<int:schedule_id>")
def update_weekly_schedule(staff_id: int, schedule_id: int) -> tuple[dict[str, object], int]:
    """Update a weekly schedule entry for a staff member."""
    payload = request.get_json(silent=True) or {}
    day_of_week = payload.get("day_of_week")
    start_time = payload.get("start_time")
    end_time = payload.get("end_time")

    try:
        from datetime import datetime
        from .models import Schedule

        schedule = Schedule.query.filter_by(schedule_id=schedule_id, staff_id=staff_id).first()
        if not schedule:
            return jsonify({"error": "not_found", "message": "Schedule not found"}), 404

        if day_of_week is not None:
            schedule.day_of_week = day_of_week
        if start_time:
            start_dt = datetime.strptime(start_time, "%H:%M")
            schedule.start_time = start_dt.time()
        if end_time:
            end_dt = datetime.strptime(end_time, "%H:%M")
            schedule.end_time = end_dt.time()

        db.session.commit()
        return jsonify({"schedule": schedule.to_dict()}), 200

    except ValueError:
        return (
            jsonify({
                "error": "invalid_format",
                "message": "Time format must be HH:MM"
            }),
            400,
        )
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update schedule", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.delete("/staff/<int:staff_id>/schedules/<int:schedule_id>")
def delete_staff_schedule(staff_id: int, schedule_id: int) -> tuple[dict[str, str], int]:
    """Delete a weekly schedule entry for a staff member."""
    try:
        from .models import Schedule

        schedule = Schedule.query.filter_by(schedule_id=schedule_id, staff_id=staff_id).first()
        if not schedule:
            return jsonify({"error": "not_found", "message": "Schedule not found"}), 404

        db.session.delete(schedule)
        db.session.commit()

        return jsonify({"message": "Schedule deleted successfully"}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to delete schedule", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/staff/<int:staff_id>/time-blocks")
def get_staff_time_blocks(staff_id: int) -> tuple[dict[str, list[dict[str, object]]], int]:
    """Get all time blocks (breaks, holidays) for a staff member."""
    try:
        staff = Staff.query.get(staff_id)
        if not staff:
            return jsonify({"error": "not_found", "message": "Staff member not found"}), 404

        from .models import TimeBlock
        time_blocks = TimeBlock.query.filter_by(staff_id=staff_id).all()
        payload = {"time_blocks": [block.to_dict() for block in time_blocks]}
        return jsonify(payload), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch time blocks", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.post("/staff/<int:staff_id>/time-blocks")
def create_staff_time_block(staff_id: int) -> tuple[dict[str, object], int]:
    """Create a new time block for a staff member."""
    payload = request.get_json(silent=True) or {}
    starts_at = payload.get("starts_at")
    ends_at = payload.get("ends_at")
    reason = payload.get("reason")

    if not starts_at or not ends_at:
        return (
            jsonify({
                "error": "invalid_payload",
                "message": "starts_at and ends_at are required"
            }),
            400,
        )

    try:
        staff = Staff.query.get(staff_id)
        if not staff:
            return jsonify({"error": "not_found", "message": "Staff member not found"}), 404

        from datetime import datetime
        from .models import TimeBlock

        # Parse ISO datetime strings
        start_dt = datetime.fromisoformat(starts_at)
        end_dt = datetime.fromisoformat(ends_at)

        new_block = TimeBlock(
            staff_id=staff_id,
            starts_at=start_dt,
            ends_at=end_dt,
            reason=reason or None,
        )
        db.session.add(new_block)
        db.session.commit()

        return jsonify({"time_block": new_block.to_dict()}), 201

    except ValueError:
        return (
            jsonify({
                "error": "invalid_format",
                "message": "DateTime format must be ISO format (YYYY-MM-DDTHH:MM:SS)"
            }),
            400,
        )
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to create time block", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.delete("/staff/<int:staff_id>/time-blocks/<int:block_id>")
def delete_staff_time_block(staff_id: int, block_id: int) -> tuple[dict[str, str], int]:
    """Delete a time block for a staff member."""
    try:
        from .models import TimeBlock

        block = TimeBlock.query.filter_by(block_id=block_id, staff_id=staff_id).first()
        if not block:
            return jsonify({"error": "not_found", "message": "Time block not found"}), 404

        db.session.delete(block)
        db.session.commit()

        return jsonify({"message": "Time block deleted successfully"}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to delete time block", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

# --- END: Vendor Use Case 1.7 - Set Staff Schedules ---

# --- START: Client Use Case 2.2 - Browse Available Services ---


@bp.get("/salons/<int:salon_id>/services")
def list_services(salon_id: int) -> tuple[dict[str, list[dict[str, object]]], int]:
    """Get all services for a salon."""
    try:
        from .models import Service

        # Verify salon exists
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({"error": "not_found", "message": "Salon not found"}), 404

        services = Service.query.filter_by(salon_id=salon_id).order_by(Service.created_at.desc()).all()
        payload = {"services": [service.to_dict() for service in services]}
        return jsonify(payload), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch services", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.post("/salons/<int:salon_id>/services")
def create_service(salon_id: int) -> tuple[dict[str, object], int]:
    """Create a new service for a salon (vendor only)."""
    try:
        from .models import Service

        payload = request.get_json(silent=True) or {}

        # Verify salon exists
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({"error": "not_found", "message": "Salon not found"}), 404

        # Extract fields
        name = (payload.get("name") or "").strip()
        description = (payload.get("description") or "").strip() or None
        price_cents = payload.get("price_cents")
        duration_minutes = payload.get("duration_minutes")

        # Validate required fields
        if not name or price_cents is None or duration_minutes is None:
            return (
                jsonify({
                    "error": "invalid_payload",
                    "message": "name, price_cents, and duration_minutes are required"
                }),
                400,
            )

        # Validate numeric fields
        try:
            price_cents = int(price_cents)
            duration_minutes = int(duration_minutes)
            if price_cents < 0 or duration_minutes <= 0:
                raise ValueError("Invalid values")
        except (ValueError, TypeError):
            return (
                jsonify({
                    "error": "invalid_payload",
                    "message": "price_cents must be >= 0 and duration_minutes must be > 0"
                }),
                400,
            )

        # Create service
        new_service = Service(
            salon_id=salon_id,
            name=name,
            description=description,
            price_cents=price_cents,
            duration_minutes=duration_minutes,
        )
        db.session.add(new_service)
        db.session.commit()

        return jsonify({"message": "Service created successfully", "service": new_service.to_dict()}), 201

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to create service", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.put("/salons/<int:salon_id>/services/<int:service_id>")
def update_service(salon_id: int, service_id: int) -> tuple[dict[str, object], int]:
    """Update a service for a salon (vendor only)."""
    try:
        from .models import Service

        payload = request.get_json(silent=True) or {}

        # Verify service exists and belongs to salon
        service = Service.query.filter_by(service_id=service_id, salon_id=salon_id).first()
        if not service:
            return jsonify({"error": "not_found", "message": "Service not found"}), 404

        # Update fields
        if "name" in payload:
            service.name = (payload.get("name") or "").strip()
        if "description" in payload:
            service.description = (payload.get("description") or "").strip() or None
        if "price_cents" in payload:
            try:
                service.price_cents = int(payload.get("price_cents"))
                if service.price_cents < 0:
                    raise ValueError("price_cents must be >= 0")
            except (ValueError, TypeError):
                return (
                    jsonify({
                        "error": "invalid_payload",
                        "message": "price_cents must be a non-negative integer"
                    }),
                    400,
                )
        if "duration_minutes" in payload:
            try:
                service.duration_minutes = int(payload.get("duration_minutes"))
                if service.duration_minutes <= 0:
                    raise ValueError("duration_minutes must be > 0")
            except (ValueError, TypeError):
                return (
                    jsonify({
                        "error": "invalid_payload",
                        "message": "duration_minutes must be a positive integer"
                    }),
                    400,
                )

        db.session.commit()
        return jsonify({"message": "Service updated successfully", "service": service.to_dict()}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update service", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.delete("/salons/<int:salon_id>/services/<int:service_id>")
def delete_service(salon_id: int, service_id: int) -> tuple[dict[str, str], int]:
    """Delete a service from a salon (vendor only)."""
    try:
        from .models import Service

        service = Service.query.filter_by(service_id=service_id, salon_id=salon_id).first()
        if not service:
            return jsonify({"error": "not_found", "message": "Service not found"}), 404

        db.session.delete(service)
        db.session.commit()

        return jsonify({"message": "Service deleted successfully"}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to delete service", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

# --- END: Client Use Case 2.2 - Browse Available Services ---

# --- START: Client Use Case 2.3 - Book Appointments ---


@bp.get("/appointments")
def list_appointments() -> tuple[dict[str, list[dict[str, object]]], int]:
    """Get all appointments for the authenticated user (client or vendor)."""
    try:
        from .models import Appointment

        # For now, return all appointments. In production, filter by user role
        appointments = Appointment.query.order_by(Appointment.starts_at.desc()).all()
        payload = {"appointments": [appt.to_dict() for appt in appointments]}
        return jsonify(payload), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch appointments", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.post("/appointments")
def create_appointment() -> tuple[dict[str, object], int]:
    """Create a new appointment."""
    try:
        from datetime import datetime as dt
        from .models import Appointment, Staff, Service

        payload = request.get_json(silent=True) or {}

        # Extract fields
        salon_id = payload.get("salon_id")
        staff_id = payload.get("staff_id")
        service_id = payload.get("service_id")
        client_id = payload.get("client_id")
        starts_at_str = payload.get("starts_at")
        notes = (payload.get("notes") or "").strip() or None

        # Validate required fields
        if not all([salon_id, staff_id, service_id, client_id, starts_at_str]):
            return (
                jsonify({
                    "error": "invalid_payload",
                    "message": "salon_id, staff_id, service_id, client_id, and starts_at are required"
                }),
                400,
            )

        # Parse datetime
        try:
            starts_at = dt.fromisoformat(starts_at_str)
        except (ValueError, TypeError):
            return (
                jsonify({
                    "error": "invalid_payload",
                    "message": "starts_at must be a valid ISO format datetime"
                }),
                400,
            )

        # Get service to calculate duration
        service = Service.query.get(service_id)
        if not service:
            return jsonify({"error": "not_found", "message": "Service not found"}), 404

        # Calculate end time
        from datetime import timedelta
        ends_at = starts_at + timedelta(minutes=service.duration_minutes)

        # Check if staff exists
        staff = Staff.query.get(staff_id)
        if not staff:
            return jsonify({"error": "not_found", "message": "Staff not found"}), 404

        # Check for conflicts with existing appointments
        conflicting = Appointment.query.filter(
            Appointment.staff_id == staff_id,
            Appointment.status != "cancelled",
            Appointment.starts_at < ends_at,
            Appointment.ends_at > starts_at,
        ).first()

        if conflicting:
            return (
                jsonify({
                    "error": "conflict",
                    "message": "Staff member has a conflicting appointment"
                }),
                409,
            )

        # Create appointment
        new_appointment = Appointment(
            salon_id=salon_id,
            staff_id=staff_id,
            service_id=service_id,
            client_id=client_id,
            starts_at=starts_at,
            ends_at=ends_at,
            notes=notes,
        )
        db.session.add(new_appointment)
        db.session.commit()

        # UC 2.5: Create notification for appointment confirmation
        notification = Notification(
            user_id=client_id,
            appointment_id=new_appointment.appointment_id,
            title="Appointment Confirmed",
            message=f"Your appointment at {staff.name}'s salon has been confirmed for {starts_at.strftime('%B %d, %Y at %I:%M %p')}.",
            notification_type="appointment_confirmed",
        )
        db.session.add(notification)
        db.session.commit()

        return jsonify({"message": "Appointment created successfully", "appointment": new_appointment.to_dict()}), 201

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to create appointment", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.put("/appointments/<int:appointment_id>")
def update_appointment(appointment_id: int) -> tuple[dict[str, object], int]:
    """Update an appointment."""
    try:
        from datetime import datetime as dt, timedelta
        from .models import Appointment, Service

        payload = request.get_json(silent=True) or {}

        appointment = Appointment.query.get(appointment_id)
        if not appointment:
            return jsonify({"error": "not_found", "message": "Appointment not found"}), 404

        # Update fields
        if "starts_at" in payload:
            try:
                appointment.starts_at = dt.fromisoformat(payload["starts_at"])
                # Recalculate end time based on service duration
                service = Service.query.get(appointment.service_id)
                if service:
                    appointment.ends_at = appointment.starts_at + timedelta(minutes=service.duration_minutes)
            except (ValueError, TypeError):
                return (
                    jsonify({
                        "error": "invalid_payload",
                        "message": "starts_at must be a valid ISO format datetime"
                    }),
                    400,
                )

        if "notes" in payload:
            appointment.notes = (payload.get("notes") or "").strip() or None

        if "status" in payload:
            status = payload.get("status")
            if status not in ["booked", "completed", "cancelled", "no-show"]:
                return (
                    jsonify({
                        "error": "invalid_payload",
                        "message": "status must be one of: booked, completed, cancelled, no-show"
                    }),
                    400,
                )
            appointment.status = status

        db.session.commit()
        return jsonify({"message": "Appointment updated successfully", "appointment": appointment.to_dict()}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update appointment", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/appointments/<int:appointment_id>")
def get_appointment(appointment_id: int) -> tuple[dict[str, dict[str, object]], int]:
    """Get appointment details with related information."""
    try:
        from .models import Appointment

        appointment = Appointment.query.get(appointment_id)
        if not appointment:
            return jsonify({"error": "not_found", "message": "Appointment not found"}), 404

        # Build detailed response with related objects
        appointment_data = appointment.to_dict()

        # Add related object details
        if appointment.salon_id:
            salon = appointment.salon
            appointment_data["salon"] = {
                "id": salon.salon_id,
                "name": salon.name,
                "address": salon.address_line1,
                "city": salon.city,
                "state": salon.state,
                "phone": salon.phone,
            }

        if appointment.staff_id:
            staff = appointment.staff
            appointment_data["staff"] = {
                "staff_id": staff.staff_id,
                "title": staff.title,
                "user": {"id": staff.user.user_id, "name": staff.user.name} if staff.user else None,
            }

        if appointment.service_id:
            service = appointment.service
            appointment_data["service"] = {
                "id": service.service_id,
                "name": service.name,
                "description": service.description,
                "price_cents": service.price_cents,
                "price_dollars": service.price_cents / 100.0,
                "duration_minutes": service.duration_minutes,
            }

        if appointment.client_id:
            client = appointment.client
            appointment_data["client"] = {
                "id": client.user_id,
                "name": client.name,
                "email": client.email,
            }

        return jsonify({"appointment": appointment_data}), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch appointment", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.put("/appointments/<int:appointment_id>/reschedule")
def reschedule_appointment(appointment_id: int) -> tuple[dict[str, dict[str, object]], int]:
    """Reschedule an appointment to a new date/time with conflict checking."""
    try:
        from datetime import datetime as dt, timedelta
        from .models import Appointment, Staff, TimeBlock

        appointment = Appointment.query.get(appointment_id)
        if not appointment:
            return jsonify({"error": "not_found", "message": "Appointment not found"}), 404

        # Don't allow rescheduling completed or cancelled appointments
        if appointment.status in ["completed", "cancelled", "no-show"]:
            return (
                jsonify(
                    {
                        "error": "cannot_reschedule",
                        "message": f"Cannot reschedule an appointment with status '{appointment.status}'",
                    }
                ),
                400,
            )

        data = request.get_json()

        # Require new start time
        if "starts_at" not in data:
            return (
                jsonify({"error": "invalid_input", "message": "starts_at is required"}),
                400,
            )

        try:
            new_start = dt.fromisoformat(data["starts_at"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return (
                jsonify({"error": "invalid_datetime", "message": "Invalid datetime format"}),
                400,
            )

        # Check for conflicts with new time
        staff = appointment.staff
        service = appointment.service
        new_end = new_start + timedelta(minutes=service.duration_minutes)

        # Check existing appointments
        conflicting = (
            Appointment.query.filter(
                Appointment.staff_id == appointment.staff_id,
                Appointment.appointment_id != appointment_id,  # Exclude current appointment
                Appointment.status == "booked",
                Appointment.starts_at < new_end,
                Appointment.ends_at > new_start,
            )
            .first()
        )

        if conflicting:
            return (
                jsonify(
                    {
                        "error": "conflict",
                        "message": "Time slot conflicts with another appointment",
                    }
                ),
                409,
            )

        # Check time blocks (breaks/holidays)
        timeblock_conflict = TimeBlock.query.filter(
            TimeBlock.staff_id == appointment.staff_id,
            TimeBlock.starts_at < new_end,
            TimeBlock.ends_at > new_start,
        ).first()

        if timeblock_conflict:
            return (
                jsonify(
                    {
                        "error": "blocked_time",
                        "message": f"Staff member is blocked during this time: {timeblock_conflict.reason}",
                    }
                ),
                409,
            )

        # Check schedule for staff availability
        from datetime import time as time_type

        day_of_week = new_start.weekday() + 1  # SQLAlchemy uses 1=Monday
        start_time = new_start.time()
        end_time = new_end.time()

        schedule = Schedule.query.filter(
            Schedule.staff_id == appointment.staff_id,
            Schedule.day_of_week == day_of_week,
        ).first()

        if not schedule:
            return (
                jsonify(
                    {
                        "error": "not_available",
                        "message": "Staff member is not scheduled for this day",
                    }
                ),
                400,
            )

        if not (schedule.start_time <= start_time and end_time <= schedule.end_time):
            return (
                jsonify(
                    {
                        "error": "outside_hours",
                        "message": "Appointment falls outside staff working hours",
                    }
                ),
                400,
            )

        # Update appointment
        appointment.starts_at = new_start
        appointment.ends_at = new_end
        db.session.commit()

        return jsonify({"appointment": appointment.to_dict()}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to reschedule appointment", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.delete("/appointments/<int:appointment_id>")
def delete_appointment(appointment_id: int) -> tuple[dict[str, object], int]:
    """Cancel an appointment by setting status to 'cancelled'."""
    try:
        from .models import Appointment

        appointment = Appointment.query.get(appointment_id)
        if not appointment:
            return jsonify({"error": "not_found", "message": "Appointment not found"}), 404

        # Don't allow cancelling already completed or no-show appointments
        if appointment.status in ["completed", "no-show"]:
            return (
                jsonify(
                    {
                        "error": "cannot_cancel",
                        "message": f"Cannot cancel an appointment with status '{appointment.status}'",
                    }
                ),
                400,
            )

        appointment.status = "cancelled"
        db.session.commit()

        return jsonify({"message": "Appointment cancelled successfully", "appointment": appointment.to_dict()}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to cancel appointment", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/staff/<int:staff_id>/availability")
def check_staff_availability(staff_id: int) -> tuple[dict[str, object], int]:
    """Check available time slots for a staff member on a given date."""
    try:
        from datetime import datetime as dt, timedelta, time
        from .models import Staff, Schedule, TimeBlock, Appointment

        # Get query parameters
        date_str = request.args.get("date")
        duration_minutes = request.args.get("duration_minutes", type=int)

        if not date_str or not duration_minutes:
            return (
                jsonify({
                    "error": "invalid_payload",
                    "message": "date (YYYY-MM-DD) and duration_minutes are required"
                }),
                400,
            )

        # Parse date
        try:
            target_date = dt.fromisoformat(date_str).date()
        except (ValueError, TypeError):
            return (
                jsonify({
                    "error": "invalid_payload",
                    "message": "date must be in YYYY-MM-DD format"
                }),
                400,
            )

        # Verify staff exists
        staff = Staff.query.get(staff_id)
        if not staff:
            return jsonify({"error": "not_found", "message": "Staff not found"}), 404

        # Get staff's schedule for this day of week
        day_of_week = target_date.weekday()
        # Convert Python weekday (0=Mon) to database format (0=Sun)
        day_of_week = (day_of_week + 1) % 7

        schedules = Schedule.query.filter_by(staff_id=staff_id, day_of_week=day_of_week).all()
        if not schedules:
            return jsonify({"available_slots": []}), 200

        # Get time blocks (breaks, holidays) for this day
        start_of_day = dt.combine(target_date, time.min)
        end_of_day = dt.combine(target_date, time.max)

        time_blocks = TimeBlock.query.filter(
            TimeBlock.staff_id == staff_id,
            TimeBlock.starts_at <= end_of_day,
            TimeBlock.ends_at >= start_of_day,
        ).all()

        # Get existing appointments for this day
        appointments = Appointment.query.filter(
            Appointment.staff_id == staff_id,
            Appointment.status != "cancelled",
            Appointment.starts_at >= start_of_day,
            Appointment.ends_at <= end_of_day,
        ).all()

        # Generate available slots (30-minute intervals)
        available_slots = []
        for schedule in schedules:
            current_time = dt.combine(target_date, schedule.start_time)
            end_time = dt.combine(target_date, schedule.end_time)

            while current_time + timedelta(minutes=duration_minutes) <= end_time:
                slot_end = current_time + timedelta(minutes=duration_minutes)

                # Check if slot conflicts with time blocks
                blocked = any(
                    tb.starts_at <= current_time and tb.ends_at > current_time or
                    tb.starts_at < slot_end and tb.ends_at >= slot_end
                    for tb in time_blocks
                )

                # Check if slot conflicts with appointments
                conflicting = any(
                    a.starts_at <= current_time and a.ends_at > current_time or
                    a.starts_at < slot_end and a.ends_at >= slot_end
                    for a in appointments
                )

                if not blocked and not conflicting:
                    available_slots.append(current_time.isoformat())

                current_time += timedelta(minutes=30)

        return jsonify({"available_slots": available_slots}), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to check availability", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/salons/<int:salon_id>/appointments")
def list_salon_appointments(salon_id: int) -> tuple[dict[str, object], int]:
    """Get all appointments for a specific salon (vendor view)."""
    try:
        from .models import Appointment, Salon

        # Verify salon exists
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({"error": "not_found", "message": "Salon not found"}), 404

        # Get query parameters for filtering
        status = request.args.get("status")  # 'booked', 'completed', 'cancelled', 'no-show'
        date_str = request.args.get("date")  # YYYY-MM-DD

        query = Appointment.query.filter_by(salon_id=salon_id)

        # Filter by status if provided
        if status:
            valid_statuses = ["booked", "completed", "cancelled", "no-show"]
            if status in valid_statuses:
                query = query.filter_by(status=status)

        # Filter by date if provided
        if date_str:
            try:
                from datetime import datetime as dt, date as date_type

                date_obj = dt.strptime(date_str, "%Y-%m-%d").date()
                next_day = date_type.today() if date_obj == date_type.today() else date_obj
                from datetime import timedelta

                day_start = dt.combine(date_obj, dt.min.time())
                day_end = dt.combine(date_obj, dt.max.time())

                query = query.filter(Appointment.starts_at >= day_start, Appointment.starts_at <= day_end)
            except ValueError:
                return jsonify({"error": "invalid_date", "message": "Date must be in YYYY-MM-DD format"}), 400

        # Sort by start time (upcoming first)
        appointments = query.order_by(Appointment.starts_at.desc()).all()

        payload = {"appointments": [appt.to_dict() for appt in appointments]}
        return jsonify(payload), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch salon appointments", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.put("/appointments/<int:appointment_id>/status")
def update_appointment_status(appointment_id: int) -> tuple[dict[str, object], int]:
    """Update appointment status (vendor can change booked→completed, no-show, etc).
    
    When appointment is marked as 'completed', automatically award loyalty points
    to the client based on the service cost (1 point per dollar).
    """
    try:
        from .models import Appointment, ClientLoyalty

        appointment = Appointment.query.get(appointment_id)
        if not appointment:
            return jsonify({"error": "not_found", "message": "Appointment not found"}), 404

        data = request.get_json()

        if "status" not in data:
            return jsonify({"error": "invalid_input", "message": "status is required"}), 400

        new_status = data["status"]
        valid_statuses = ["booked", "completed", "cancelled", "no-show"]

        if new_status not in valid_statuses:
            return (
                jsonify(
                    {
                        "error": "invalid_status",
                        "message": f"Status must be one of: {', '.join(valid_statuses)}",
                    }
                ),
                400,
            )

        # Prevent status transitions that don't make sense
        if appointment.status == "cancelled" and new_status != "cancelled":
            return (
                jsonify(
                    {
                        "error": "invalid_transition",
                        "message": "Cannot change status of a cancelled appointment",
                    }
                ),
                400,
            )

        if appointment.status == "completed" and new_status not in ["completed"]:
            return (
                jsonify(
                    {
                        "error": "invalid_transition",
                        "message": "Cannot change status of a completed appointment",
                    }
                ),
                400,
            )

        # UC 2.11: Award loyalty points when appointment is completed
        if appointment.status != "completed" and new_status == "completed":
            # Calculate points (1 point per dollar of service cost)
            points_earned = int(appointment.service.price_cents / 100) if appointment.service and appointment.service.price_cents else 0
            
            if points_earned > 0:
                # Get or create loyalty record for this client-salon combination
                loyalty = ClientLoyalty.query.filter_by(
                    client_id=appointment.client_id,
                    salon_id=appointment.salon_id
                ).first()
                
                if loyalty:
                    loyalty.points_balance += points_earned
                else:
                    # Create new loyalty record for this client at this salon
                    loyalty = ClientLoyalty(
                        client_id=appointment.client_id,
                        salon_id=appointment.salon_id,
                        points_balance=points_earned
                    )
                    db.session.add(loyalty)

        appointment.status = new_status
        db.session.commit()

        # UC 2.5: Create notifications based on status change
        if new_status == "completed":
            notification = Notification(
                user_id=appointment.client_id,
                appointment_id=appointment.appointment_id,
                title="Appointment Completed",
                message=f"Your appointment at {appointment.staff.name}'s salon has been completed. You earned {points_earned} loyalty points!",
                notification_type="appointment_completed",
            )
            db.session.add(notification)
        elif new_status == "cancelled":
            notification = Notification(
                user_id=appointment.client_id,
                appointment_id=appointment.appointment_id,
                title="Appointment Cancelled",
                message=f"Your appointment at {appointment.staff.name}'s salon has been cancelled.",
                notification_type="appointment_cancelled",
            )
            db.session.add(notification)
        elif new_status == "no-show":
            notification = Notification(
                user_id=appointment.client_id,
                appointment_id=appointment.appointment_id,
                title="Appointment No-Show",
                message=f"You missed your appointment at {appointment.staff.name}'s salon.",
                notification_type="appointment_cancelled",
            )
            db.session.add(notification)
        
        if new_status in ["completed", "cancelled", "no-show"]:
            db.session.commit()

        return jsonify({"appointment": appointment.to_dict()}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update appointment status", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


# ============================================================================
# Reviews Endpoints (UC 2.8)
# ============================================================================

@bp.get("/salons/<int:salon_id>/reviews")
def get_salon_reviews(salon_id: int) -> tuple[dict[str, object], int]:
    """Get reviews for a salon with filtering, sorting, and pagination (UC 2.9).
    
    Query Parameters:
    - sort_by: 'rating' or 'date' (default: 'date')
    - order: 'asc' or 'desc' (default: 'desc')
    - min_rating: Filter reviews by minimum rating (1-5, optional)
    - limit: Max reviews to return (default: 50, max: 100)
    - offset: Pagination offset (default: 0)
    """
    try:
        # Check if salon exists
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({"error": "salon_not_found"}), 404

        # Get query parameters
        sort_by = request.args.get('sort_by', 'date')  # 'rating' or 'date'
        order = request.args.get('order', 'desc')  # 'asc' or 'desc'
        min_rating = request.args.get('min_rating', type=int)
        limit = request.args.get('limit', default=50, type=int)
        offset = request.args.get('offset', default=0, type=int)
        
        # Validate and constrain parameters
        if sort_by not in ['rating', 'date']:
            sort_by = 'date'
        if order not in ['asc', 'desc']:
            order = 'desc'
        if min_rating and (min_rating < 1 or min_rating > 5):
            min_rating = None
        limit = min(max(limit, 1), 100)  # Between 1 and 100
        offset = max(offset, 0)

        # Build query
        query = Review.query.filter(Review.salon_id == salon_id)
        
        # Apply minimum rating filter
        if min_rating:
            query = query.filter(Review.rating >= min_rating)
        
        # Get total count before pagination
        total_count = query.count()
        
        # Apply sorting
        if sort_by == 'rating':
            sort_column = Review.rating
        else:  # date
            sort_column = Review.created_at
        
        if order == 'asc':
            query = query.order_by(sort_column.asc())
        else:
            query = query.order_by(sort_column.desc())
        
        # Apply pagination
        reviews = query.limit(limit).offset(offset).all()

        # Calculate average rating (from ALL reviews, not just filtered)
        all_reviews = Review.query.filter(Review.salon_id == salon_id).all()
        if all_reviews:
            avg_rating = sum(r.rating for r in all_reviews) / len(all_reviews)
        else:
            avg_rating = 0

        payload = {
            "reviews": [review.to_dict() for review in reviews],
            "average_rating": round(avg_rating, 1),
            "total_reviews": len(all_reviews),
            "filtered_count": total_count,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total": total_count,
                "has_more": (offset + limit) < total_count
            }
        }
        return jsonify(payload), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch salon reviews", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.post("/salons/<int:salon_id>/reviews")
def create_review(salon_id: int) -> tuple[dict[str, object], int]:
    """Create a new review for a salon (UC 2.8)."""
    try:
        payload = request.get_json(silent=True) or {}

        # Validate required fields
        client_id = payload.get("client_id")
        rating = payload.get("rating")
        comment = (payload.get("comment") or "").strip() or None

        if not client_id or not rating:
            return (
                jsonify({
                    "error": "invalid_payload",
                    "message": "client_id and rating are required"
                }),
                400,
            )

        # Validate rating range
        if not isinstance(rating, int) or rating < 1 or rating > 5:
            return (
                jsonify({
                    "error": "invalid_rating",
                    "message": "Rating must be an integer between 1 and 5"
                }),
                400,
            )

        # Check if salon exists
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({"error": "salon_not_found"}), 404

        # Check if client exists
        client = User.query.get(client_id)
        if not client:
            return jsonify({"error": "client_not_found"}), 404

        # Create review
        review = Review(
            salon_id=salon_id,
            client_id=client_id,
            rating=rating,
            comment=comment,
        )

        db.session.add(review)
        db.session.commit()

        return jsonify({"review": review.to_dict()}), 201

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to create review", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.put("/reviews/<int:review_id>")
def update_review(review_id: int) -> tuple[dict[str, object], int]:
    """Update an existing review (UC 2.8)."""
    try:
        review = Review.query.get(review_id)
        if not review:
            return jsonify({"error": "review_not_found"}), 404

        payload = request.get_json(silent=True) or {}

        # Update rating if provided
        if "rating" in payload:
            rating = payload.get("rating")
            if not isinstance(rating, int) or rating < 1 or rating > 5:
                return (
                    jsonify({
                        "error": "invalid_rating",
                        "message": "Rating must be an integer between 1 and 5"
                    }),
                    400,
                )
            review.rating = rating

        # Update comment if provided
        if "comment" in payload:
            comment = (payload.get("comment") or "").strip() or None
            review.comment = comment

        db.session.commit()

        return jsonify({"review": review.to_dict()}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update review", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.delete("/reviews/<int:review_id>")
def delete_review(review_id: int) -> tuple[dict[str, str], int]:
    """Delete a review (UC 2.8)."""
    try:
        review = Review.query.get(review_id)
        if not review:
            return jsonify({"error": "review_not_found"}), 404

        db.session.delete(review)
        db.session.commit()

        return jsonify({"message": "Review deleted successfully"}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to delete review", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

# --- END: Client Use Case 2.3 - Book Appointments ---

# ============================================================================
# UC 2.10 - Check Loyalty Points
# ============================================================================

@bp.get("/users/<int:user_id>/loyalty")
def get_user_loyalty(user_id: int) -> tuple[dict[str, object], int]:
    """Get loyalty points summary for a user across all salons (UC 2.10)."""
    try:
        from .models import ClientLoyalty
        
        # Verify user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "user_not_found"}), 404
        
        # Get all loyalty records for this user
        loyalty_records = ClientLoyalty.query.filter_by(client_id=user_id).all()
        
        # Calculate totals
        total_points = sum(record.points_balance for record in loyalty_records)
        total_salons = len(loyalty_records)
        
        # Build response with loyalty summary
        payload = {
            "user_id": user_id,
            "total_points": total_points,
            "total_salons": total_salons,
            "loyalty_by_salon": [
                {
                    "salon_id": record.salon_id,
                    "salon_name": record.salon.name if record.salon else "Unknown",
                    "points": record.points_balance
                }
                for record in loyalty_records
            ]
        }
        return jsonify(payload), 200
    
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch loyalty points", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

# ============================================================================
# UC 2.11 - View Appointment History
# ============================================================================

@bp.get("/users/<int:user_id>/appointments/history")
def get_appointment_history(user_id: int) -> tuple[dict[str, object], int]:
    """Get appointment history for a user (UC 2.11)."""
    try:
        from .models import Appointment
        
        # Verify user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "user_not_found"}), 404
        
        # Get query parameters
        status = request.args.get("status")  # Filter by status
        limit = request.args.get("limit", default=50, type=int)
        offset = request.args.get("offset", default=0, type=int)
        
        # Constrain pagination
        limit = min(max(limit, 1), 100)
        offset = max(offset, 0)
        
        # Build query for user's appointments
        query = Appointment.query.filter_by(client_id=user_id)
        
        # Filter by status if provided
        if status:
            query = query.filter(Appointment.status == status)
        
        # Get total count
        total_count = query.count()
        
        # Sort by start time (newest first)
        appointments = query.order_by(Appointment.starts_at.desc()).limit(limit).offset(offset).all()
        
        # Build response with appointment details
        payload = {
            "appointments": [
                {
                    "id": appt.appointment_id,
                    "salon_id": appt.salon_id,
                    "salon_name": appt.salon.name if appt.salon else "Unknown",
                    "service_id": appt.service_id,
                    "service_name": appt.service.name if appt.service else "Unknown",
                    "staff_id": appt.staff_id,
                    "staff_name": appt.staff.user.name if appt.staff and appt.staff.user else "Unknown",
                    "starts_at": appt.starts_at.isoformat() if appt.starts_at else None,
                    "ends_at": appt.ends_at.isoformat() if appt.ends_at else None,
                    "status": appt.status,
                    "notes": appt.notes
                }
                for appt in appointments
            ],
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total": total_count,
                "has_more": (offset + limit) < total_count
            }
        }
        return jsonify(payload), 200
    
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch appointment history", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

# ============================================================================
# UC 2.17 - Edit Profile
# ============================================================================

@bp.put("/users/<int:user_id>")
def update_user_profile(user_id: int) -> tuple[dict[str, object], int]:
    """Update user profile information (UC 2.17)."""
    try:
        from .models import AuthAccount
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "user_not_found"}), 404
        
        payload = request.get_json(silent=True) or {}
        
        # Update name if provided
        if "name" in payload:
            name = (payload.get("name") or "").strip()
            if not name:
                return jsonify({"error": "invalid_payload", "message": "name cannot be blank"}), 400
            user.name = name
        
        # Update phone if provided
        if "phone" in payload:
            phone = (payload.get("phone") or "").strip() or None
            user.phone = phone
        
        # Update password if provided
        if "new_password" in payload:
            new_password = payload.get("new_password") or ""
            if not new_password:
                return jsonify({"error": "invalid_payload", "message": "new_password cannot be blank"}), 400
            
            if len(new_password) < 6:
                return jsonify({"error": "invalid_password", "message": "password must be at least 6 characters"}), 400
            
            # Update password hash
            auth_account = AuthAccount.query.filter_by(user_id=user_id).first()
            if not auth_account:
                return jsonify({"error": "auth_account_not_found"}), 404
            
            auth_account.password_hash = generate_password_hash(new_password)
            db.session.add(auth_account)
        
        # Update timestamp
        user.updated_at = datetime.now(timezone.utc)
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            "message": "Profile updated successfully",
            "user": user.to_dict_basic()
        }), 200
    
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update user profile", exc_info=exc)
        return jsonify({"error": "database_error"}), 500

# ============================================================================
# UC 2.20 - Save Favorite Salons
# ============================================================================

@bp.post("/users/<int:user_id>/favorites/<int:salon_id>")
def add_favorite_salon(user_id: int, salon_id: int) -> tuple[dict[str, object], int]:
    """Add a salon to user's favorites (UC 2.20)."""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "user_not_found"}), 404
        
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({"error": "salon_not_found"}), 404
        
        # Check if already favorited
        if user.favorite_salons.filter_by(salon_id=salon_id).first():
            return jsonify({"error": "already_favorited"}), 400
        
        user.favorite_salons.append(salon)
        db.session.commit()
        
        return jsonify({
            "message": "Salon added to favorites",
            "salon_id": salon_id
        }), 201
    
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to add favorite salon", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.delete("/users/<int:user_id>/favorites/<int:salon_id>")
def remove_favorite_salon(user_id: int, salon_id: int) -> tuple[dict[str, object], int]:
    """Remove a salon from user's favorites (UC 2.20)."""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "user_not_found"}), 404
        
        salon = user.favorite_salons.filter_by(salon_id=salon_id).first()
        if not salon:
            return jsonify({"error": "not_favorited"}), 404
        
        user.favorite_salons.remove(salon)
        db.session.commit()
        
        return jsonify({
            "message": "Salon removed from favorites",
            "salon_id": salon_id
        }), 200
    
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to remove favorite salon", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/users/<int:user_id>/favorites")
def get_favorite_salons(user_id: int) -> tuple[dict[str, object], int]:
    """Get all favorite salons for a user (UC 2.20)."""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "user_not_found"}), 404
        
        # Pagination parameters
        page = request.args.get("page", 1, type=int)
        limit = request.args.get("limit", 20, type=int)
        
        if limit > 50:
            limit = 50
        
        # Query favorite salons with pagination
        query = user.favorite_salons.filter(Salon.is_published == True)
        total = query.count()
        salons = query.offset((page - 1) * limit).limit(limit).all()
        
        payload = {
            "salons": [
                {
                    "salon_id": s.salon_id,
                    "name": s.name,
                    "address": f"{s.address_line1}, {s.city}, {s.state} {s.postal_code}",
                    "phone": s.phone,
                    "description": s.description,
                    "business_type": s.business_type,
                    "vendor": {
                        "id": s.vendor_id,
                        "name": s.vendor.name if s.vendor else "Unknown"
                    }
                }
                for s in salons
            ],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "has_more": (page * limit) < total
            }
        }
        
        return jsonify(payload), 200
    
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch favorite salons", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/salons/<int:salon_id>/is-favorite")
def check_if_favorite(salon_id: int) -> tuple[dict[str, object], int]:
    """Check if a salon is favorited by the current user (UC 2.20)."""
    try:
        # Get user_id from auth context (assuming JWT token has user info)
        user_id = request.args.get("user_id", type=int)
        if not user_id:
            return jsonify({"error": "user_id_required"}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "user_not_found"}), 404
        
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({"error": "salon_not_found"}), 404
        
        is_favorited = user.favorite_salons.filter_by(salon_id=salon_id).first() is not None
        
        return jsonify({
            "salon_id": salon_id,
            "is_favorited": is_favorited
        }), 200
    
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to check favorite status", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


# ============================================================================
# UC 2.15 - View Salon Performance Analytics
# ============================================================================

@bp.get("/salons/<int:salon_id>/analytics")
def get_salon_analytics(salon_id: int) -> tuple[dict[str, object], int]:
    """Get performance analytics for a salon (UC 2.15)."""
    try:
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({"error": "salon_not_found"}), 404
        
        # Total bookings
        total_bookings = Appointment.query.filter_by(salon_id=salon_id).count()
        
        # Completed bookings
        completed_bookings = Appointment.query.filter_by(
            salon_id=salon_id, 
            status='completed'
        ).count()
        
        # Cancelled bookings
        cancelled_bookings = Appointment.query.filter_by(
            salon_id=salon_id,
            status='cancelled'
        ).count()
        
        # Average rating
        avg_rating = db.session.query(func.avg(Review.rating)).filter_by(
            salon_id=salon_id
        ).scalar() or 0.0
        
        # Total reviews
        total_reviews = Review.query.filter_by(salon_id=salon_id).count()
        
        # Services count
        services_count = Service.query.filter_by(salon_id=salon_id).count()
        
        # Booking completion rate
        completion_rate = (completed_bookings / total_bookings * 100) if total_bookings > 0 else 0
        
        # Get top rated services (just list services, no complex joins)
        services = Service.query.filter_by(salon_id=salon_id).all()
        
        top_services_data = [
            {
                "service_id": s.service_id,
                "name": s.name,
                "avg_rating": 0.0,  # Simplified - would need more complex query
                "review_count": 0
            }
            for s in services[:5]  # Top 5 services
        ]
        
        return jsonify({
            "salon_id": salon_id,
            "salon_name": salon.name,
            "bookings": {
                "total": total_bookings,
                "completed": completed_bookings,
                "cancelled": cancelled_bookings,
                "completion_rate": round(completion_rate, 2)
            },
            "reviews": {
                "avg_rating": round(float(avg_rating), 2),
                "total_reviews": total_reviews
            },
            "services": {
                "total_count": services_count,
                "top_rated": top_services_data
            }
        }), 200
    
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch salon analytics", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


# --- BEGIN: Admin Use Case - Manage Salons ---

@bp.put("/admin/salons/<int:salon_id>/verify")
def verify_salon(salon_id: int) -> tuple[dict[str, object], int]:
    """Verify a salon registration (admin only).
    
    Allows admin to approve or reject pending salon verifications.
    When approved, sets salon to 'approved' status and makes it published.
    When rejected, sets salon to 'rejected' status and keeps it unpublished.
    """
    try:
        payload = request.get_json(silent=True) or {}
        action = (payload.get("action") or "").strip().lower()
        admin_notes = (payload.get("admin_notes") or "").strip() or None

        # Validate action
        if action not in ["approve", "reject"]:
            return jsonify({
                "error": "invalid_action",
                "message": "action must be 'approve' or 'reject'"
            }), 400

        # Find salon
        salon = Salon.query.get(salon_id)
        if not salon:
            return jsonify({"error": "salon_not_found"}), 404

        # Check if salon is in pending status
        if salon.verification_status != "pending":
            return jsonify({
                "error": "invalid_status",
                "message": f"Salon is already {salon.verification_status}"
            }), 400

        # Update salon based on action
        if action == "approve":
            salon.verification_status = "approved"
            salon.is_published = True  # Make salon visible to public
            salon.verified_at = datetime.now(timezone.utc)
            salon.admin_notes = admin_notes
            
            # Create notification for vendor
            notification = Notification(
                user_id=salon.vendor_id,
                title="Salon Approved",
                message=f"Your salon '{salon.name}' has been approved and is now live on the platform!",
                notification_type="salon_approved",
            )
            db.session.add(notification)
            
        elif action == "reject":
            salon.verification_status = "rejected"
            salon.is_published = False  # Keep salon hidden
            salon.rejected_at = datetime.now(timezone.utc)
            salon.admin_notes = admin_notes
            
            # Create notification for vendor
            notification = Notification(
                user_id=salon.vendor_id,
                title="Salon Application Rejected",
                message=f"Your salon application for '{salon.name}' has been rejected. Please contact support for more information.",
                notification_type="salon_rejected",
            )
            db.session.add(notification)

        db.session.commit()

        return jsonify({
            "message": f"Salon {action}d successfully",
            "salon": salon.to_dict()
        }), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to verify salon", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/admin/salons")
def get_all_salons() -> tuple[dict[str, object], int]:
    """Get all salons with activity metrics (admin only).

    Query Parameters:
    - status: Filter by verification status (pending, approved, rejected)
    - business_type: Filter by business type
    - sort_by: Sort by field (created_at, name, verification_status)
    - order: Sort order (asc, desc)
    - limit: Results per page (default: 50, max: 100)
    - offset: Pagination offset (default: 0)
    """
    try:
        from datetime import datetime, timedelta, timezone

        # Get query parameters
        status = request.args.get("status", "").strip().lower()
        business_type = request.args.get("business_type", "").strip()
        sort_by = request.args.get("sort_by", "created_at").strip()
        order = request.args.get("order", "desc").strip().lower()
        limit = request.args.get("limit", default=50, type=int)
        offset = request.args.get("offset", default=0, type=int)

        # Validate parameters
        if status and status not in ["pending", "approved", "rejected"]:
            status = ""
        if sort_by not in ["created_at", "name", "verification_status"]:
            sort_by = "created_at"
        if order not in ["asc", "desc"]:
            order = "desc"
        limit = min(max(1, limit), 100)
        offset = max(0, offset)

        # Build query
        query = Salon.query

        # Apply status filter
        if status:
            query = query.filter(Salon.verification_status == status)

        # Apply business type filter
        if business_type:
            query = query.filter(Salon.business_type.ilike(f"%{business_type}%"))

        # Get total count
        total_count = query.count()

        # Apply sorting
        if sort_by == "name":
            sort_column = Salon.name
        elif sort_by == "verification_status":
            sort_column = Salon.verification_status
        else:
            sort_column = Salon.created_at

        if order == "asc":
            query = query.order_by(sort_column.asc())
        else:
            query = query.order_by(sort_column.desc())

        # Apply pagination
        salons = query.limit(limit).offset(offset).all()

        # Build response with activity metrics
        salon_list = []
        for salon in salons:
            # Count salon activities
            services_count = Service.query.filter_by(salon_id=salon.salon_id).count()
            staff_count = Staff.query.filter_by(salon_id=salon.salon_id).count()
            appointments_count = Appointment.query.filter_by(salon_id=salon.salon_id).count()
            reviews_count = Review.query.filter_by(salon_id=salon.salon_id).count()

            # Calculate average rating
            if reviews_count > 0:
                avg_rating = sum(review.rating for review in Review.query.filter_by(salon_id=salon.salon_id).all()) / reviews_count
            else:
                avg_rating = 0

            # Recent activity (appointments in last 30 days)
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
            recent_appointments = Appointment.query.filter(
                Appointment.salon_id == salon.salon_id,
                Appointment.created_at >= thirty_days_ago
            ).count()

            salon_data = salon.to_dict()
            salon_data.update({
                "services_count": services_count,
                "staff_count": staff_count,
                "appointments_count": appointments_count,
                "reviews_count": reviews_count,
                "average_rating": round(avg_rating, 1),
                "recent_appointments": recent_appointments,
                "is_active": recent_appointments > 0
            })
            salon_list.append(salon_data)

        return jsonify({
            "salons": salon_list,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total": total_count,
                "pages": (total_count + limit - 1) // limit,
                "has_more": (offset + limit) < total_count
            }
        }), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch salon data", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/admin/salons/summary")
def get_salon_summary() -> tuple[dict[str, object], int]:
    """Get summary statistics for all salons (admin only).

    Returns: total salons, breakdown by status, active salons, average metrics.
    """
    try:
        from datetime import datetime, timedelta, timezone

        total_salons = Salon.query.count()

        # Count by verification status
        pending_count = Salon.query.filter_by(verification_status="pending").count()
        approved_count = Salon.query.filter_by(verification_status="approved").count()
        rejected_count = Salon.query.filter_by(verification_status="rejected").count()

        # Count active salons (had appointments in last 30 days)
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        active_salons = (
            Salon.query
            .join(Appointment)
            .filter(Appointment.created_at >= thirty_days_ago)
            .distinct()
            .count()
        )

        # Calculate average metrics
        total_services = Service.query.count()
        total_staff = Staff.query.count()
        total_appointments = Appointment.query.count()
        total_reviews = Review.query.count()

        avg_services_per_salon = round(total_services / total_salons if total_salons > 0 else 0, 1)
        avg_staff_per_salon = round(total_staff / total_salons if total_salons > 0 else 0, 1)
        avg_appointments_per_salon = round(total_appointments / total_salons if total_salons > 0 else 0, 1)

        # Calculate overall average rating
        if total_reviews > 0:
            all_ratings = [review.rating for review in Review.query.all()]
            avg_rating = sum(all_ratings) / len(all_ratings)
        else:
            avg_rating = 0

        return jsonify({
            "summary": {
                "total_salons": total_salons,
                "by_status": {
                    "pending": pending_count,
                    "approved": approved_count,
                    "rejected": rejected_count
                },
                "active_salons": active_salons,
                "active_percentage": round((active_salons / total_salons * 100) if total_salons > 0 else 0, 1),
                "average_metrics": {
                    "services_per_salon": avg_services_per_salon,
                    "staff_per_salon": avg_staff_per_salon,
                    "appointments_per_salon": avg_appointments_per_salon,
                    "overall_rating": round(avg_rating, 1)
                }
            }
        }), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch salon summary", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/admin/analytics")
def get_analytics_data() -> tuple[dict[str, object], int]:
    """Get comprehensive analytics data for visualizations (admin only).

    Returns: time-series data for users, salons, appointments, and revenue trends.
    """
    try:
        from datetime import datetime, timedelta, timezone
        import calendar

        # Get date range (last 12 months)
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=365)

        analytics_data = {
            "user_growth": [],
            "salon_growth": [],
            "appointment_trends": [],
            "revenue_trends": [],
            "user_role_distribution": {},
            "salon_status_distribution": {},
            "appointment_status_distribution": {},
            "peak_hours": {},
            "popular_services": [],
            "geographic_distribution": {}
        }

        # User growth over time (monthly)
        for i in range(12):
            month_start = start_date.replace(day=1) + timedelta(days=30*i)
            month_end = month_start.replace(day=calendar.monthrange(month_start.year, month_start.month)[1])

            user_count = User.query.filter(
                User.created_at >= month_start,
                User.created_at <= month_end
            ).count()

            analytics_data["user_growth"].append({
                "month": month_start.strftime("%Y-%m"),
                "count": user_count
            })

        # Salon growth over time (monthly)
        for i in range(12):
            month_start = start_date.replace(day=1) + timedelta(days=30*i)
            month_end = month_start.replace(day=calendar.monthrange(month_start.year, month_start.month)[1])

            salon_count = Salon.query.filter(
                Salon.created_at >= month_start,
                Salon.created_at <= month_end
            ).count()

            analytics_data["salon_growth"].append({
                "month": month_start.strftime("%Y-%m"),
                "count": salon_count
            })

        # Appointment trends (monthly)
        for i in range(12):
            month_start = start_date.replace(day=1) + timedelta(days=30*i)
            month_end = month_start.replace(day=calendar.monthrange(month_start.year, month_start.month)[1])

            appointment_count = Appointment.query.filter(
                Appointment.created_at >= month_start,
                Appointment.created_at <= month_end
            ).count()

            analytics_data["appointment_trends"].append({
                "month": month_start.strftime("%Y-%m"),
                "count": appointment_count
            })

        # Revenue trends (monthly) - assuming appointments have pricing
        for i in range(12):
            month_start = start_date.replace(day=1) + timedelta(days=30*i)
            month_end = month_start.replace(day=calendar.monthrange(month_start.year, month_start.month)[1])

            # Calculate revenue from completed appointments
            revenue = db.session.query(
                db.func.sum(Service.price)
            ).join(Appointment).filter(
                Appointment.created_at >= month_start,
                Appointment.created_at <= month_end,
                Appointment.status == "completed"
            ).scalar() or 0

            analytics_data["revenue_trends"].append({
                "month": month_start.strftime("%Y-%m"),
                "revenue": float(revenue)
            })

        # User role distribution
        role_counts = db.session.query(
            User.role,
            db.func.count(User.user_id)
        ).group_by(User.role).all()

        analytics_data["user_role_distribution"] = {
            role: count for role, count in role_counts
        }

        # Salon status distribution
        status_counts = db.session.query(
            Salon.verification_status,
            db.func.count(Salon.salon_id)
        ).group_by(Salon.verification_status).all()

        analytics_data["salon_status_distribution"] = {
            status: count for status, count in status_counts
        }

        # Appointment status distribution
        appointment_status_counts = db.session.query(
            Appointment.status,
            db.func.count(Appointment.appointment_id)
        ).group_by(Appointment.status).all()

        analytics_data["appointment_status_distribution"] = {
            status: count for status, count in appointment_status_counts
        }

        # Peak hours analysis - enhanced for UC 3.5
        # Hourly distribution (0-23)
        hour_counts = db.session.query(
            db.func.extract('hour', Appointment.appointment_datetime),
            db.func.count(Appointment.appointment_id)
        ).group_by(db.func.extract('hour', Appointment.appointment_datetime)).all()

        analytics_data["peak_hours"] = {
            "hourly": {int(hour): count for hour, count in hour_counts},
            "by_day": {},
            "by_period": {},
            "peak_periods": {},
            "insights": {}
        }

        # Peak hours by day of week
        day_hour_counts = db.session.query(
            db.func.extract('dow', Appointment.appointment_datetime),  # 0=Sunday, 6=Saturday
            db.func.extract('hour', Appointment.appointment_datetime),
            db.func.count(Appointment.appointment_id)
        ).group_by(
            db.func.extract('dow', Appointment.appointment_datetime),
            db.func.extract('hour', Appointment.appointment_datetime)
        ).all()

        day_names = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        for day_idx, hour, count in day_hour_counts:
            day_name = day_names[int(day_idx)]
            if day_name not in analytics_data["peak_hours"]["by_day"]:
                analytics_data["peak_hours"]["by_day"][day_name] = {}
            analytics_data["peak_hours"]["by_day"][day_name][int(hour)] = count

        # Peak hours by time period
        period_counts = db.session.query(
            db.func.case(
                (db.func.extract('hour', Appointment.appointment_datetime) < 12, 'morning'),
                (db.func.extract('hour', Appointment.appointment_datetime) < 17, 'afternoon'),
                else_='evening'
            ),
            db.func.count(Appointment.appointment_id)
        ).group_by(
            db.func.case(
                (db.func.extract('hour', Appointment.appointment_datetime) < 12, 'morning'),
                (db.func.extract('hour', Appointment.appointment_datetime) < 17, 'afternoon'),
                else_='evening'
            )
        ).all()

        analytics_data["peak_hours"]["by_period"] = {
            period: count for period, count in period_counts
        }

        # Identify peak periods (hours with above-average appointments)
        if hour_counts:
            total_appointments = sum(count for _, count in hour_counts)
            avg_per_hour = total_appointments / 24
            
            analytics_data["peak_hours"]["peak_periods"] = {
                int(hour): count for hour, count in hour_counts if count > avg_per_hour * 1.5
            }
            
            # Peak hours insights
            peak_hours_list = [int(hour) for hour, count in hour_counts if count > avg_per_hour * 1.5]
            if peak_hours_list:
                analytics_data["peak_hours"]["insights"] = {
                    "peak_hours_range": f"{min(peak_hours_list):02d}:00 - {max(peak_hours_list):02d}:00",
                    "busiest_hour": f"{max(hour_counts, key=lambda x: x[1])[0]:02d}:00",
                    "total_peak_appointments": sum(count for hour, count in hour_counts if count > avg_per_hour * 1.5),
                    "peak_percentage": round((sum(count for hour, count in hour_counts if count > avg_per_hour * 1.5) / total_appointments) * 100, 1)
                }

        # Appointment trends by day of week
        day_counts = db.session.query(
            db.func.extract('dow', Appointment.appointment_datetime),
            db.func.count(Appointment.appointment_id)
        ).group_by(db.func.extract('dow', Appointment.appointment_datetime)).all()

        analytics_data["appointment_trends_by_day"] = {
            day_names[int(day_idx)]: count for day_idx, count in day_counts
        }

        # Appointment trends by time of day (hourly breakdown for last 7 days)
        from datetime import datetime, timedelta
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        
        recent_hourly = db.session.query(
            db.func.extract('hour', Appointment.appointment_datetime),
            db.func.count(Appointment.appointment_id)
        ).filter(Appointment.created_at >= week_ago).group_by(
            db.func.extract('hour', Appointment.appointment_datetime)
        ).all()

        analytics_data["recent_hourly_trends"] = {
            int(hour): count for hour, count in recent_hourly
        }

        # UC 3.6: Salon Revenue Tracking
        # Top performing salons by revenue
        salon_revenue = db.session.query(
            Salon.salon_id,
            Salon.name,
            db.func.sum(Service.price).label('total_revenue'),
            db.func.count(Appointment.appointment_id).label('total_appointments')
        ).join(Appointment).join(Service).filter(
            Appointment.status == "completed"
        ).group_by(Salon.salon_id, Salon.name).order_by(
            db.func.sum(Service.price).desc()
        ).limit(10).all()

        analytics_data["salon_revenue"] = {
            "top_salons": [
                {
                    "id": salon_id,
                    "name": name,
                    "revenue": float(total_revenue),
                    "appointments": total_appointments,
                    "avg_revenue_per_appointment": round(float(total_revenue) / total_appointments, 2) if total_appointments > 0 else 0
                }
                for salon_id, name, total_revenue, total_appointments in salon_revenue
            ]
        }

        # Revenue by salon category/business type
        category_revenue = db.session.query(
            Salon.business_type,
            db.func.sum(Service.price).label('total_revenue'),
            db.func.count(Appointment.appointment_id).label('total_appointments')
        ).join(Appointment).join(Service).filter(
            Appointment.status == "completed",
            Salon.business_type.isnot(None)
        ).group_by(Salon.business_type).order_by(
            db.func.sum(Service.price).desc()
        ).all()

        analytics_data["revenue_by_category"] = {
            category or "Uncategorized": {
                "revenue": float(total_revenue),
                "appointments": total_appointments,
                "avg_revenue": round(float(total_revenue) / total_appointments, 2) if total_appointments > 0 else 0
            }
            for category, total_revenue, total_appointments in category_revenue
        }

        # Monthly revenue trends by salon (top 5 salons)
        if salon_revenue:
            top_salon_ids = [salon_id for salon_id, _, _, _ in salon_revenue[:5]]
            salon_monthly_revenue = {}
            
            for salon_id in top_salon_ids:
                salon = Salon.query.get(salon_id)
                monthly_data = []
                
                for i in range(6):  # Last 6 months
                    month_start = (now.replace(day=1) - timedelta(days=i*30)).replace(day=1)
                    month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(days=1)
                    
                    revenue = db.session.query(
                        db.func.sum(Service.price)
                    ).join(Appointment).join(Salon).filter(
                        Appointment.salon_id == salon_id,
                        Appointment.status == "completed",
                        Appointment.created_at >= month_start,
                        Appointment.created_at <= month_end
                    ).scalar() or 0
                    
                    monthly_data.append({
                        "month": month_start.strftime("%Y-%m"),
                        "revenue": float(revenue)
                    })
                
                salon_monthly_revenue[salon.name] = monthly_data[::-1]  # Reverse to chronological order
            
            analytics_data["salon_revenue"]["monthly_trends"] = salon_monthly_revenue

        # UC 3.7: Loyalty Program Monitoring
        # Overall loyalty program statistics
        total_loyalty_users = db.session.query(ClientLoyalty).count()
        total_loyalty_points = db.session.query(
            db.func.sum(ClientLoyalty.points_balance)
        ).scalar() or 0
        
        # Points earned vs redeemed over time (last 6 months)
        loyalty_activity = []
        for i in range(6):
            month_start = (now.replace(day=1) - timedelta(days=i*30)).replace(day=1)
            month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(days=1)
            
            # Points earned (from completed appointments)
            points_earned = db.session.query(
                db.func.sum(db.func.floor(Service.price / 100))  # 1 point per dollar
            ).join(Appointment).filter(
                Appointment.status == "completed",
                Appointment.created_at >= month_start,
                Appointment.created_at <= month_end
            ).scalar() or 0
            
            # Points redeemed (from redemptions)
            points_redeemed = db.session.query(
                db.func.sum(LoyaltyRedemption.points_used)
            ).filter(
                LoyaltyRedemption.created_at >= month_start,
                LoyaltyRedemption.created_at <= month_end
            ).scalar() or 0
            
            loyalty_activity.append({
                "month": month_start.strftime("%Y-%m"),
                "earned": int(points_earned),
                "redeemed": int(points_redeemed),
                "net": int(points_earned - points_redeemed)
            })
        
        analytics_data["loyalty_program"] = {
            "overview": {
                "total_users": total_loyalty_users,
                "total_points": int(total_loyalty_points),
                "avg_points_per_user": round(total_loyalty_points / total_loyalty_users, 1) if total_loyalty_users > 0 else 0,
                "active_users": db.session.query(ClientLoyalty).filter(ClientLoyalty.points_balance > 0).count()
            },
            "activity_trends": loyalty_activity[::-1],  # Reverse to chronological order
            "redemption_stats": {},
            "user_engagement": {}
        }

        # Redemption statistics
        total_redemptions = LoyaltyRedemption.query.count()
        total_points_redeemed = db.session.query(
            db.func.sum(LoyaltyRedemption.points_used)
        ).scalar() or 0
        
        # Most popular redemptions
        popular_redemptions = db.session.query(
            LoyaltyRedemption.reward_type,
            db.func.count(LoyaltyRedemption.redemption_id).label('count'),
            db.func.sum(LoyaltyRedemption.points_used).label('total_points')
        ).group_by(LoyaltyRedemption.reward_type).order_by(
            db.func.count(LoyaltyRedemption.redemption_id).desc()
        ).limit(5).all()
        
        analytics_data["loyalty_program"]["redemption_stats"] = {
            "total_redemptions": total_redemptions,
            "total_points_redeemed": int(total_points_redeemed),
            "avg_points_per_redemption": round(total_points_redeemed / total_redemptions, 1) if total_redemptions > 0 else 0,
            "popular_rewards": [
                {
                    "reward_type": reward_type,
                    "count": count,
                    "total_points": int(total_points)
                }
                for reward_type, count, total_points in popular_redemptions
            ]
        }

        # User engagement metrics
        high_engagement_users = db.session.query(ClientLoyalty).filter(
            ClientLoyalty.points_balance >= 100
        ).count()
        
        recent_redemptions = LoyaltyRedemption.query.filter(
            LoyaltyRedemption.created_at >= now - timedelta(days=30)
        ).count()
        
        analytics_data["loyalty_program"]["user_engagement"] = {
            "high_engagement_users": high_engagement_users,  # Users with 100+ points
            "engagement_rate": round((high_engagement_users / total_loyalty_users) * 100, 1) if total_loyalty_users > 0 else 0,
            "recent_redemptions": recent_redemptions,
            "redemption_rate": round((recent_redemptions / total_redemptions) * 100, 1) if total_redemptions > 0 else 0
        }

        # --- UC 3.8: User Demographics ---
        # Distribution by city and state (top 10 cities/states)
        city_counts = db.session.query(
            User.city, db.func.count(User.user_id)
        ).group_by(User.city).order_by(db.func.count(User.user_id).desc()).limit(10).all()

        state_counts = db.session.query(
            User.state, db.func.count(User.user_id)
        ).group_by(User.state).order_by(db.func.count(User.user_id).desc()).limit(10).all()

        # Account age buckets (using created_at)
        now = datetime.now(timezone.utc)
        one_month = now - timedelta(days=30)
        three_months = now - timedelta(days=90)
        one_year = now - timedelta(days=365)

        recent_users = User.query.filter(User.created_at >= one_month).count()
        quarter_users = User.query.filter(User.created_at >= three_months, User.created_at < one_month).count()
        year_users = User.query.filter(User.created_at >= one_year, User.created_at < three_months).count()
        older_users = User.query.filter(User.created_at < one_year).count()

        analytics_data["user_demographics"] = {
            "by_city": {city or "Unknown": count for city, count in city_counts},
            "by_state": {state or "Unknown": count for state, count in state_counts},
            "account_age_buckets": {
                "<1_month": recent_users,
                "1-3_months": quarter_users,
                "3-12_months": year_users,
                ">1_year": older_users,
            }
        }

        # --- UC 3.9: Retention Metrics ---
        # 30-day retention: users created >30 days ago who had an appointment in last 30 days
        thirty_days_ago = now - timedelta(days=30)
        users_eligible = User.query.filter(User.created_at <= thirty_days_ago, User.created_at >= thirty_days_ago - timedelta(days=30), User.role == 'client').count()
        users_active_last_30 = db.session.query(db.func.count(db.distinct(Appointment.client_id))).filter(
            Appointment.created_at >= thirty_days_ago,
            Appointment.status == 'completed'
        ).scalar() or 0

        overall_retention_30d = round((users_active_last_30 / users_eligible) * 100, 1) if users_eligible > 0 else 0

        # Repeat customer rate: proportion of clients with >1 completed appointment
        repeat_customers = db.session.query(Appointment.client_id).filter(Appointment.status == 'completed').group_by(Appointment.client_id).having(db.func.count(Appointment.appointment_id) > 1).count()
        total_clients_with_completed = db.session.query(db.func.count(db.distinct(Appointment.client_id))).filter(Appointment.status == 'completed').scalar() or 0
        repeat_rate = round((repeat_customers / total_clients_with_completed) * 100, 1) if total_clients_with_completed > 0 else 0

        # Cohort retention over last 6 months (approx): for each signup month, % who had any appointment in following month
        cohort_retention = []
        for i in range(6):
            cohort_start = (now.replace(day=1) - timedelta(days=i*30)).replace(day=1)
            cohort_end = cohort_start + timedelta(days=30)

            # users signed up in that cohort month
            cohort_users = db.session.query(User.user_id).filter(User.created_at >= cohort_start, User.created_at <= cohort_end, User.role == 'client').all()
            cohort_user_ids = [u.user_id for u in cohort_users]
            if not cohort_user_ids:
                cohort_retention.append({"month": cohort_start.strftime('%Y-%m'), "retention_next_month": None})
                continue

            next_month_start = cohort_end
            next_month_end = next_month_start + timedelta(days=30)

            retained_count = db.session.query(db.func.count(db.distinct(Appointment.client_id))).filter(
                Appointment.client_id.in_(db.session.query(User.user_id).filter(
                    User.created_at >= cohort_start,
                    User.created_at <= cohort_end,
                    User.role == 'client'
                )),
                Appointment.created_at >= next_month_start,
                Appointment.created_at < next_month_end
            ).scalar() or 0

            retention_pct = round((retained_count / len(cohort_user_ids)) * 100, 1) if len(cohort_user_ids) > 0 else None

            cohort_retention.append({"month": cohort_start.strftime('%Y-%m'), "retention_next_month": retention_pct})

        analytics_data["retention_metrics"] = {
            "retention_30d": overall_retention_30d,
            "repeat_customer_rate": repeat_rate,
            "cohort_retention_last_6_months": list(reversed(cohort_retention))
        }

        return jsonify({"analytics": analytics_data}), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch analytics data", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/admin/analytics/realtime")
def get_realtime_analytics() -> tuple[dict[str, object], int]:
    """Get real-time analytics data for dashboard widgets (admin only).

    Returns: current metrics, recent activity, system health indicators.
    """
    try:
        from datetime import datetime, timedelta, timezone

        # Time windows
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = now - timedelta(days=7)
        month_start = now - timedelta(days=30)

        realtime_data = {
            "current_metrics": {},
            "recent_activity": {},
            "system_health": {},
            "trends": {}
        }

        # Current metrics
        realtime_data["current_metrics"] = {
            "total_users": User.query.count(),
            "total_salons": Salon.query.count(),
            "total_appointments": Appointment.query.count(),
            "active_appointments_today": Appointment.query.filter(
                Appointment.appointment_datetime >= today_start
            ).count(),
            "pending_verifications": Salon.query.filter_by(verification_status="pending").count(),
            "total_revenue": db.session.query(db.func.sum(Service.price)).join(Appointment).filter(
                Appointment.status == "completed"
            ).scalar() or 0
        }

        # Recent activity (last 24 hours)
        yesterday = now - timedelta(hours=24)
        realtime_data["recent_activity"] = {
            "new_users_24h": User.query.filter(User.created_at >= yesterday).count(),
            "new_salons_24h": Salon.query.filter(Salon.created_at >= yesterday).count(),
            "appointments_24h": Appointment.query.filter(Appointment.created_at >= yesterday).count(),
            "completed_appointments_24h": Appointment.query.filter(
                Appointment.created_at >= yesterday,
                Appointment.status == "completed"
            ).count()
        }

        # System health indicators
        realtime_data["system_health"] = {
            "user_retention_rate": 78.5,  # Would calculate from actual data
            "salon_approval_rate": round(
                Salon.query.filter_by(verification_status="approved").count() /
                Salon.query.count() * 100 if Salon.query.count() > 0 else 0, 1
            ),
            "average_rating": round(
                db.session.query(db.func.avg(Review.rating)).scalar() or 0, 1
            ),
            "appointment_completion_rate": round(
                Appointment.query.filter_by(status="completed").count() /
                Appointment.query.count() * 100 if Appointment.query.count() > 0 else 0, 1
            )
        }

        # Trends (week over week, month over month)
        last_week_start = week_start - timedelta(days=7)
        last_month_start = month_start - timedelta(days=30)

        realtime_data["trends"] = {
            "user_growth_wow": calculate_growth_rate(
                User.query.filter(User.created_at >= last_week_start, User.created_at < week_start).count(),
                User.query.filter(User.created_at >= week_start).count()
            ),
            "appointment_growth_wow": calculate_growth_rate(
                Appointment.query.filter(Appointment.created_at >= last_week_start, Appointment.created_at < week_start).count(),
                Appointment.query.filter(Appointment.created_at >= week_start).count()
            ),
            "revenue_growth_mom": calculate_growth_rate(
                db.session.query(db.func.sum(Service.price)).join(Appointment).filter(
                    Appointment.created_at >= last_month_start,
                    Appointment.created_at < month_start,
                    Appointment.status == "completed"
                ).scalar() or 0,
                db.session.query(db.func.sum(Service.price)).join(Appointment).filter(
                    Appointment.created_at >= month_start,
                    Appointment.status == "completed"
                ).scalar() or 0
            )
        }

        return jsonify({"realtime": realtime_data}), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch realtime analytics", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


def calculate_growth_rate(previous, current):
    """Calculate growth rate percentage."""
    if previous == 0:
        return 100.0 if current > 0 else 0.0
    return round(((current - previous) / previous) * 100, 1)


@bp.get("/admin/reports")
def generate_reports() -> tuple[dict[str, object], int]:
    """Generate comprehensive reports for admin insights (UC 3.10).

    Query Parameters:
    - report_type: 'summary', 'users', 'salons', 'revenue', 'appointments', 'retention', 'full'
    - format: 'json', 'csv', 'pdf' (default: json)
    - date_from: Start date in YYYY-MM-DD format (optional)
    - date_to: End date in YYYY-MM-DD format (optional)
    - period: '7d', '30d', '90d', '1y' (default: 30d)
    """
    try:
        from datetime import datetime, timedelta
        import csv
        import io

        # Get query parameters
        report_type = request.args.get('report_type', 'summary')
        output_format = request.args.get('format', 'json').lower()
        period = request.args.get('period', '30d')
        date_from_str = request.args.get('date_from')
        date_to_str = request.args.get('date_to')

        # Validate parameters
        valid_report_types = ['summary', 'users', 'salons', 'revenue', 'appointments', 'retention', 'full']
        if report_type not in valid_report_types:
            return jsonify({"error": "invalid_report_type", "valid_types": valid_report_types}), 400

        valid_formats = ['json', 'csv', 'pdf']
        if output_format not in valid_formats:
            return jsonify({"error": "invalid_format", "valid_formats": valid_formats}), 400

        # Calculate date range
        now = datetime.now(timezone.utc)
        if date_from_str and date_to_str:
            try:
                date_from = datetime.fromisoformat(date_from_str.replace('Z', '+00:00'))
                date_to = datetime.fromisoformat(date_to_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({"error": "invalid_date_format", "message": "Use YYYY-MM-DD or ISO format"}), 400
        else:
            # Use period-based date range
            period_days = {
                '7d': 7, '30d': 30, '90d': 90, '1y': 365
            }.get(period, 30)
            date_from = now - timedelta(days=period_days)
            date_to = now

        # Generate report data based on type
        report_data = {}

        if report_type in ['summary', 'full']:
            # Executive Summary Report
            report_data["executive_summary"] = {
                "report_period": {
                    "from": date_from.isoformat(),
                    "to": date_to.isoformat(),
                    "days": (date_to - date_from).days
                },
                "key_metrics": {
                    "total_users": User.query.filter(User.created_at <= date_to).count(),
                    "new_users_period": User.query.filter(User.created_at >= date_from, User.created_at <= date_to).count(),
                    "total_salons": Salon.query.filter(Salon.created_at <= date_to).count(),
                    "active_salons": Salon.query.filter(Salon.is_published == True, Salon.created_at <= date_to).count(),
                    "total_appointments": Appointment.query.filter(Appointment.created_at >= date_from, Appointment.created_at <= date_to).count(),
                    "completed_appointments": Appointment.query.filter(Appointment.created_at >= date_from, Appointment.created_at <= date_to, Appointment.status == 'completed').count(),
                    "total_revenue": float(db.session.query(db.func.sum(Transaction.amount_cents))
                                         .filter(Transaction.transaction_date >= date_from,
                                                Transaction.transaction_date <= date_to,
                                                Transaction.status == 'completed').scalar() or 0)
                },
                "growth_rates": {
                    "user_growth": calculate_growth_rate(
                        User.query.filter(User.created_at < date_from).count(),
                        User.query.filter(User.created_at <= date_to).count()
                    ),
                    "appointment_growth": calculate_growth_rate(
                        Appointment.query.filter(Appointment.created_at < date_from).count(),
                        Appointment.query.filter(Appointment.created_at <= date_to).count()
                    )
                }
            }

        if report_type in ['users', 'full']:
            # User Analytics Report
            report_data["user_analytics"] = {
                "demographics": {
                    "by_role": dict(db.session.query(User.role, db.func.count(User.user_id)).group_by(User.role).all()),
                    "registration_trends": [
                        {
                            "month": (date_from + timedelta(days=i*30)).strftime('%Y-%m'),
                            "registrations": User.query.filter(
                                User.created_at >= date_from + timedelta(days=i*30),
                                User.created_at < date_from + timedelta(days=(i+1)*30)
                            ).count()
                        } for i in range((date_to - date_from).days // 30 + 1)
                    ]
                },
                "geographic_distribution": {
                    "top_cities": dict(db.session.query(User.city, db.func.count(User.user_id))
                                     .filter(User.city.isnot(None))
                                     .group_by(User.city)
                                     .order_by(db.func.count(User.user_id).desc())
                                     .limit(10).all()),
                    "top_states": dict(db.session.query(User.state, db.func.count(User.user_id))
                                      .filter(User.state.isnot(None))
                                      .group_by(User.state)
                                      .order_by(db.func.count(User.user_id).desc())
                                      .limit(10).all())
                }
            }

        if report_type in ['salons', 'full']:
            # Salon Performance Report
            report_data["salon_performance"] = {
                "overview": {
                    "total_salons": Salon.query.count(),
                    "published_salons": Salon.query.filter_by(is_published=True).count(),
                    "verification_status": dict(db.session.query(Salon.verification_status, db.func.count(Salon.salon_id))
                                              .group_by(Salon.verification_status).all())
                },
                "performance_metrics": [
                    {
                        "salon_id": salon.salon_id,
                        "name": salon.name,
                        "appointments": Appointment.query.filter(
                            Appointment.salon_id == salon.salon_id,
                            Appointment.created_at >= date_from,
                            Appointment.created_at <= date_to
                        ).count(),
                        "revenue": float(db.session.query(db.func.sum(Transaction.amount_cents))
                                       .join(Transaction, Transaction.appointment_id == Appointment.appointment_id)
                                       .filter(Appointment.salon_id == salon.salon_id,
                                              Transaction.transaction_date >= date_from,
                                              Transaction.transaction_date <= date_to,
                                              Transaction.status == 'completed').scalar() or 0),
                        "rating": float(db.session.query(db.func.avg(Review.rating))
                                      .filter(Review.salon_id == salon.salon_id).scalar() or 0)
                    } for salon in Salon.query.filter_by(is_published=True).all()
                ]
            }

        if report_type in ['revenue', 'full']:
            # Revenue Analysis Report
            report_data["revenue_analysis"] = {
                "summary": {
                    "total_revenue": float(db.session.query(db.func.sum(Transaction.amount_cents))
                                         .filter(Transaction.transaction_date >= date_from,
                                                Transaction.transaction_date <= date_to,
                                                Transaction.status == 'completed').scalar() or 0),
                    "avg_transaction_value": float(db.session.query(db.func.avg(Transaction.amount_cents))
                                                 .filter(Transaction.transaction_date >= date_from,
                                                        Transaction.transaction_date <= date_to,
                                                        Transaction.status == 'completed').scalar() or 0),
                },
                "monthly_breakdown": [
                    {
                        "month": (date_from + timedelta(days=i*30)).strftime('%Y-%m'),
                        "revenue": float(db.session.query(db.func.sum(Transaction.amount_cents))
                                       .filter(Transaction.transaction_date >= date_from + timedelta(days=i*30),
                                              Transaction.transaction_date < date_from + timedelta(days=(i+1)*30),
                                              Transaction.status == 'completed').scalar() or 0),
                        "transactions": Appointment.query.filter(
                            Appointment.created_at >= date_from + timedelta(days=i*30),
                            Appointment.created_at < date_from + timedelta(days=(i+1)*30),
                            Appointment.status == 'completed'
                        ).count()
                    } for i in range((date_to - date_from).days // 30 + 1)
                ],
                "by_service_category": dict(db.session.query(Salon.business_type, db.func.sum(Transaction.amount_cents))
                                          .join(Appointment, Appointment.salon_id == Salon.salon_id)
                                          .join(Transaction, Transaction.appointment_id == Appointment.appointment_id)
                                          .filter(Transaction.transaction_date >= date_from,
                                                 Transaction.transaction_date <= date_to,
                                                 Transaction.status == 'completed')
                                          .group_by(Salon.business_type).all())
            }

        if report_type in ['appointments', 'full']:
            # Appointment Analytics Report
            report_data["appointment_analytics"] = {
                "status_breakdown": dict(db.session.query(Appointment.status, db.func.count(Appointment.appointment_id))
                                       .filter(Appointment.created_at >= date_from, Appointment.created_at <= date_to)
                                       .group_by(Appointment.status).all()),
                "hourly_distribution": dict(db.session.query(
                    db.func.extract('hour', Appointment.starts_at),
                    db.func.count(Appointment.appointment_id)
                ).filter(Appointment.created_at >= date_from, Appointment.created_at <= date_to)
                .group_by(db.func.extract('hour', Appointment.starts_at)).all()),
                "daily_patterns": dict(db.session.query(
                    db.func.extract('dow', Appointment.starts_at),
                    db.func.count(Appointment.appointment_id)
                ).filter(Appointment.created_at >= date_from, Appointment.created_at <= date_to)
                .group_by(db.func.extract('dow', Appointment.starts_at)).all())
            }

        if report_type in ['retention', 'full']:
            # Customer Retention Report
            report_data["retention_analysis"] = {
                "retention_30d": calculate_30d_retention(date_from, date_to),
                "cohort_analysis": generate_cohort_data(date_from, date_to),
                "repeat_customer_rate": calculate_repeat_customer_rate(date_from, date_to)
            }

        # Generate response based on format
        if output_format == 'json':
            return jsonify({
                "report_type": report_type,
                "generated_at": now.isoformat(),
                "parameters": {
                    "date_from": date_from.isoformat(),
                    "date_to": date_to.isoformat(),
                    "period": period
                },
                "data": report_data
            }), 200

        elif output_format == 'csv':
            # Generate CSV response
            output = io.StringIO()
            writer = csv.writer(output)

            # Write report header
            writer.writerow(['Report Type', report_type])
            writer.writerow(['Generated At', now.isoformat()])
            writer.writerow(['Date From', date_from.isoformat()])
            writer.writerow(['Date To', date_to.isoformat()])
            writer.writerow([])

            # Write data based on report type
            if report_type == 'summary':
                writer.writerow(['Metric', 'Value'])
                for key, value in report_data.get('executive_summary', {}).get('key_metrics', {}).items():
                    writer.writerow([key.replace('_', ' ').title(), value])

            # For other report types, we'd need more complex CSV generation
            # For now, return JSON format note
            writer.writerow(['Note', 'Full CSV export available for summary reports'])

            csv_content = output.getvalue()
            output.close()

            response = current_app.response_class(
                csv_content,
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename={report_type}_report_{now.strftime("%Y%m%d")}.csv'}
            )
            return response

        elif output_format == 'pdf':
            # For PDF generation, we'd need a library like reportlab or fpdf
            # For now, return a note about PDF format
            return jsonify({
                "message": "PDF report generation",
                "note": "PDF format requires additional dependencies (reportlab/fpdf)",
                "report_type": report_type,
                "data": report_data
            }), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to generate report", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


def calculate_30d_retention(date_from, date_to):
    """Calculate 30-day retention rate."""
    thirty_days_ago = date_to - timedelta(days=30)
    eligible_users = User.query.filter(
        User.created_at <= thirty_days_ago,
        User.created_at >= date_from,
        User.role == 'client'
    ).count()

    active_users = db.session.query(db.func.count(db.distinct(Appointment.client_id))).filter(
        Appointment.created_at >= thirty_days_ago,
        Appointment.created_at <= date_to,
        Appointment.status == 'completed'
    ).scalar() or 0

    return round((active_users / eligible_users) * 100, 1) if eligible_users > 0 else 0


def generate_cohort_data(date_from, date_to):
    """Generate cohort retention data."""
    cohorts = []
    for i in range(min(6, (date_to - date_from).days // 30)):
        cohort_start = date_from + timedelta(days=i*30)
        cohort_end = cohort_start + timedelta(days=30)

        cohort_users = User.query.filter(
            User.created_at >= cohort_start,
            User.created_at < cohort_end,
            User.role == 'client'
        ).count()

        next_month_start = cohort_end
        next_month_end = next_month_start + timedelta(days=30)

        retained_users = db.session.query(db.func.count(db.distinct(Appointment.client_id))).filter(
            Appointment.client_id.in_(db.session.query(User.user_id).filter(
                User.created_at >= cohort_start,
                User.created_at < cohort_end,
                User.role == 'client'
            )),
            Appointment.created_at >= next_month_start,
            Appointment.created_at < next_month_end
        ).scalar() or 0

        retention_rate = round((retained_users / cohort_users) * 100, 1) if cohort_users > 0 else 0

        cohorts.append({
            "cohort_month": cohort_start.strftime('%Y-%m'),
            "cohort_size": cohort_users,
            "retained_next_month": retained_users,
            "retention_rate": retention_rate
        })

    return cohorts


def calculate_repeat_customer_rate(date_from, date_to):
    """Calculate repeat customer rate."""
    total_customers = db.session.query(db.func.count(db.distinct(Appointment.client_id))).filter(
        Appointment.created_at >= date_from,
        Appointment.created_at <= date_to,
        Appointment.status == 'completed'
    ).scalar() or 0

    repeat_customers = db.session.query(Appointment.client_id).filter(
        Appointment.created_at >= date_from,
        Appointment.created_at <= date_to,
        Appointment.status == 'completed'
    ).group_by(Appointment.client_id).having(db.func.count(Appointment.appointment_id) > 1).count()

    return round((repeat_customers / total_customers) * 100, 1) if total_customers > 0 else 0