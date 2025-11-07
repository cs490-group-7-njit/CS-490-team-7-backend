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
from .models import AuthAccount, Salon, User, Staff, Service, Review, Appointment, ClientLoyalty, StaffRating, Notification, Message, LoyaltyRedemption, DiscountAlert, Product, ProductPurchase

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
        
        # Filter to only published salons (uncomment when ready)
        # salon_query = salon_query.filter(Salon.is_published.is_(True))
        
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
    """Update appointment status (vendor can change booked→completed, no-show, etc)."""
    try:
        from .models import Appointment

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

        appointment.status = new_status
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

        if not client_id or rating is None:
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


# ============================================================================
# UC 2.16 - Rate Staff
# ============================================================================

@bp.post("/staff/<int:staff_id>/rate")
def rate_staff(staff_id: int) -> tuple[dict[str, object], int]:
    """Create a new rating/review for a staff member (UC 2.16)."""
    try:
        from .models import StaffRating
        
        payload = request.get_json(silent=True) or {}

        # Validate required fields
        client_id = payload.get("client_id")
        rating = payload.get("rating")
        comment = (payload.get("comment") or "").strip() or None

        if not client_id or rating is None:
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

        # Check if staff exists
        staff = Staff.query.get(staff_id)
        if not staff:
            return jsonify({"error": "staff_not_found"}), 404

        # Check if client exists
        client = User.query.get(client_id)
        if not client:
            return jsonify({"error": "client_not_found"}), 404

        # Create staff rating
        staff_rating = StaffRating(
            staff_id=staff_id,
            client_id=client_id,
            rating=rating,
            comment=comment,
        )

        db.session.add(staff_rating)
        db.session.commit()

        return jsonify({"staff_rating": staff_rating.to_dict()}), 201

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to create staff rating", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/staff/<int:staff_id>/reviews")
def get_staff_reviews(staff_id: int) -> tuple[dict[str, object], int]:
    """Get reviews for a staff member with pagination (UC 2.16)."""
    try:
        from .models import StaffRating
        
        # Check if staff exists
        staff = Staff.query.get(staff_id)
        if not staff:
            return jsonify({"error": "staff_not_found"}), 404

        # Get pagination parameters
        page = request.args.get("page", 1, type=int)
        limit = request.args.get("limit", 20, type=int)

        # Validate pagination
        if page < 1 or limit < 1:
            return jsonify({"error": "invalid_pagination"}), 400
        if limit > 50:
            limit = 50

        # Query reviews with pagination
        pagination = StaffRating.query.filter_by(staff_id=staff_id).order_by(
            StaffRating.created_at.desc()
        ).paginate(page=page, per_page=limit)

        reviews_data = [review.to_dict() for review in pagination.items]

        return jsonify({
            "staff_id": staff_id,
            "reviews": reviews_data,
            "pagination": {
                "page": page,
                "per_page": limit,
                "total": pagination.total,
                "pages": pagination.pages,
            }
        }), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch staff reviews", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.get("/staff/<int:staff_id>/rating")
def get_staff_rating(staff_id: int) -> tuple[dict[str, object], int]:
    """Get average rating and stats for a staff member (UC 2.16)."""
    try:
        from .models import StaffRating
        from sqlalchemy import func
        
        # Check if staff exists
        staff = Staff.query.get(staff_id)
        if not staff:
            return jsonify({"error": "staff_not_found"}), 404

        # Query aggregated rating data
        rating_stats = db.session.query(
            func.avg(StaffRating.rating).label("avg_rating"),
            func.count(StaffRating.rating_id).label("total_ratings")
        ).filter_by(staff_id=staff_id).first()

        avg_rating = rating_stats.avg_rating or 0
        total_ratings = rating_stats.total_ratings or 0

        return jsonify({
            "staff_id": staff_id,
            "avg_rating": round(float(avg_rating), 2),
            "total_ratings": total_ratings
        }), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch staff rating", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


# ===== Payment Methods (UC 2.18) =====

@bp.get("/users/<int:user_id>/payment-methods")
def get_payment_methods(user_id: int) -> tuple[dict[str, object], int]:
    """Get all payment methods for a user (UC 2.18)."""
    try:
        from .models import PaymentMethod

        payment_methods = PaymentMethod.query.filter_by(user_id=user_id).all()
        return jsonify({
            "payment_methods": [pm.to_dict() for pm in payment_methods]
        }), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch payment methods", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.post("/users/<int:user_id>/payment-methods")
def add_payment_method(user_id: int) -> tuple[dict[str, object], int]:
    """Add a new payment method for a user (UC 2.18)."""
    try:
        from .models import PaymentMethod, User

        # Verify user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "not_found", "message": "User not found"}), 404

        data = request.get_json()

        # Validate required fields
        required = ["card_holder_name", "card_number", "card_brand", "expiry_month", "expiry_year"]
        if not all(data.get(field) for field in required):
            return jsonify({"error": "invalid_request"}), 400

        # Extract last 4 digits
        card_number = str(data.get("card_number", "")).replace(" ", "")
        if len(card_number) < 4:
            return jsonify({"error": "invalid_card_number"}), 400

        card_last_four = card_number[-4:]

        # If this is the first card, make it default
        is_default = data.get("is_default", False)
        existing_methods = PaymentMethod.query.filter_by(user_id=user_id).count()
        if existing_methods == 0:
            is_default = True

        payment_method = PaymentMethod(
            user_id=user_id,
            card_holder_name=data.get("card_holder_name"),
            card_number_last_four=card_last_four,
            card_brand=data.get("card_brand"),
            expiry_month=int(data.get("expiry_month")),
            expiry_year=int(data.get("expiry_year")),
            is_default=is_default,
        )

        db.session.add(payment_method)
        db.session.commit()

        return jsonify({"payment_method": payment_method.to_dict()}), 201

    except (ValueError, KeyError) as e:
        return jsonify({"error": "invalid_request"}), 400
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to add payment method", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.delete("/users/<int:user_id>/payment-methods/<int:payment_method_id>")
def delete_payment_method(user_id: int, payment_method_id: int) -> tuple[dict[str, object], int]:
    """Delete a payment method (UC 2.18)."""
    try:
        from .models import PaymentMethod

        payment_method = PaymentMethod.query.filter_by(
            payment_method_id=payment_method_id,
            user_id=user_id
        ).first()

        if not payment_method:
            return jsonify({"error": "not_found"}), 404

        db.session.delete(payment_method)
        db.session.commit()

        return jsonify({"message": "Payment method deleted"}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to delete payment method", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.put("/users/<int:user_id>/payment-methods/<int:payment_method_id>/default")
def set_default_payment_method(user_id: int, payment_method_id: int) -> tuple[dict[str, object], int]:
    """Set a payment method as default (UC 2.18)."""
    try:
        from .models import PaymentMethod

        payment_method = PaymentMethod.query.filter_by(
            payment_method_id=payment_method_id,
            user_id=user_id
        ).first()

        if not payment_method:
            return jsonify({"error": "not_found"}), 404

        # Unset all other defaults
        PaymentMethod.query.filter_by(user_id=user_id).update({"is_default": False})
        payment_method.is_default = True
        db.session.commit()

        return jsonify({"payment_method": payment_method.to_dict()}), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to set default payment method", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


# ===== Transactions (UC 2.19) =====

@bp.get("/users/<int:user_id>/transactions")
def get_transactions(user_id: int) -> tuple[dict[str, object], int]:
    """Get payment history for a user (UC 2.19)."""
    try:
        from .models import Transaction

        # Get query parameters
        page = request.args.get("page", 1, type=int)
        limit = request.args.get("limit", 20, type=int)
        limit = min(limit, 50)  # Max 50 per page

        transactions = Transaction.query.filter_by(user_id=user_id).order_by(
            Transaction.transaction_date.desc()
        ).paginate(page=page, per_page=limit)

        return jsonify({
            "transactions": [t.to_dict() for t in transactions.items],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": transactions.total,
                "pages": transactions.pages,
            }
        }), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch transactions", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp.post("/users/<int:user_id>/transactions")
def create_transaction(user_id: int) -> tuple[dict[str, object], int]:
    """Create a transaction record (UC 2.19)."""
    try:
        from .models import Transaction, Appointment

        data = request.get_json()

        # Validate required fields
        if not data.get("appointment_id") or not data.get("amount_cents"):
            return jsonify({"error": "invalid_request"}), 400

        appointment_id = data.get("appointment_id")
        amount_cents = int(data.get("amount_cents"))

        # Verify appointment exists and belongs to this user
        appointment = Appointment.query.get(appointment_id)
        if not appointment or appointment.client_id != user_id:
            return jsonify({"error": "not_found", "message": "Appointment not found"}), 404

        transaction = Transaction(
            user_id=user_id,
            appointment_id=appointment_id,
            payment_method_id=data.get("payment_method_id"),
            amount_cents=amount_cents,
            status=data.get("status", "completed"),
        )

        db.session.add(transaction)
        db.session.commit()

        return jsonify({"transaction": transaction.to_dict()}), 201

    except (ValueError, KeyError) as e:
        return jsonify({"error": "invalid_request"}), 400
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to create transaction", exc_info=exc)
        return jsonify({"error": "database_error"}), 500