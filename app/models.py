"""Database models for the SalonHub backend."""
from __future__ import annotations

from datetime import datetime, timezone

from .extensions import db


def utc_now() -> datetime:
    """Return a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    role = db.Column(
        db.Enum(
            "client",
            "vendor",
            "admin",
            name="user_role",
            native_enum=False,
            validate_strings=True,
        ),
        nullable=False,
        server_default="client",
    )
    phone = db.Column(db.String(30))
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    salons = db.relationship("Salon", back_populates="vendor", lazy="dynamic")
    auth_account = db.relationship("AuthAccount", back_populates="user", uselist=False)

    def to_dict_basic(self) -> dict[str, object]:
        return {
            "id": self.user_id,
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "phone": self.phone,
        }


class Salon(db.Model):
    __tablename__ = "salons"

    salon_id = db.Column(db.Integer, primary_key=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    business_type = db.Column(db.String(100))
    address_line1 = db.Column(db.String(150))
    address_line2 = db.Column(db.String(150))
    city = db.Column(db.String(100))
    state = db.Column(db.String(100))
    postal_code = db.Column(db.String(20))
    phone = db.Column(db.String(30))
    is_published = db.Column(db.Boolean, nullable=False, server_default="0")
    verification_status = db.Column(
        db.Enum(
            "pending",
            "approved",
            "rejected",
            name="verification_status",
            native_enum=False,
            validate_strings=True,
        ),
        nullable=False,
        server_default="pending",
    )
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    vendor = db.relationship("User", back_populates="salons")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.salon_id,
            "name": self.name,
            "description": self.description,
            "business_type": self.business_type,
            "address": {
                "line1": self.address_line1,
                "line2": self.address_line2,
                "city": self.city,
                "state": self.state,
                "postal_code": self.postal_code,
            },
            "phone": self.phone,
            "is_published": bool(self.is_published),
            "verification_status": self.verification_status,
            "vendor": self.vendor.to_dict_basic() if self.vendor else None,
        }

class AuthAccount(db.Model):
    __tablename__ = "auth_accounts"

    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), primary_key=True)
    password_hash = db.Column(db.String(255), nullable=False)
    last_login_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)

    user = db.relationship("User", back_populates="auth_account")


class Staff(db.Model):
    __tablename__ = "staff"

    staff_id = db.Column(db.Integer, primary_key=True)
    salon_id = db.Column(db.Integer, db.ForeignKey("salons.salon_id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=True)
    title = db.Column(db.String(100), nullable=False)
    schedule = db.Column(db.JSON, nullable=True, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    salon = db.relationship("Salon")
    user = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.staff_id,
            "salon_id": self.salon_id,
            "user_id": self.user_id,
            "title": self.title,
            "schedule": self.schedule or {},
            "user": self.user.to_dict_basic() if self.user else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Schedule(db.Model):
    """Weekly schedule for a staff member (UC 1.7)."""

    __tablename__ = "schedules"

    schedule_id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey("staff.staff_id"), nullable=False)
    day_of_week = db.Column(db.Integer, nullable=False)  # 0=Sunday, 1=Monday, etc.
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    staff = db.relationship("Staff")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.schedule_id,
            "staff_id": self.staff_id,
            "day_of_week": self.day_of_week,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class TimeBlock(db.Model):
    """Time block (e.g., break, holiday) for a staff member (UC 1.7, UC 1.14)."""

    __tablename__ = "time_blocks"

    block_id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey("staff.staff_id"), nullable=False)
    starts_at = db.Column(db.DateTime, nullable=False)
    ends_at = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    staff = db.relationship("Staff")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.block_id,
            "staff_id": self.staff_id,
            "starts_at": self.starts_at.isoformat() if self.starts_at else None,
            "ends_at": self.ends_at.isoformat() if self.ends_at else None,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Service(db.Model):
    """Services offered by a salon (UC 2.2)."""

    __tablename__ = "services"

    service_id = db.Column(db.Integer, primary_key=True)
    salon_id = db.Column(db.Integer, db.ForeignKey("salons.salon_id"), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    price_cents = db.Column(db.Integer, nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    salon = db.relationship("Salon")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.service_id,
            "salon_id": self.salon_id,
            "name": self.name,
            "description": self.description,
            "price_cents": self.price_cents,
            "price_dollars": self.price_cents / 100.0,
            "duration_minutes": self.duration_minutes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }