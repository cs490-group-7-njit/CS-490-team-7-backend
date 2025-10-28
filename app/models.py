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
