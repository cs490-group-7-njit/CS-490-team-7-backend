"""Database models for the SalonHub backend."""
from __future__ import annotations

from datetime import datetime, timezone

from .extensions import db


def utc_now() -> datetime:
    """Return a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


# Association table for favorite salons (UC 2.20)
favorite_salons = db.Table(
    "favorite_salons",
    db.Column("user_id", db.Integer, db.ForeignKey("users.user_id"), primary_key=True),
    db.Column("salon_id", db.Integer, db.ForeignKey("salons.salon_id"), primary_key=True),
)


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
    favorite_salons = db.relationship(
        "Salon",
        secondary=favorite_salons,
        backref="favorited_by",
        lazy="dynamic"
    )

    def to_dict_basic(self) -> dict[str, object]:
        return {
            "id": self.user_id,
            "user_id": self.user_id,
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
    # UC 1.19: Delay notifications data
    delay_notifications_data = db.Column(db.JSON, nullable=True, default=dict)
    # UC 1.22: Social media links data
    social_media_data = db.Column(db.JSON, nullable=True, default=dict)

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


class Appointment(db.Model):
    """Client appointments at salons (UC 2.3)."""

    __tablename__ = "appointments"

    appointment_id = db.Column(db.Integer, primary_key=True)
    salon_id = db.Column(db.Integer, db.ForeignKey("salons.salon_id"), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey("staff.staff_id"), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey("services.service_id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    starts_at = db.Column(db.DateTime, nullable=False)
    ends_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(
        db.Enum(
            "booked",
            "completed",
            "cancelled",
            "no-show",
            name="appointment_status",
            native_enum=False,
            validate_strings=True,
        ),
        nullable=False,
        server_default="booked",
    )
    notes = db.Column(db.Text)

    # Added this for POST​/appointments​/{appointment_id}​/images
    image_data = db.Column(db.JSON, nullable=True, default=dict)

    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    salon = db.relationship("Salon")
    staff = db.relationship("Staff")
    service = db.relationship("Service")
    client = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.appointment_id,
            "salon_id": self.salon_id,
            "salon_name": self.salon.name if self.salon else None,
            "staff_id": self.staff_id,
            "staff": {
                "id": self.staff.staff_id,
                "user": {
                    "name": self.staff.user.name,
                    "email": self.staff.user.email
                }
            } if self.staff and self.staff.user else None,
            "service_id": self.service_id,
            "service": {
                "id": self.service.service_id,
                "name": self.service.name,
                "price_cents": self.service.price_cents,
                "duration_minutes": self.service.duration_minutes
            } if self.service else None,
            "client_id": self.client_id,
            "client": {
                "id": self.client.user_id,
                "name": self.client.name,
                "email": self.client.email,
                "phone": self.client.phone
            } if self.client else None,
            "starts_at": self.starts_at.isoformat() if self.starts_at else None,
            "ends_at": self.ends_at.isoformat() if self.ends_at else None,
            "status": self.status,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Review(db.Model):
    """Reviews and ratings for salons (UC 2.8, 1.11)."""

    __tablename__ = "reviews"

    review_id = db.Column(db.Integer, primary_key=True)
    salon_id = db.Column(db.Integer, db.ForeignKey("salons.salon_id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    comment = db.Column(db.Text)
    vendor_reply = db.Column(db.Text, nullable=True)  # UC 1.11: Vendor response
    vendor_reply_at = db.Column(db.DateTime, nullable=True)  # UC 1.11: When vendor replied
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    salon = db.relationship("Salon")
    client = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.review_id,
            "salon_id": self.salon_id,
            "client_id": self.client_id,
            "client_name": self.client.name if self.client else "Anonymous",
            "rating": self.rating,
            "comment": self.comment,
            "vendor_reply": self.vendor_reply,
            "vendor_reply_at": self.vendor_reply_at.isoformat() if self.vendor_reply_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ClientLoyalty(db.Model):
    """Client loyalty points tracking (UC 2.10, 2.11)."""

    __tablename__ = "client_loyalty"

    client_loyalty_id = db.Column(db.Integer, primary_key=True)
    salon_id = db.Column(db.Integer, db.ForeignKey("salons.salon_id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    points_balance = db.Column(db.Integer, nullable=False, default=0)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    salon = db.relationship("Salon")
    client = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "client_loyalty_id": self.client_loyalty_id,
            "salon_id": self.salon_id,
            "client_id": self.client_id,
            "points_balance": self.points_balance,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class StaffRating(db.Model):
    """Ratings and reviews for staff members (UC 2.16)."""

    __tablename__ = "staff_ratings"

    rating_id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey("staff.staff_id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    staff = db.relationship("Staff")
    client = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.rating_id,
            "staff_id": self.staff_id,
            "client_id": self.client_id,
            "client_name": self.client.name if self.client else "Anonymous",
            "rating": self.rating,
            "comment": self.comment,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class PaymentMethod(db.Model):
    """Payment methods for clients (UC 2.18)."""

    __tablename__ = "payment_methods"

    payment_method_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    card_holder_name = db.Column(db.String(255), nullable=False)
    card_number_last_four = db.Column(db.String(4), nullable=False)
    card_brand = db.Column(db.String(50), nullable=False)  # Visa, Mastercard, Amex
    expiry_month = db.Column(db.Integer, nullable=False)
    expiry_year = db.Column(db.Integer, nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    user = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.payment_method_id,
            "user_id": self.user_id,
            "card_holder_name": self.card_holder_name,
            "card_number_last_four": self.card_number_last_four,
            "card_brand": self.card_brand,
            "expiry_month": self.expiry_month,
            "expiry_year": self.expiry_year,
            "is_default": self.is_default,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Transaction(db.Model):
    """Payment transactions (UC 2.19)."""

    __tablename__ = "transactions"

    transaction_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey("appointments.appointment_id"), nullable=False)
    payment_method_id = db.Column(db.Integer, db.ForeignKey("payment_methods.payment_method_id"), nullable=True)
    amount_cents = db.Column(db.Integer, nullable=False)
    # Track payment gateway identifier (e.g. Stripe payment intent id)
    gateway_payment_id = db.Column(db.String(255), nullable=True, unique=True)

    status = db.Column(db.String(50), nullable=False, default="completed")  # completed, pending, failed, refunded
    transaction_date = db.Column(db.DateTime, nullable=False, default=utc_now)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    user = db.relationship("User")
    appointment = db.relationship("Appointment")
    payment_method = db.relationship("PaymentMethod")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.transaction_id,
            "user_id": self.user_id,
            "appointment_id": self.appointment_id,
            "payment_method_id": self.payment_method_id,
            "amount_cents": self.amount_cents,
            "amount_dollars": self.amount_cents / 100.0,
            "status": self.status,
            "transaction_date": self.transaction_date.isoformat() if self.transaction_date else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "gateway_payment_id": self.gateway_payment_id,
        }


# UC 2.5 - Notifications
class Notification(db.Model):
    __tablename__ = "notifications"

    notification_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey("appointments.appointment_id"), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(
        db.Enum(
            "appointment_confirmed",
            "appointment_cancelled",
            "appointment_rescheduled",
            "appointment_completed",
            "appointment_delayed",
            "message_received",
            "discount_alert",
            "loyalty_points_earned",
            "loyalty_redeemed",
            name="notification_type",
            native_enum=False,
            validate_strings=True,
        ),
        nullable=False,
    )
    is_read = db.Column(db.Boolean, nullable=False, server_default="0")
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    user = db.relationship("User")
    appointment = db.relationship("Appointment")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.notification_id,
            "user_id": self.user_id,
            "appointment_id": self.appointment_id,
            "title": self.title,
            "message": self.message,
            "notification_type": self.notification_type,
            "is_read": self.is_read,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# UC 2.7 - Messaging
class Message(db.Model):
    __tablename__ = "messages"

    message_id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    salon_id = db.Column(db.Integer, db.ForeignKey("salons.salon_id"), nullable=True)
    subject = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, server_default="0")
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)

    sender = db.relationship("User", foreign_keys=[sender_id])
    recipient = db.relationship("User", foreign_keys=[recipient_id])
    salon = db.relationship("Salon")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.message_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "salon_id": self.salon_id,
            "subject": self.subject,
            "body": self.body,
            "is_read": self.is_read,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# UC 2.13 - Loyalty Redemption
class LoyaltyRedemption(db.Model):
    __tablename__ = "loyalty_redemptions"

    redemption_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    points_redeemed = db.Column(db.Integer, nullable=False)
    discount_code = db.Column(db.String(50), unique=True, nullable=False)
    discount_value_cents = db.Column(db.Integer, nullable=False)
    is_used = db.Column(db.Boolean, nullable=False, server_default="0")
    redeemed_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.redemption_id,
            "user_id": self.user_id,
            "points_redeemed": self.points_redeemed,
            "discount_code": self.discount_code,
            "discount_value_cents": self.discount_value_cents,
            "discount_value_dollars": self.discount_value_cents / 100.0,
            "is_used": self.is_used,
            "redeemed_at": self.redeemed_at.isoformat() if self.redeemed_at else None,
            "used_at": self.used_at.isoformat() if self.used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


# UC 2.14 - Discount Alerts
class DiscountAlert(db.Model):
    __tablename__ = "discount_alerts"

    alert_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    salon_id = db.Column(db.Integer, db.ForeignKey("salons.salon_id"), nullable=True)
    discount_percentage = db.Column(db.Integer, nullable=False)
    discount_cents = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, server_default="0")
    is_dismissed = db.Column(db.Boolean, nullable=False, server_default="0")
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    expires_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship("User")
    salon = db.relationship("Salon")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.alert_id,
            "user_id": self.user_id,
            "salon_id": self.salon_id,
            "discount_percentage": self.discount_percentage,
            "discount_cents": self.discount_cents,
            "discount_dollars": self.discount_cents / 100.0,
            "description": self.description,
            "is_read": self.is_read,
            "is_dismissed": self.is_dismissed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


# UC 2.15 - Products
class Product(db.Model):
    __tablename__ = "products"

    product_id = db.Column(db.Integer, primary_key=True)
    salon_id = db.Column(db.Integer, db.ForeignKey("salons.salon_id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price_cents = db.Column(db.Integer, nullable=False)
    stock_quantity = db.Column(db.Integer, nullable=False, server_default="0")
    category = db.Column(db.String(100))
    is_available = db.Column(db.Boolean, nullable=False, server_default="1")
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)

    salon = db.relationship("Salon")
    purchases = db.relationship("ProductPurchase", back_populates="product")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.product_id,
            "salon_id": self.salon_id,
            "name": self.name,
            "description": self.description,
            "price_cents": self.price_cents,
            "price_dollars": self.price_cents / 100.0,
            "stock_quantity": self.stock_quantity,
            "category": self.category,
            "is_available": self.is_available,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ProductPurchase(db.Model):
    __tablename__ = "product_purchases"

    purchase_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.product_id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price_cents = db.Column(db.Integer, nullable=False)
    total_price_cents = db.Column(db.Integer, nullable=False)
    order_status = db.Column(
        db.Enum(
            "pending",
            "confirmed",
            "shipped",
            "delivered",
            "cancelled",
            name="product_order_status",
            native_enum=False,
            validate_strings=True,
        ),
        nullable=False,
        server_default="pending",
    )
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)

    user = db.relationship("User")
    product = db.relationship("Product", back_populates="purchases")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.purchase_id,
            "user_id": self.user_id,
            "product_id": self.product_id,
            "quantity": self.quantity,
            "unit_price_cents": self.unit_price_cents,
            "unit_price_dollars": self.unit_price_cents / 100.0,
            "total_price_cents": self.total_price_cents,
            "total_price_dollars": self.total_price_cents / 100.0,
            "order_status": self.order_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# UC 1.12: Appointment Memos
class AppointmentMemo(db.Model):
    """Vendor memos/notes for appointments sent to clients."""

    __tablename__ = "appointment_memos"

    memo_id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey("appointments.appointment_id"), nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    appointment = db.relationship("Appointment")
    vendor = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.memo_id,
            "appointment_id": self.appointment_id,
            "vendor_id": self.vendor_id,
            "content": self.content,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# UC 1.17: Service Images (Before/After)
class ServiceImage(db.Model):
    """Before and after images for services."""

    __tablename__ = "service_images"

    image_id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey("services.service_id"), nullable=False)
    image_type = db.Column(
        db.Enum("before", "after", name="image_type", native_enum=False, validate_strings=True),
        nullable=False,
    )
    image_url = db.Column(db.String(500), nullable=False)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    service = db.relationship("Service")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.image_id,
            "service_id": self.service_id,
            "image_type": self.image_type,
            "image_url": self.image_url,
            "title": self.title,
            "description": self.description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# UC 1.18: Promotions
class Promotion(db.Model):
    """Promotional offers created by vendors."""

    __tablename__ = "promotions"

    promotion_id = db.Column(db.Integer, primary_key=True)
    salon_id = db.Column(db.Integer, db.ForeignKey("salons.salon_id"), nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    discount_percent = db.Column(db.Integer)
    discount_amount_cents = db.Column(db.Integer)
    target_customers = db.Column(db.String(50), default="all")  # "all", "loyal", "new"
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, server_default="1")
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    salon = db.relationship("Salon")
    vendor = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.promotion_id,
            "salon_id": self.salon_id,
            "vendor_id": self.vendor_id,
            "title": self.title,
            "description": self.description,
            "discount_percent": self.discount_percent,
            "discount_amount_cents": self.discount_amount_cents,
            "discount_amount_dollars": self.discount_amount_cents / 100.0 if self.discount_amount_cents else None,
            "target_customers": self.target_customers,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# UC 1.19: Delay Notifications
class DelayNotification(db.Model):
    """Notifications when barbers are running late."""

    __tablename__ = "delay_notifications"

    notification_id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey("appointments.appointment_id"), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey("staff.staff_id"), nullable=False)
    delay_minutes = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(500))
    sent_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    appointment = db.relationship("Appointment")
    staff = db.relationship("Staff")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.notification_id,
            "appointment_id": self.appointment_id,
            "staff_id": self.staff_id,
            "delay_minutes": self.delay_minutes,
            "reason": self.reason,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# UC 1.20: Online Shop Products
class ShopProduct(db.Model):
    """Products sold in the salon's online shop."""

    __tablename__ = "shop_products"

    product_id = db.Column(db.Integer, primary_key=True)
    salon_id = db.Column(db.Integer, db.ForeignKey("salons.salon_id"), nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey("users.user_id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price_cents = db.Column(db.Integer, nullable=False)
    stock_quantity = db.Column(db.Integer, nullable=False, server_default="0")
    image_url = db.Column(db.String(500))
    category = db.Column(db.String(100))
    is_available = db.Column(db.Boolean, nullable=False, server_default="1")
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
    )

    salon = db.relationship("Salon")
    vendor = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.product_id,
            "salon_id": self.salon_id,
            "vendor_id": self.vendor_id,
            "name": self.name,
            "description": self.description,
            "price_cents": self.price_cents,
            "price_dollars": self.price_cents / 100.0,
            "stock_quantity": self.stock_quantity,
            "image_url": self.image_url,
            "category": self.category,
            "is_available": self.is_available,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# UC 1.22: Staff Social Media Links
class SocialMediaLink(db.Model):
    """Social media accounts for staff members."""

    __tablename__ = "social_media_links"

    link_id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.Integer, db.ForeignKey("staff.staff_id"), nullable=False)
    platform = db.Column(db.String(50), nullable=False)  # instagram, facebook, tiktok, etc.
    url = db.Column(db.String(500), nullable=False)
    handle = db.Column(db.String(100))
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
            "id": self.link_id,
            "staff_id": self.staff_id,
            "platform": self.platform,
            "url": self.url,
            "handle": self.handle,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class AppointmentImage(db.Model):
    """Before and after images for appointment transformations."""

    __tablename__ = "appointment_images"

    image_id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(
        db.Integer, db.ForeignKey("appointments.appointment_id"), nullable=False
    )
    image_type = db.Column(
        db.Enum("before", "after", name="appointment_image_type", native_enum=False, validate_strings=True),
        nullable=False,
    )
    image_url = db.Column(db.String(500), nullable=False)
    s3_key = db.Column(db.String(500))  # S3 object key for direct access
    description = db.Column(db.Text)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("users.user_id"))
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    appointment = db.relationship("Appointment")
    uploaded_by = db.relationship("User")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.image_id,
            "appointment_id": self.appointment_id,
            "image_type": self.image_type,
            "image_url": self.image_url,
            "s3_key": self.s3_key,
            "description": self.description,
            "uploaded_by_id": self.uploaded_by_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
