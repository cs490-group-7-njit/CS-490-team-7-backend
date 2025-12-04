"""Extended routes for UC 2.5, 2.7, 2.13, 2.14, 2.15."""
from __future__ import annotations

import random
import string
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload

from .extensions import db
from .models import (ClientLoyalty, DiscountAlert, LoyaltyRedemption, Message,
                     Notification, Product, ProductPurchase, Salon, User)

bp_ext = Blueprint("api_ext", __name__)


# UC 2.5 - NOTIFICATIONS
@bp_ext.get("/users/<int:user_id>/notifications")
def get_notifications(user_id: int) -> tuple[dict[str, object], int]:
    """Get all notifications for a user with pagination.
    ---
    tags:
      - Notifications
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
      - name: page
        in: query
        type: integer
        default: 1
      - name: limit
        in: query
        type: integer
        default: 20
        maximum: 50
      - name: unread_only
        in: query
        type: boolean
        default: false
    responses:
      200:
        description: List of notifications with pagination
      400:
        description: Invalid parameters
      500:
        description: Database error
    """
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(50, max(1, int(request.args.get("limit", 20))))
        unread_only = request.args.get("unread_only", "false").lower() == "true"

        query = Notification.query.filter(Notification.user_id == user_id)

        if unread_only:
            query = query.filter(Notification.is_read.is_(False))

        total = query.count()
        notifications = (
            query.order_by(Notification.created_at.desc())
            .limit(limit)
            .offset((page - 1) * limit)
            .all()
        )

        return (
            jsonify({
                "notifications": [n.to_dict() for n in notifications],
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "pages": (total + limit - 1) // limit,
                },
                "unread_count": Notification.query.filter(
                    Notification.user_id == user_id,
                    Notification.is_read.is_(False),
                ).count(),
            }),
            200,
        )
    except (ValueError, TypeError):
        return jsonify({"error": "invalid_parameters"}), 400
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch notifications", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp_ext.put("/notifications/<int:notification_id>/read")
def mark_notification_read(notification_id: int) -> tuple[dict[str, object], int]:
    """Mark a notification as read.
    ---
    tags:
      - Notifications
    parameters:
      - name: notification_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: Notification marked as read
      404:
        description: Notification not found
      500:
        description: Database error
    """
    try:
        notification = Notification.query.get(notification_id)
        if not notification:
            return jsonify({"error": "notification_not_found"}), 404

        notification.is_read = True
        db.session.commit()
        return jsonify({"notification": notification.to_dict()}), 200
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to mark notification read", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp_ext.put("/users/<int:user_id>/notifications/read-all")
def mark_all_notifications_read(user_id: int) -> tuple[dict[str, object], int]:
    """Mark all notifications as read for a user.
    ---
    tags:
      - Notifications
    parameters:
      - in: path
        name: user_id
        required: true
        schema:
          type: integer
    responses:
      200:
        description: All notifications marked as read
      500:
        description: Database error
    """
    try:
        Notification.query.filter(Notification.user_id == user_id).update(
            {"is_read": True}
        )
        db.session.commit()
        return jsonify({"status": "all_marked_read"}), 200
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to mark all read", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


# UC 2.7 - MESSAGING
@bp_ext.get("/users/<int:user_id>/messages")
def get_messages(user_id: int) -> tuple[dict[str, object], int]:
    """Get all messages for a user.
    ---
    tags:
      - Messages
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
      - name: page
        in: query
        type: integer
        default: 1
      - name: limit
        in: query
        type: integer
        default: 20
    responses:
      200:
        description: List of messages
      500:
        description: Database error
    """
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(50, max(1, int(request.args.get("limit", 20))))

        query = Message.query.filter(
            (Message.sender_id == user_id) | (Message.recipient_id == user_id)
        )

        total = query.count()
        messages = (
            query.order_by(Message.created_at.desc())
            .limit(limit)
            .offset((page - 1) * limit)
            .all()
        )

        return (
            jsonify({
                "messages": [m.to_dict() for m in messages],
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "pages": (total + limit - 1) // limit,
                },
                "unread_count": Message.query.filter(
                    Message.recipient_id == user_id,
                    Message.is_read.is_(False),
                ).count(),
            }),
            200,
        )
    except (ValueError, TypeError):
        return jsonify({"error": "invalid_parameters"}), 400
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch messages", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp_ext.post("/messages")
def send_message() -> tuple[dict[str, object], int]:
    """Send a new message.
    ---
    tags:
      - Messages
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            recipient_id:
              type: integer
            content:
              type: string
          required:
            - recipient_id
            - content
    responses:
      201:
        description: Message sent successfully
      400:
        description: Invalid payload
      500:
        description: Database error
    """
    try:
        data = request.get_json()
        sender_id = data.get("sender_id")
        recipient_id = data.get("recipient_id")
        salon_id = data.get("salon_id")
        subject = data.get("subject", "").strip()
        body = data.get("body", "").strip()

        if not all([sender_id, recipient_id, subject, body]):
            return jsonify({"error": "missing_fields"}), 400

        sender = User.query.get(sender_id)
        recipient = User.query.get(recipient_id)
        if not sender or not recipient:
            return jsonify({"error": "user_not_found"}), 404

        message = Message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            salon_id=salon_id,
            subject=subject,
            body=body,
        )
        db.session.add(message)
        db.session.commit()

        return jsonify({"message": message.to_dict()}), 201

    except (ValueError, KeyError) as e:
        return jsonify({"error": "invalid_request"}), 400
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to send message", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp_ext.put("/messages/<int:message_id>/read")
def mark_message_read(message_id: int) -> tuple[dict[str, object], int]:
    """Mark a message as read."""
    try:
        message = Message.query.get(message_id)
        if not message:
            return jsonify({"error": "message_not_found"}), 404

        message.is_read = True
        db.session.commit()
        return jsonify({"message": message.to_dict()}), 200
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to mark message read", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


# UC 2.13 - LOYALTY REDEMPTION
@bp_ext.get("/users/<int:user_id>/loyalty/redemptions")
def get_loyalty_redemptions(user_id: int) -> tuple[dict[str, object], int]:
    """Get loyalty redemption history for a user.
    ---
    tags:
      - Loyalty
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: List of redemptions
      500:
        description: Database error
    """
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(50, max(1, int(request.args.get("limit", 20))))

        query = LoyaltyRedemption.query.filter(LoyaltyRedemption.user_id == user_id)
        total = query.count()
        redemptions = (
            query.order_by(LoyaltyRedemption.redeemed_at.desc())
            .limit(limit)
            .offset((page - 1) * limit)
            .all()
        )

        return (
            jsonify({
                "redemptions": [r.to_dict() for r in redemptions],
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "pages": (total + limit - 1) // limit,
                },
            }),
            200,
        )
    except (ValueError, TypeError):
        return jsonify({"error": "invalid_parameters"}), 400
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch redemptions", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp_ext.post("/users/<int:user_id>/loyalty/redeem")
def redeem_loyalty_points(user_id: int) -> tuple[dict[str, object], int]:
    """Redeem loyalty points for a discount code."""
    try:
        # Get the first loyalty record for this user (could have multiple per salon)
        loyalty = ClientLoyalty.query.filter_by(client_id=user_id).first()
        if not loyalty:
            return jsonify({"error": "no_loyalty_found"}), 404

        data = request.get_json()
        if not data:
            return jsonify({"error": "invalid_request"}), 400
            
        points_to_redeem = int(data.get("points", 0))

        if points_to_redeem <= 0:
            return jsonify({"error": "invalid_points"}), 400

        if loyalty.points_balance < points_to_redeem:
            return jsonify({"error": "insufficient_points"}), 400

        discount_value_cents = int(points_to_redeem * 5)  # 1 point = $0.05

        code = "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

        redemption = LoyaltyRedemption(
            user_id=user_id,
            points_redeemed=points_to_redeem,
            discount_code=code,
            discount_value_cents=discount_value_cents,
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
        )

        loyalty.points_balance -= points_to_redeem

        db.session.add(redemption)
        db.session.commit()

        return jsonify({"redemption": redemption.to_dict()}), 201

    except (ValueError, KeyError, TypeError) as e:
        current_app.logger.warning(f"Invalid redemption request: {e}")
        return jsonify({"error": "invalid_request", "message": str(e)}), 400
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to redeem points", exc_info=exc)
        return jsonify({"error": "database_error", "message": str(exc)}), 500
    except Exception as exc:
        current_app.logger.exception("Unexpected error during redemption", exc_info=exc)
        return jsonify({"error": "server_error", "message": str(exc)}), 500


# UC 2.14 - DISCOUNT ALERTS
@bp_ext.get("/users/<int:user_id>/discount-alerts")
def get_discount_alerts(user_id: int) -> tuple[dict[str, object], int]:
    """Get all discount alerts for a user."""
    try:
        active_only = request.args.get("active_only", "false").lower() == "true"

        query = DiscountAlert.query.filter(DiscountAlert.user_id == user_id)

        if active_only:
            query = query.filter(
                DiscountAlert.expires_at > datetime.now(timezone.utc),
                DiscountAlert.is_dismissed.is_(False),
            )

        alerts = query.order_by(DiscountAlert.created_at.desc()).all()

        return jsonify({"alerts": [a.to_dict() for a in alerts]}), 200

    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch discount alerts", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp_ext.put("/discount-alerts/<int:alert_id>/dismiss")
def dismiss_alert(alert_id: int) -> tuple[dict[str, object], int]:
    """Dismiss a discount alert."""
    try:
        alert = DiscountAlert.query.get(alert_id)
        if not alert:
            return jsonify({"error": "alert_not_found"}), 404

        alert.is_dismissed = True
        db.session.commit()
        return jsonify({"alert": alert.to_dict()}), 200
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to dismiss alert", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


# UC 2.15 - PRODUCTS
@bp_ext.get("/salons/<int:salon_id>/products")
def get_salon_products(salon_id: int) -> tuple[dict[str, object], int]:
    """Get products available at a salon.
    ---
    tags:
      - Products
    parameters:
      - name: salon_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: List of products
      404:
        description: Salon not found
      500:
        description: Database error
    """
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(50, max(1, int(request.args.get("limit", 12))))

        query = Product.query.filter(
            Product.salon_id == salon_id,
            Product.is_available.is_(True),
        )

        total = query.count()
        products = (
            query.order_by(Product.created_at.desc())
            .limit(limit)
            .offset((page - 1) * limit)
            .all()
        )

        return (
            jsonify({
                "products": [p.to_dict() for p in products],
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "pages": (total + limit - 1) // limit,
                },
            }),
            200,
        )
    except (ValueError, TypeError):
        return jsonify({"error": "invalid_parameters"}), 400
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch products", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp_ext.post("/users/<int:user_id>/products/purchase")
def purchase_product(user_id: int) -> tuple[dict[str, object], int]:
    """Purchase a product."""
    try:
        data = request.get_json()
        product_id = data.get("product_id")
        quantity = data.get("quantity", 1)

        if not product_id or quantity <= 0:
            return jsonify({"error": "invalid_request"}), 400

        product = Product.query.get(product_id)
        if not product:
            return jsonify({"error": "product_not_found"}), 404

        if product.stock_quantity < quantity:
            return jsonify({"error": "insufficient_stock"}), 400

        total_price = product.price_cents * quantity

        purchase = ProductPurchase(
            user_id=user_id,
            product_id=product_id,
            quantity=quantity,
            unit_price_cents=product.price_cents,
            total_price_cents=total_price,
        )

        product.stock_quantity -= quantity

        db.session.add(purchase)
        db.session.commit()

        return jsonify({"purchase": purchase.to_dict()}), 201

    except (ValueError, KeyError) as e:
        return jsonify({"error": "invalid_request"}), 400
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to create purchase", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp_ext.get("/users/<int:user_id>/product-purchases")
def get_user_purchases(user_id: int) -> tuple[dict[str, object], int]:
    """Get all product purchases for a user."""
    try:
        page = max(1, int(request.args.get("page", 1)))
        limit = min(50, max(1, int(request.args.get("limit", 20))))

        query = ProductPurchase.query.filter(ProductPurchase.user_id == user_id)
        total = query.count()
        purchases = (
            query.order_by(ProductPurchase.created_at.desc())
            .limit(limit)
            .offset((page - 1) * limit)
            .all()
        )

        return (
            jsonify({
                "purchases": [p.to_dict() for p in purchases],
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total,
                    "pages": (total + limit - 1) // limit,
                },
            }),
            200,
        )
    except (ValueError, TypeError):
        return jsonify({"error": "invalid_parameters"}), 400
    except SQLAlchemyError as exc:
        current_app.logger.exception("Failed to fetch purchases", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


@bp_ext.put("/product-purchases/<int:purchase_id>/status")
def update_purchase_status(purchase_id: int) -> tuple[dict[str, object], int]:
    """Update product purchase status."""
    try:
        data = request.get_json()
        status = data.get("status")

        valid_statuses = ["pending", "confirmed", "shipped", "delivered", "cancelled"]
        if status not in valid_statuses:
            return jsonify({"error": "invalid_status"}), 400

        purchase = ProductPurchase.query.get(purchase_id)
        if not purchase:
            return jsonify({"error": "purchase_not_found"}), 404

        purchase.order_status = status
        db.session.commit()
        return jsonify({"purchase": purchase.to_dict()}), 200


# ============================================================================
# UC 2.17 - BEFORE/AFTER SERVICE IMAGES
# ============================================================================

@bp_ext.post("/appointments/<int:appointment_id>/images")
def upload_appointment_image(appointment_id: int) -> tuple[dict[str, object], int]:
    """Upload a before/after image for an appointment."""
    try:
        import uuid
        from .models import Appointment, AppointmentImage
        
        try:
            import boto3
        except ImportError:
            return jsonify({"error": "s3_unavailable", "message": "Image upload service not configured"}), 503

        # Get appointment
        appointment = Appointment.query.get(appointment_id)
        if not appointment:
            return jsonify({"error": "appointment_not_found"}), 404

        # Check authorization (vendor or client associated with appointment)
        current_user_id = g.current_user.user_id if hasattr(g, "current_user") else None
        is_vendor = (
            appointment.staff
            and appointment.staff.user_id == current_user_id
        )
        is_client = appointment.client_id == current_user_id
        is_admin = hasattr(g, "current_user") and g.current_user.role == "admin"

        if not (is_vendor or is_client or is_admin):
            return jsonify({"error": "unauthorized"}), 403

        # Get image file from request
        if "image" not in request.files:
            return jsonify({"error": "no_image_provided"}), 400

        file = request.files["image"]
        if file.filename == "":
            return jsonify({"error": "empty_filename"}), 400

        image_type = request.form.get("type", "other")
        if image_type not in ("before", "after", "other"):
            image_type = "other"

        description = request.form.get("description", "")

        # Upload to S3
        s3_client = boto3.client("s3")
        file_extension = file.filename.split(".")[-1].lower()
        s3_key = f"appointment-images/{appointment_id}/{image_type}_{uuid.uuid4()}.{file_extension}"
        bucket_name = current_app.config.get("AWS_S3_BUCKET", "beautiful-hair-images")

        s3_client.upload_fileobj(
            file,
            bucket_name,
            s3_key,
            ExtraArgs={"ContentType": file.content_type or "image/jpeg"},
        )

        # Create database record
        image_url = f"https://{bucket_name}.s3.amazonaws.com/{s3_key}"
        appointment_image = AppointmentImage(
            appointment_id=appointment_id,
            image_type=image_type,
            image_url=image_url,
            s3_key=s3_key,
            description=description,
            uploaded_by_id=current_user_id,
        )

        db.session.add(appointment_image)
        db.session.commit()

        return jsonify({"image": appointment_image.to_dict()}), 201

    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to upload appointment image", exc_info=exc)
        return jsonify({"error": "upload_failed", "message": str(exc)}), 500


@bp_ext.get("/appointments/<int:appointment_id>/images")
def get_appointment_images(appointment_id: int) -> tuple[dict[str, object], int]:
    """Get all images for an appointment."""
    try:
        from .models import Appointment, AppointmentImage

        # Get appointment
        appointment = Appointment.query.get(appointment_id)
        if not appointment:
            return jsonify({"error": "appointment_not_found"}), 404

        # Get images
        images = AppointmentImage.query.filter_by(appointment_id=appointment_id).all()

        # Group by type
        images_by_type = {"before": [], "after": [], "other": []}
        for img in images:
            images_by_type[img.image_type].append(img.to_dict())

        return (
            jsonify(
                {
                    "appointment_id": appointment_id,
                    "images": [img.to_dict() for img in images],
                    "images_by_type": images_by_type,
                }
            ),
            200,
        )

    except Exception as exc:
        current_app.logger.exception("Failed to get appointment images", exc_info=exc)
        return jsonify({"error": "fetch_failed", "message": str(exc)}), 500


@bp_ext.delete("/appointments/<int:appointment_id>/images/<int:image_id>")
def delete_appointment_image(
    appointment_id: int, image_id: int
) -> tuple[dict[str, object], int]:
    """Delete an image from an appointment."""
    try:
        from .models import AppointmentImage
        
        try:
            import boto3
        except ImportError:
            boto3 = None

        # Get image
        image = AppointmentImage.query.get(image_id)
        if not image or image.appointment_id != appointment_id:
            return jsonify({"error": "image_not_found"}), 404

        # Check authorization
        current_user_id = g.current_user.user_id if hasattr(g, "current_user") else None
        is_uploader = image.uploaded_by_id == current_user_id
        is_admin = hasattr(g, "current_user") and g.current_user.role == "admin"

        if not (is_uploader or is_admin):
            return jsonify({"error": "unauthorized"}), 403

        # Delete from S3 if boto3 available
        if boto3 and image.s3_key:
            try:
                s3_client = boto3.client("s3")
                bucket_name = current_app.config.get("AWS_S3_BUCKET", "beautiful-hair-images")
                s3_client.delete_object(Bucket=bucket_name, Key=image.s3_key)
            except Exception as e:
                current_app.logger.warning(f"Failed to delete S3 object: {e}")

        # Delete from database
        db.session.delete(image)
        db.session.commit()

        return jsonify({"success": True}), 200

    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to delete appointment image", exc_info=exc)
        return jsonify({"error": "delete_failed", "message": str(exc)}), 500


@bp_ext.get("/services/<int:service_id>/images")
def get_service_images(service_id: int) -> tuple[dict[str, object], int]:
    """Get portfolio images for a service (before/after from appointments)."""
    try:
        from .models import (
            AppointmentImage,
            Service,
            Appointment,
        )

        # Get service
        service = Service.query.get(service_id)
        if not service:
            return jsonify({"error": "service_not_found"}), 404

        # Get all appointments with this service that have images
        images = (
            db.session.query(AppointmentImage)
            .join(Appointment)
            .filter(Appointment.service_id == service_id)
            .order_by(AppointmentImage.created_at.desc())
            .all()
        )

        # Group by type
        images_by_type = {"before": [], "after": [], "other": []}
        for img in images:
            images_by_type[img.image_type].append(img.to_dict())

        return (
            jsonify(
                {
                    "service_id": service_id,
                    "images": [img.to_dict() for img in images],
                    "images_by_type": images_by_type,
                }
            ),
            200,
        )

    except Exception as exc:
        current_app.logger.exception("Failed to get service images", exc_info=exc)
        return jsonify({"error": "fetch_failed", "message": str(exc)}), 500
    except (ValueError, KeyError) as e:
        return jsonify({"error": "invalid_request"}), 400
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update purchase", exc_info=exc)
        return jsonify({"error": "database_error"}), 500
