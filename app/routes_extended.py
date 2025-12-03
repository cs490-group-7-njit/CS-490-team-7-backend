"""Extended routes for UC 2.5, 2.7, 2.13, 2.14, 2.15."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request, make_response
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
        loyalty = ClientLoyalty.query.filter(ClientLoyalty.user_id == user_id).first()
        if not loyalty:
            return jsonify({"error": "no_loyalty_found"}), 404

        data = request.get_json()
        points_to_redeem = data.get("points", 0)

        if points_to_redeem <= 0:
            return jsonify({"error": "invalid_points"}), 400

        if loyalty.points_balance < points_to_redeem:
            return jsonify({"error": "insufficient_points"}), 400

        discount_value_cents = points_to_redeem * 5  # 1 point = $0.05

        import random
        import string

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

    except (ValueError, KeyError) as e:
        return jsonify({"error": "invalid_request"}), 400
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to redeem points", exc_info=exc)
        return jsonify({"error": "database_error"}), 500


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

    except (ValueError, KeyError) as e:
        return jsonify({"error": "invalid_request"}), 400
    except SQLAlchemyError as exc:
        db.session.rollback()
        current_app.logger.exception("Failed to update purchase", exc_info=exc)
        return jsonify({"error": "database_error"}), 500
    
    
