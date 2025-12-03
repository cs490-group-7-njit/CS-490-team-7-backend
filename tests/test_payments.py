"""Tests for payment endpoints."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.extensions import db
from app.models import Appointment, Salon, Service, Staff, Transaction, User


@pytest.fixture
def stripe_mock():
    """Mock Stripe API calls."""
    with patch("app.routes.stripe") as mock_stripe:
        # Mock PaymentIntent object
        mock_intent = MagicMock()
        mock_intent.id = "pi_test123"
        mock_intent.client_secret = "pi_test123_secret_abc"
        mock_intent.amount = 3000
        mock_intent.status = "succeeded"
        
        mock_stripe.PaymentIntent.create.return_value = mock_intent
        mock_stripe.PaymentIntent.retrieve.return_value = mock_intent
        
        # Mock Stripe error classes
        mock_stripe.error.StripeError = Exception
        mock_stripe.error.InvalidRequestError = Exception
        
        yield mock_stripe


def test_create_payment_intent_without_auth(app, client) -> None:
    """Test that create_payment_intent requires authentication."""
    response = client.post(
        "/create-payment-intent",
        json={"appointment_id": 1},
    )
    
    assert response.status_code == 401
    data = response.get_json()
    assert data["error"] == "unauthorized"


def test_create_payment_intent_with_missing_appointment(app, client, stripe_mock) -> None:
    """Test create_payment_intent with non-existent appointment."""
    with app.app_context():
        # Create test user
        user = User(name="Test User", email="test@example.com", role="client")
        db.session.add(user)
        db.session.commit()
        user_id = user.user_id
    
    # Mock get_jwt_identity to return user_id
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        response = client.post(
            "/create-payment-intent",
            json={"appointment_id": 9999},
        )
    
    assert response.status_code == 404
    data = response.get_json()
    assert data["error"] == "not_found"


def test_create_payment_intent_unauthorized_appointment(app, client, stripe_mock) -> None:
    """Test that user cannot create payment intent for another user's appointment."""
    with app.app_context():
        # Create users
        user1 = User(name="User One", email="user1@example.com", role="client")
        user2 = User(name="User Two", email="user2@example.com", role="client")
        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add_all([user1, user2, vendor])
        db.session.flush()
        
        # Create salon
        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Test St",
            city="New York",
            state="NY",
            postal_code="10001",
            phone="212-555-0101",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()
        
        staff = Staff(
            salon_id=salon.salon_id,
            user_id=None,
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()
        
        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=3000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.flush()
        
        # Create appointment for user1
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=user1.user_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()
        
        appointment_id = appointment.appointment_id
        user2_id = user2.user_id
    
    # Mock get_jwt_identity to return user2_id (different user)
    with patch("app.routes.get_jwt_identity", return_value=user2_id):
        # Mock Stripe config
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_fake"
            response = client.post(
                "/create-payment-intent",
                json={"appointment_id": appointment_id},
            )
    
    assert response.status_code == 403
    data = response.get_json()
    assert data["error"] == "forbidden"


def test_create_payment_intent_appointment_without_service(app, client) -> None:
    """Test create_payment_intent with missing service (edge case - service was deleted)."""
    with app.app_context():
        # Create users
        user = User(name="Test User", email="test@example.com", role="client")
        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add_all([user, vendor])
        db.session.flush()
        
        # Create salon
        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Test St",
            city="New York",
            state="NY",
            postal_code="10001",
            phone="212-555-0101",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()
        
        staff = Staff(
            salon_id=salon.salon_id,
            user_id=None,
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()
        
        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=3000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.flush()
        
        # Create appointment with service
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=user.user_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()
        
        # Delete the service to simulate edge case where service was removed after appointment was created
        db.session.delete(service)
        db.session.commit()
        
        appointment_id = appointment.appointment_id
        user_id = user.user_id
    
    # Mock get_jwt_identity
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        # Mock Stripe config
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_fake"
            response = client.post(
                "/create-payment-intent",
                json={"appointment_id": appointment_id},
            )
    
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "invalid_appointment"


def test_create_payment_intent_success(app, client, stripe_mock) -> None:
    """Test successful payment intent creation."""
    with app.app_context():
        # Create users
        user = User(name="Test User", email="test@example.com", role="client")
        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add_all([user, vendor])
        db.session.flush()
        
        # Create salon
        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Test St",
            city="New York",
            state="NY",
            postal_code="10001",
            phone="212-555-0101",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()
        
        staff = Staff(
            salon_id=salon.salon_id,
            user_id=None,
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()
        
        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=3000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.flush()
        
        # Create appointment
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=user.user_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()
        
        appointment_id = appointment.appointment_id
        user_id = user.user_id
    
    # Mock get_jwt_identity
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        # Mock Stripe config
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_fake"
            response = client.post(
                "/create-payment-intent",
                json={"appointment_id": appointment_id},
            )
    
    assert response.status_code == 200
    data = response.get_json()
    assert "client_secret" in data
    assert "payment_intent_id" in data
    assert data["payment_intent_id"] == "pi_test123"


def test_create_payment_intent_with_service_id(app, client, stripe_mock) -> None:
    """Test creating payment intent with service_id instead of appointment_id."""
    with app.app_context():
        # Create users
        user = User(name="Test User", email="test@example.com", role="client")
        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add_all([user, vendor])
        db.session.flush()
        
        # Create salon
        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Test St",
            city="New York",
            state="NY",
            postal_code="10001",
            phone="212-555-0101",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()
        
        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=3000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.commit()
        
        service_id = service.service_id
        user_id = user.user_id
    
    # Mock get_jwt_identity
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        # Mock Stripe config
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_fake"
            response = client.post(
                "/create-payment-intent",
                json={"service_id": service_id},
            )
    
    assert response.status_code == 200
    data = response.get_json()
    assert "client_secret" in data
    assert "payment_intent_id" in data
    assert data["payment_intent_id"] == "pi_test123"
    
    # Verify the correct amount was used
    stripe_mock.PaymentIntent.create.assert_called_once()
    call_args = stripe_mock.PaymentIntent.create.call_args
    assert call_args[1]["amount"] == 3000


def test_create_payment_intent_with_missing_service(app, client, stripe_mock) -> None:
    """Test create_payment_intent with non-existent service_id."""
    with app.app_context():
        # Create test user
        user = User(name="Test User", email="test@example.com", role="client")
        db.session.add(user)
        db.session.commit()
        user_id = user.user_id
    
    # Mock get_jwt_identity to return user_id
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        response = client.post(
            "/create-payment-intent",
            json={"service_id": 9999},
        )
    
    assert response.status_code == 404
    data = response.get_json()
    assert data["error"] == "not_found"
    assert data["message"] == "Service not found"


def test_confirm_payment_without_auth(app, client) -> None:
    """Test that confirm_payment requires authentication."""
    response = client.post(
        "/confirm-payment",
        json={"payment_intent_id": "pi_test123", "appointment_id": 1},
    )
    
    assert response.status_code == 401
    data = response.get_json()
    assert data["error"] == "unauthorized"


def test_confirm_payment_unauthorized_appointment(app, client, stripe_mock) -> None:
    """Test that user cannot confirm payment for another user's appointment."""
    with app.app_context():
        # Create users
        user1 = User(name="User One", email="user1@example.com", role="client")
        user2 = User(name="User Two", email="user2@example.com", role="client")
        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add_all([user1, user2, vendor])
        db.session.flush()
        
        # Create salon
        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Test St",
            city="New York",
            state="NY",
            postal_code="10001",
            phone="212-555-0101",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()
        
        staff = Staff(
            salon_id=salon.salon_id,
            user_id=None,
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()
        
        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=3000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.flush()
        
        # Create appointment for user1
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=user1.user_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()
        
        appointment_id = appointment.appointment_id
        user2_id = user2.user_id
    
    # Mock get_jwt_identity to return user2_id (different user)
    with patch("app.routes.get_jwt_identity", return_value=user2_id):
        # Mock Stripe config
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_fake"
            response = client.post(
                "/confirm-payment",
                json={"payment_intent_id": "pi_test123", "appointment_id": appointment_id},
            )
    
    assert response.status_code == 403
    data = response.get_json()
    assert data["error"] == "forbidden"


def test_confirm_payment_prevents_duplicate_transactions(app, client, stripe_mock) -> None:
    """Test that confirm_payment prevents duplicate transaction creation."""
    with app.app_context():
        # Create users
        user = User(name="Test User", email="test@example.com", role="client")
        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add_all([user, vendor])
        db.session.flush()
        
        # Create salon
        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Test St",
            city="New York",
            state="NY",
            postal_code="10001",
            phone="212-555-0101",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()
        
        staff = Staff(
            salon_id=salon.salon_id,
            user_id=None,
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()
        
        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=3000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.flush()
        
        # Create appointment
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=user.user_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.flush()
        
        # Create existing transaction
        existing_tx = Transaction(
            user_id=user.user_id,
            appointment_id=appointment.appointment_id,
            payment_method_id=None,
            amount_cents=3000,
            status="completed",
            gateway_payment_id="pi_test123",
        )
        db.session.add(existing_tx)
        db.session.commit()
        
        appointment_id = appointment.appointment_id
        user_id = user.user_id
        existing_tx_id = existing_tx.transaction_id
    
    # Mock get_jwt_identity
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        # Mock Stripe config
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_fake"
            response = client.post(
                "/confirm-payment",
                json={"payment_intent_id": "pi_test123", "appointment_id": appointment_id},
            )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    # Should return the existing transaction ID
    assert data["transaction_id"] == existing_tx_id
    
    # Verify only one transaction exists
    with app.app_context():
        count = Transaction.query.filter_by(gateway_payment_id="pi_test123").count()
        assert count == 1


def test_confirm_payment_success(app, client, stripe_mock) -> None:
    """Test successful payment confirmation and transaction creation."""
    with app.app_context():
        # Create users
        user = User(name="Test User", email="test@example.com", role="client")
        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add_all([user, vendor])
        db.session.flush()
        
        # Create salon
        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Test St",
            city="New York",
            state="NY",
            postal_code="10001",
            phone="212-555-0101",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()
        
        staff = Staff(
            salon_id=salon.salon_id,
            user_id=None,
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()
        
        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=3000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.flush()
        
        # Create appointment
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=user.user_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()
        
        appointment_id = appointment.appointment_id
        user_id = user.user_id
    
    # Mock get_jwt_identity
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        # Mock Stripe config
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_fake"
            response = client.post(
                "/confirm-payment",
                json={"payment_intent_id": "pi_test123", "appointment_id": appointment_id},
            )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert "transaction_id" in data
    
    # Verify transaction was created
    with app.app_context():
        tx = Transaction.query.filter_by(gateway_payment_id="pi_test123").first()
        assert tx is not None
        assert tx.user_id == user_id
        assert tx.appointment_id == appointment_id
        assert tx.amount_cents == 3000
        assert tx.status == "completed"


def test_stripe_webhook_invalid_payload(app, client) -> None:
    """Test webhook with invalid payload."""
    with patch("app.routes.current_app") as mock_app:
        mock_app.config.get.return_value = "whsec_test"
        with patch("app.routes.stripe.Webhook.construct_event", side_effect=ValueError):
            response = client.post(
                "/stripe-webhook",
                data=b"invalid",
                headers={"Stripe-Signature": "sig_test"},
            )
    
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "invalid_payload"


def test_stripe_webhook_invalid_signature(app, client) -> None:
    """Test webhook with invalid signature."""
    # Create a proper mock exception class
    class MockSignatureVerificationError(Exception):
        """Mock Stripe SignatureVerificationError."""
        pass
    
    with patch("app.routes.current_app") as mock_app:
        mock_app.config.get.return_value = "whsec_test"
        with patch("app.routes.stripe.error.SignatureVerificationError", MockSignatureVerificationError):
            with patch("app.routes.stripe.Webhook.construct_event", side_effect=MockSignatureVerificationError):
                response = client.post(
                    "/stripe-webhook",
                    data=b"payload",
                    headers={"Stripe-Signature": "sig_invalid"},
                )
    
    assert response.status_code == 400
    data = response.get_json()
    assert data["error"] == "invalid_signature"


def test_stripe_webhook_payment_intent_succeeded(app, client, stripe_mock) -> None:
    """Test webhook handling of payment_intent.succeeded event."""
    with app.app_context():
        # Create users
        user = User(name="Test User", email="test@example.com", role="client")
        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add_all([user, vendor])
        db.session.flush()
        
        # Create salon
        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Test St",
            city="New York",
            state="NY",
            postal_code="10001",
            phone="212-555-0101",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()
        
        staff = Staff(
            salon_id=salon.salon_id,
            user_id=None,
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()
        
        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=3000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.flush()
        
        # Create appointment
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=user.user_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()
        
        appointment_id = appointment.appointment_id
        user_id = user.user_id
    
    # Mock webhook event
    mock_event = {
        "type": "payment_intent.succeeded",
        "data": {
            "object": {
                "id": "pi_webhook_test",
                "amount": 3000,
                "metadata": {
                    "appointment_id": str(appointment_id),
                    "client_id": str(user_id),
                },
            }
        },
    }
    
    with patch("app.routes.current_app") as mock_app:
        mock_app.config.get.return_value = "whsec_test"
        with patch("app.routes.stripe.Webhook.construct_event", return_value=mock_event):
            response = client.post(
                "/stripe-webhook",
                data=b"payload",
                headers={"Stripe-Signature": "sig_test"},
            )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data["received"] is True
    
    # Verify transaction was created
    with app.app_context():
        tx = Transaction.query.filter_by(gateway_payment_id="pi_webhook_test").first()
        assert tx is not None
        assert tx.user_id == user_id
        assert tx.appointment_id == appointment_id
        assert tx.amount_cents == 3000
        assert tx.status == "completed"


def test_confirm_payment_non_succeeded_status(app, client, stripe_mock) -> None:
    """Test confirm_payment with a payment intent that has not succeeded."""
    with app.app_context():
        # Create test data
        user = User(name="Test User", email="test@example.com", role="client")
        db.session.add(user)
        db.session.commit()
        user_id = user.user_id

        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add(vendor)
        db.session.commit()

        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Main St",
            city="Test City",
            state="NY",
            postal_code="10001",
            phone="555-1234",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.commit()

        staff = Staff(salon_id=salon.salon_id, user_id=None, title="Stylist")
        db.session.add(staff)
        db.session.commit()

        service = Service(name="Test Service", description="Test", duration_minutes=60, price_cents=3000, salon_id=salon.salon_id)
        db.session.add(service)
        db.session.commit()

        appointment = Appointment(
            client_id=user_id,
            staff_id=staff.staff_id,
            salon_id=salon.salon_id,
            service_id=service.service_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()
        appointment_id = appointment.appointment_id

    # Mock Stripe payment intent with "processing" status
    stripe_mock.PaymentIntent.retrieve.return_value.status = "processing"
    stripe_mock.PaymentIntent.retrieve.return_value.id = "pi_test_processing"

    # Mock get_jwt_identity to return user_id
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_123"
            response = client.post(
                "/confirm-payment",
                json={
                    "payment_intent_id": "pi_test_processing",
                    "appointment_id": appointment_id,
                },
            )

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "processing"
    assert "transaction_id" not in data


def test_confirm_payment_invalid_payment_intent_id(app, client, stripe_mock) -> None:
    """Test confirm_payment with an invalid payment intent ID."""
    with app.app_context():
        # Create test data
        user = User(name="Test User", email="test@example.com", role="client")
        db.session.add(user)
        db.session.commit()
        user_id = user.user_id

        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add(vendor)
        db.session.commit()

        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Main St",
            city="Test City",
            state="NY",
            postal_code="10001",
            phone="555-1234",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.commit()

        staff = Staff(salon_id=salon.salon_id, user_id=None, title="Stylist")
        db.session.add(staff)
        db.session.commit()

        service = Service(name="Test Service", description="Test", duration_minutes=60, price_cents=3000, salon_id=salon.salon_id)
        db.session.add(service)
        db.session.commit()

        appointment = Appointment(
            client_id=user_id,
            staff_id=staff.staff_id,
            salon_id=salon.salon_id,
            service_id=service.service_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()
        appointment_id = appointment.appointment_id

    # Mock Stripe API to raise a Stripe error
    stripe_mock.PaymentIntent.retrieve.side_effect = stripe_mock.error.StripeError("Invalid payment intent")

    # Mock get_jwt_identity to return user_id
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_123"
            response = client.post(
                "/confirm-payment",
                json={
                    "payment_intent_id": "pi_invalid",
                    "appointment_id": appointment_id,
                },
            )

    assert response.status_code == 500
    data = response.get_json()
    assert data["error"] == "payment_error"


def test_create_payment_intent_with_zero_amount(app, client, stripe_mock) -> None:
    """Test create_payment_intent with a service that has zero price."""
    with app.app_context():
        # Create test data
        user = User(name="Test User", email="test@example.com", role="client")
        db.session.add(user)
        db.session.commit()
        user_id = user.user_id

        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add(vendor)
        db.session.commit()

        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Main St",
            city="Test City",
            state="NY",
            postal_code="10001",
            phone="555-1234",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.commit()

        # Service with zero price
        service = Service(name="Free Service", description="Test", duration_minutes=60, price_cents=0, salon_id=salon.salon_id)
        db.session.add(service)
        db.session.commit()
        service_id = service.service_id

    # Mock get_jwt_identity to return user_id
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_123"
            response = client.post(
                "/create-payment-intent",
                json={"service_id": service_id},
            )

    # Stripe API allows creating payment intents with 0 amount
    assert response.status_code == 200


def test_stripe_webhook_other_event_type(app, client) -> None:
    """Test webhook handler with event types other than payment_intent.succeeded."""
    # Mock webhook event for a different event type
    mock_event = {
        "type": "payment_intent.created",
        "data": {
            "object": {
                "id": "pi_test_created",
            }
        },
    }
    
    with patch("app.routes.current_app") as mock_app:
        mock_app.config.get.return_value = "whsec_test"
        with patch("app.routes.stripe.Webhook.construct_event", return_value=mock_event):
            response = client.post(
                "/stripe-webhook",
                data=b"payload",
                headers={"Stripe-Signature": "sig_test"},
            )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data["received"] is True


def test_create_payment_intent_with_both_ids(app, client, stripe_mock) -> None:
    """Test create_payment_intent with both appointment_id and service_id (should use appointment_id)."""
    with app.app_context():
        # Create test data
        user = User(name="Test User", email="test@example.com", role="client")
        db.session.add(user)
        db.session.commit()
        user_id = user.user_id

        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add(vendor)
        db.session.commit()

        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Main St",
            city="Test City",
            state="NY",
            postal_code="10001",
            phone="555-1234",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.commit()

        staff = Staff(salon_id=salon.salon_id, user_id=None, title="Stylist")
        db.session.add(staff)
        db.session.commit()

        service1 = Service(name="Service 1", description="Test", duration_minutes=60, price_cents=3000, salon_id=salon.salon_id)
        service2 = Service(name="Service 2", description="Test", duration_minutes=30, price_cents=1500, salon_id=salon.salon_id)
        db.session.add_all([service1, service2])
        db.session.commit()

        appointment = Appointment(
            client_id=user_id,
            staff_id=staff.staff_id,
            salon_id=salon.salon_id,
            service_id=service1.service_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()
        appointment_id = appointment.appointment_id
        service2_id = service2.service_id

    # Mock get_jwt_identity to return user_id
    with patch("app.routes.get_jwt_identity", return_value=user_id):
        with patch("app.routes.current_app") as mock_app:
            mock_app.config.get.return_value = "sk_test_123"
            response = client.post(
                "/create-payment-intent",
                json={
                    "appointment_id": appointment_id,
                    "service_id": service2_id,  # This should be ignored
                },
            )

    assert response.status_code == 200
    data = response.get_json()
    assert "client_secret" in data
    assert "payment_intent_id" in data
    
    # Verify that appointment_id was used (service1 price = 3000)
    stripe_mock.PaymentIntent.create.assert_called_once()
    call_args = stripe_mock.PaymentIntent.create.call_args
    assert call_args[1]["amount"] == 3000  # service1 price, not service2


def test_webhook_with_invalid_amount(app, client) -> None:
    """Test webhook handler with invalid (zero or negative) amount."""
    with app.app_context():
        user = User(name="Test User", email="test@example.com", role="client")
        db.session.add(user)
        db.session.commit()
        user_id = user.user_id

        vendor = User(name="Vendor", email="vendor@example.com", role="vendor")
        db.session.add(vendor)
        db.session.commit()

        salon = Salon(
            vendor_id=vendor.user_id,
            name="Test Salon",
            address_line1="123 Main St",
            city="Test City",
            state="NY",
            postal_code="10001",
            phone="555-1234",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.commit()

        staff = Staff(salon_id=salon.salon_id, user_id=None, title="Stylist")
        db.session.add(staff)
        db.session.commit()

        service = Service(name="Test Service", description="Test", duration_minutes=60, price_cents=3000, salon_id=salon.salon_id)
        db.session.add(service)
        db.session.commit()

        appointment = Appointment(
            client_id=user_id,
            staff_id=staff.staff_id,
            salon_id=salon.salon_id,
            service_id=service.service_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()
        appointment_id = appointment.appointment_id

    # Test with zero amount
    mock_event = {
        "type": "payment_intent.succeeded",
        "data": {
            "object": {
                "id": "pi_zero_amount",
                "amount": 0,
                "metadata": {
                    "appointment_id": str(appointment_id),
                    "client_id": str(user_id),
                },
            }
        },
    }
    
    with patch("app.routes.current_app") as mock_app:
        mock_app.config.get.return_value = "whsec_test"
        with patch("app.routes.stripe.Webhook.construct_event", return_value=mock_event):
            response = client.post(
                "/stripe-webhook",
                data=b"payload",
                headers={"Stripe-Signature": "sig_test"},
            )
    
    assert response.status_code == 200
    data = response.get_json()
    assert data["received"] is True
    
    # Verify no transaction was created
    with app.app_context():
        tx = Transaction.query.filter_by(gateway_payment_id="pi_zero_amount").first()
        assert tx is None
