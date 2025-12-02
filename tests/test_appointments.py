"""Tests for appointment status updates with null safety."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import Appointment, Notification, Salon, Service, Staff, User


def test_appointment_status_update_with_null_staff(app, client) -> None:
    """Test that appointment status update handles null staff gracefully."""
    with app.app_context():
        # Create test data
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        client_user = User(name="Charlie Client", email="charlie@example.com", role="client")
        db.session.add_all([vendor, client_user])
        db.session.flush()

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

        # Create staff without user (user_id is nullable)
        staff = Staff(
            salon_id=salon.salon_id,
            user_id=None,  # Explicitly null
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
            client_id=client_user.user_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()

        appointment_id = appointment.appointment_id

    # Update appointment status to completed
    response = client.put(
        f"/appointments/{appointment_id}/status",
        json={"status": "completed"},
    )
    
    assert response.status_code == 200

    # Verify notification was created with fallback text
    with app.app_context():
        notification = Notification.query.filter_by(
            appointment_id=appointment_id,
            notification_type="appointment_completed",
        ).first()
        
        assert notification is not None
        assert "the salon" in notification.message
        assert "You earned 30 loyalty points!" in notification.message


def test_appointment_status_update_with_null_staff_user(app, client) -> None:
    """Test that appointment status update handles staff with null user gracefully."""
    with app.app_context():
        # Create test data
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        client_user = User(name="Charlie Client", email="charlie@example.com", role="client")
        db.session.add_all([vendor, client_user])
        db.session.flush()

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

        # Create staff with invalid user_id (user doesn't exist)
        staff = Staff(
            salon_id=salon.salon_id,
            user_id=99999,  # Non-existent user
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()

        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=5000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.flush()

        # Create appointment
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=client_user.user_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()

        appointment_id = appointment.appointment_id

    # Update appointment status to cancelled
    response = client.put(
        f"/appointments/{appointment_id}/status",
        json={"status": "cancelled"},
    )
    
    assert response.status_code == 200

    # Verify notification was created with fallback text
    with app.app_context():
        notification = Notification.query.filter_by(
            appointment_id=appointment_id,
            notification_type="appointment_cancelled",
        ).first()
        
        assert notification is not None
        assert "the salon" in notification.message
        assert notification.message == "Your appointment at the salon has been cancelled."


def test_appointment_status_update_with_valid_staff_user(app, client) -> None:
    """Test that appointment status update uses staff name when available."""
    with app.app_context():
        # Create test data
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        client_user = User(name="Charlie Client", email="charlie@example.com", role="client")
        staff_user = User(name="Sarah Stylist", email="sarah@example.com", role="client")
        db.session.add_all([vendor, client_user, staff_user])
        db.session.flush()

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

        # Create staff with valid user
        staff = Staff(
            salon_id=salon.salon_id,
            user_id=staff_user.user_id,
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()

        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=4000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.flush()

        # Create appointment
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=client_user.user_id,
            starts_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ends_at=datetime.now(timezone.utc) + timedelta(hours=2),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()

        appointment_id = appointment.appointment_id

    # Update appointment status to no-show
    response = client.put(
        f"/appointments/{appointment_id}/status",
        json={"status": "no-show"},
    )
    
    assert response.status_code == 200

    # Verify notification was created with staff name
    with app.app_context():
        notification = Notification.query.filter_by(
            appointment_id=appointment_id,
            notification_type="appointment_cancelled",  # no-show uses this type
        ).first()
        
        assert notification is not None
        assert "Sarah Stylist's salon" in notification.message
        assert notification.message == "You missed your appointment at Sarah Stylist's salon."


def test_appointment_completed_status_with_zero_points(app, client) -> None:
    """Test that completed notification works when points_earned is 0."""
    with app.app_context():
        # Create test data
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        client_user = User(name="Charlie Client", email="charlie@example.com", role="client")
        staff_user = User(name="Sarah Stylist", email="sarah@example.com", role="client")
        db.session.add_all([vendor, client_user, staff_user])
        db.session.flush()

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
            user_id=staff_user.user_id,
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()

        # Service with 0 price
        service = Service(
            salon_id=salon.salon_id,
            name="Free Consultation",
            price_cents=0,  # Free service
            duration_minutes=15,
        )
        db.session.add(service)
        db.session.flush()

        # Create appointment
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=client_user.user_id,
            starts_at=datetime.now(timezone.utc) - timedelta(hours=1),
            ends_at=datetime.now(timezone.utc),
            status="booked",
        )
        db.session.add(appointment)
        db.session.commit()

        appointment_id = appointment.appointment_id

    # Update appointment status to completed
    response = client.put(
        f"/appointments/{appointment_id}/status",
        json={"status": "completed"},
    )
    
    assert response.status_code == 200

    # Verify notification was created with 0 points
    with app.app_context():
        notification = Notification.query.filter_by(
            appointment_id=appointment_id,
            notification_type="appointment_completed",
        ).first()
        
        assert notification is not None
        assert "You earned 0 loyalty points!" in notification.message


def test_appointment_already_completed_status_update(app, client) -> None:
    """Test updating an already completed appointment to completed doesn't error."""
    with app.app_context():
        # Create test data
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        client_user = User(name="Charlie Client", email="charlie@example.com", role="client")
        staff_user = User(name="Sarah Stylist", email="sarah@example.com", role="client")
        db.session.add_all([vendor, client_user, staff_user])
        db.session.flush()

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
            user_id=staff_user.user_id,
            title="Stylist",
        )
        db.session.add(staff)
        db.session.flush()

        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            price_cents=2500,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.flush()

        # Create appointment that's already completed
        appointment = Appointment(
            salon_id=salon.salon_id,
            staff_id=staff.staff_id,
            service_id=service.service_id,
            client_id=client_user.user_id,
            starts_at=datetime.now(timezone.utc) - timedelta(hours=2),
            ends_at=datetime.now(timezone.utc) - timedelta(hours=1),
            status="completed",  # Already completed
        )
        db.session.add(appointment)
        db.session.commit()

        appointment_id = appointment.appointment_id

    # Try to update to completed again (should succeed but award 0 points)
    response = client.put(
        f"/appointments/{appointment_id}/status",
        json={"status": "completed"},
    )
    
    # Should return 200 OK and not throw UnboundLocalError for points_earned
    assert response.status_code == 200
    
    # Verify notification message includes 0 points (not undefined)
    with app.app_context():
        notification = Notification.query.filter_by(
            appointment_id=appointment_id,
            notification_type="appointment_completed",
        ).first()
        
        assert notification is not None
        assert "You earned 0 loyalty points!" in notification.message
