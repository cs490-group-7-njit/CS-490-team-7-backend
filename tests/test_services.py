"""Tests for the services endpoints (UC 2.2)."""
from __future__ import annotations

from datetime import datetime

from app.extensions import db
from app.models import Salon, Service, User


def test_list_services_for_salon(app, client) -> None:
    """Test listing services for a specific salon."""
    with app.app_context():
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        db.session.add(vendor)
        db.session.flush()

        salon = Salon(
            vendor_id=vendor.user_id,
            name="The Cutting Edge",
            address_line1="123 Shear St",
            city="New York",
            state="NY",
            postal_code="10001",
            phone="212-555-0101",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()

        salon_id = salon.salon_id

        # Create services
        service1 = Service(
            salon_id=salon_id,
            name="Haircut",
            description="Classic haircut",
            price_cents=3000,  # $30.00
            duration_minutes=30,
        )
        service2 = Service(
            salon_id=salon_id,
            name="Hair Coloring",
            description="Full color treatment",
            price_cents=7500,  # $75.00
            duration_minutes=90,
        )
        db.session.add_all([service1, service2])
        db.session.commit()

    # Test GET endpoint
    response = client.get(f"/salons/{salon_id}/services")
    assert response.status_code == 200
    payload = response.get_json()
    assert isinstance(payload, dict)
    assert "services" in payload
    assert len(payload["services"]) == 2

    # Verify service data
    services = payload["services"]
    haircut = next(s for s in services if s["name"] == "Haircut")
    assert haircut["description"] == "Classic haircut"
    assert haircut["price_cents"] == 3000
    assert haircut["price_dollars"] == 30.0
    assert haircut["duration_minutes"] == 30


def test_create_service(app, client) -> None:
    """Test creating a new service."""
    with app.app_context():
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        db.session.add(vendor)
        db.session.flush()

        salon = Salon(
            vendor_id=vendor.user_id,
            name="The Cutting Edge",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.commit()

        salon_id = salon.salon_id

    # Test POST endpoint
    service_data = {
        "name": "Beard Trim",
        "description": "Professional beard trimming",
        "price_cents": 2000,  # $20.00
        "duration_minutes": 20,
    }
    response = client.post(
        f"/salons/{salon_id}/services",
        json=service_data,
    )
    assert response.status_code == 201
    payload = response.get_json()
    assert "service" in payload
    assert payload["service"]["name"] == "Beard Trim"
    assert payload["service"]["price_cents"] == 2000
    assert payload["service"]["duration_minutes"] == 20


def test_create_service_invalid_data(app, client) -> None:
    """Test creating a service with missing required fields."""
    with app.app_context():
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        db.session.add(vendor)
        db.session.flush()

        salon = Salon(
            vendor_id=vendor.user_id,
            name="The Cutting Edge",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.commit()

        salon_id = salon.salon_id

    # Missing required fields
    response = client.post(
        f"/salons/{salon_id}/services",
        json={"name": "Incomplete Service"},
    )
    assert response.status_code == 400
    payload = response.get_json()
    assert "error" in payload
    assert payload["error"] == "invalid_payload"


def test_update_service(app, client) -> None:
    """Test updating an existing service."""
    with app.app_context():
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        db.session.add(vendor)
        db.session.flush()

        salon = Salon(
            vendor_id=vendor.user_id,
            name="The Cutting Edge",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()

        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            description="Original description",
            price_cents=3000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.commit()

        salon_id = salon.salon_id
        service_id = service.service_id

    # Test PUT endpoint
    update_data = {
        "name": "Premium Haircut",
        "description": "Updated description",
        "price_cents": 4000,
        "duration_minutes": 45,
    }
    response = client.put(
        f"/salons/{salon_id}/services/{service_id}",
        json=update_data,
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert "service" in payload
    assert payload["service"]["name"] == "Premium Haircut"
    assert payload["service"]["price_cents"] == 4000


def test_delete_service(app, client) -> None:
    """Test deleting a service."""
    with app.app_context():
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        db.session.add(vendor)
        db.session.flush()

        salon = Salon(
            vendor_id=vendor.user_id,
            name="The Cutting Edge",
            is_published=True,
            verification_status="approved",
        )
        db.session.add(salon)
        db.session.flush()

        service = Service(
            salon_id=salon.salon_id,
            name="Haircut",
            description="Classic haircut",
            price_cents=3000,
            duration_minutes=30,
        )
        db.session.add(service)
        db.session.commit()

        salon_id = salon.salon_id
        service_id = service.service_id

    # Test DELETE endpoint
    response = client.delete(
        f"/salons/{salon_id}/services/{service_id}",
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert "message" in payload
    assert "deleted" in payload["message"].lower()

    # Verify service is deleted
    with app.app_context():
        deleted_service = Service.query.get(service_id)
        assert deleted_service is None


def test_get_nonexistent_salon_services(app, client) -> None:
    """Test getting services for a non-existent salon."""
    response = client.get("/salons/99999/services")
    assert response.status_code == 404
    payload = response.get_json()
    assert "error" in payload
