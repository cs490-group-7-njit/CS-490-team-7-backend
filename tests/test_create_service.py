import pytest
from app.models import Salon, Service, db

@pytest.fixture
def setup_salon():
    salon_id = 1
    vendor_id = 1
    salon = Salon(salon_id=salon_id, vendor_id=vendor_id, name="Test Salon")
    db.session.add(salon)
    db.session.commit()
    return salon_id

def test_create_service_success_201(client, setup_salon):
    salon_id = setup_salon
    service_data = {
        "name": "Quick Trim",
        "description": "A quick 15-minute haircut.",
        "price_cents": 2500,
        "duration_minutes": 15
    }
    response = client.post(f"/salons/{salon_id}/services", json=service_data)
    data = response.get_json()
    assert response.status_code == 201
    assert data["message"] == "Service created successfully"
    assert db.session.query(Service).count() == 1
    assert db.session.query(Service).filter_by(name="Quick Trim").first().price_cents == 2500

def test_create_service_salon_not_found_404(client):
    service_data = {
        "name": "Invalid Service",
        "price_cents": 1000,
        "duration_minutes": 60
    }
    response = client.post("/salons/999/services", json=service_data)
    data = response.get_json()
    assert response.status_code == 404
    assert data["error"] == "not_found"

def test_create_service_missing_required_field_400(client, setup_salon):
    salon_id = setup_salon
    service_data = {
        "description": "Missing Name",
        "price_cents": 1000,
        "duration_minutes": 60
    }
    response = client.post(f"/salons/{salon_id}/services", json=service_data)
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "invalid_payload"

def test_create_service_invalid_numeric_field_400(client, setup_salon):
    salon_id = setup_salon
    service_data = {
        "name": "Invalid Price",
        "price_cents": -500,
        "duration_minutes": 60
    }
    response = client.post(f"/salons/{salon_id}/services", json=service_data)
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "invalid_payload"

def test_create_service_invalid_duration_400(client, setup_salon):
    salon_id = setup_salon
    service_data = {
        "name": "Zero Duration",
        "price_cents": 500,
        "duration_minutes": 0
    }
    response = client.post(f"/salons/{salon_id}/services", json=service_data)
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "invalid_payload"