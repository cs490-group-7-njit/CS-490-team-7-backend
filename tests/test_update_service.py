import pytest
from app.models import Salon, Service, db

@pytest.fixture
def setup_service():
    salon_id = 1
    vendor_id = 1
    service_id = 101

    salon = Salon(salon_id=salon_id, vendor_id=vendor_id, name="Test Salon")
    db.session.add(salon)
    db.session.flush()

    service = Service(service_id=service_id, salon_id=salon_id, name="Initial Cut", duration_minutes=60, price_cents=1000)
    db.session.add(service)
    db.session.commit()
    return salon_id, service_id

def test_update_service_success_200(client, setup_service):
    salon_id, service_id = setup_service
    update_data = {
        "name": "Updated Style",
        "price_cents": 1500,
        "duration_minutes": 45
    }
    response = client.put(f"/salons/{salon_id}/services/{service_id}", json=update_data)
    data = response.get_json()
    assert response.status_code == 200
    assert data["message"] == "Service updated successfully"
    assert data["service"]["name"] == "Updated Style"
    assert data["service"]["price_cents"] == 1500
    
    updated_service = db.session.get(Service, service_id)
    assert updated_service.name == "Updated Style"

def test_update_service_partial_update_200(client, setup_service):
    salon_id, service_id = setup_service
    update_data = {
        "duration_minutes": 30
    }
    response = client.put(f"/salons/{salon_id}/services/{service_id}", json=update_data)
    data = response.get_json()
    assert response.status_code == 200
    assert data["service"]["duration_minutes"] == 30
    
    updated_service = db.session.get(Service, service_id)
    assert updated_service.name == "Initial Cut"
    assert updated_service.duration_minutes == 30

def test_update_service_not_found_404(client, setup_service):
    salon_id, _ = setup_service
    non_existent_service_id = 999
    update_data = {"name": "Test"}
    response = client.put(f"/salons/{salon_id}/services/{non_existent_service_id}", json=update_data)
    data = response.get_json()
    assert response.status_code == 404
    assert data["error"] == "not_found"

def test_update_service_invalid_salon_service_id_404(client, setup_service):
    _, service_id = setup_service
    invalid_salon_id = 999
    update_data = {"name": "Test"}
    response = client.put(f"/salons/{invalid_salon_id}/services/{service_id}", json=update_data)
    data = response.get_json()
    assert response.status_code == 404
    assert data["error"] == "not_found"

def test_update_service_invalid_price_400(client, setup_service):
    salon_id, service_id = setup_service
    update_data = {"price_cents": -10}
    response = client.put(f"/salons/{salon_id}/services/{service_id}", json=update_data)
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "invalid_payload"

def test_update_service_invalid_duration_400(client, setup_service):
    salon_id, service_id = setup_service
    update_data = {"duration_minutes": 0}
    response = client.put(f"/salons/{salon_id}/services/{service_id}", json=update_data)
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "invalid_payload"