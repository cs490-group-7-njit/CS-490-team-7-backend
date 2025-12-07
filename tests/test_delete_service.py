import pytest
from app.models import Salon, Service, db

@pytest.fixture
def setup_service():
    salon_id = 1
    vendor_id = 1
    service_id = 201

    salon = Salon(salon_id=salon_id, vendor_id=vendor_id, name="Test Salon")
    db.session.add(salon)
    db.session.flush()

    service = Service(service_id=service_id, salon_id=salon_id, name="Service to Delete", duration_minutes=30, price_cents=500)
    db.session.add(service)
    db.session.commit()
    return salon_id, service_id

def test_delete_service_success_200(client, setup_service):
    salon_id, service_id = setup_service
    response = client.delete(f"/salons/{salon_id}/services/{service_id}")
    data = response.get_json()
    assert response.status_code == 200
    assert data["message"] == "Service deleted successfully"
    assert db.session.get(Service, service_id) is None

def test_delete_service_not_found_404(client, setup_service):
    salon_id, _ = setup_service
    non_existent_service_id = 999
    response = client.delete(f"/salons/{salon_id}/services/{non_existent_service_id}")
    data = response.get_json()
    assert response.status_code == 404
    assert data["error"] == "not_found"

def test_delete_service_invalid_salon_service_id_404(client, setup_service):
    _, service_id = setup_service
    invalid_salon_id = 999
    response = client.delete(f"/salons/{invalid_salon_id}/services/{service_id}")
    data = response.get_json()
    assert response.status_code == 404
    assert data["error"] == "not_found"