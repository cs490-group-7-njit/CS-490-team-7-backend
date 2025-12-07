import pytest
from app.models import Salon, Service, db

@pytest.fixture
def setup_data():
    salon_id = 1
    vendor_id = 1  
    name = "Test Salon"
    
    salon = Salon(salon_id=salon_id, vendor_id=vendor_id, name=name)
    db.session.add(salon)
    db.session.flush()

    service1 = Service(salon_id=salon_id, name="Haircut", duration_minutes=30, price_cents=50.00)
    service2 = Service(salon_id=salon_id, name="Color", duration_minutes=90, price_cents=150.00)
    db.session.add_all([service1, service2])
    db.session.commit()
    
    return salon_id

def test_list_services_success_200(client, setup_data):
    salon_id = setup_data
    response = client.get(f"/salons/{salon_id}/services")
    data = response.get_json()
    assert response.status_code == 200
    assert "services" in data
    assert len(data["services"]) == 2
    service_names = {s["name"] for s in data["services"]}
    assert "Haircut" in service_names
    assert "Color" in service_names

def test_list_services_salon_not_found_404(client):
    non_existent_salon_id = 999
    response = client.get(f"/salons/{non_existent_salon_id}/services")
    data = response.get_json()
    assert response.status_code == 404
    assert data["error"] == "not_found"