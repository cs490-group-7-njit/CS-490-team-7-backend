import pytest
from app.models import Salon, User, Staff, db
from sqlalchemy.exc import SQLAlchemyError

@pytest.fixture
def setup_staff_update():
    SALON_ID = 10
    USER_ID = 20
    STAFF_ID = 1
    
    salon = Salon(salon_id=SALON_ID, vendor_id=1, name="Update Test Salon") 
    db.session.add(salon)

    user = User(user_id=USER_ID, name="Initial Staff User", email="initial@test.com", role="barber")
    db.session.add(user)
    
    initial_staff = Staff(staff_id=STAFF_ID, salon_id=SALON_ID, user_id=USER_ID, title="Junior Assistant")
    db.session.add(initial_staff)
    
    db.session.commit()
    
    return SALON_ID, STAFF_ID

def test_update_staff_success_200(client, setup_staff_update):
    salon_id, staff_id = setup_staff_update
    
    update_data = {
        "title": "Senior Stylist"
    }

    response = client.put(f"/salons/{salon_id}/staff/{staff_id}", json=update_data)
    data = response.get_json()

    assert response.status_code == 200
    assert "staff" in data
    
    assert data["staff"]["id"] == staff_id
    
    assert data["staff"]["title"] == "Senior Stylist"
    
    updated_staff_record = Staff.query.get(staff_id)
    assert updated_staff_record is not None
    assert updated_staff_record.title == "Senior Stylist"

def test_update_staff_missing_title_400(client, setup_staff_update):
    salon_id, staff_id = setup_staff_update
    
    update_data = {
        "title": ""
    }

    response = client.put(f"/salons/{salon_id}/staff/{staff_id}", json=update_data)
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_payload"

def test_update_staff_not_found_404(client):
    salon_id = 99
    staff_id = 999
    
    update_data = {
        "title": "New Title"
    }

    response = client.put(f"/salons/{salon_id}/staff/{staff_id}", json=update_data)
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"