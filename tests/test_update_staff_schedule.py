import pytest
from app.models import Salon, User, Staff, db
from app import create_app
import json

@pytest.fixture
def setup_staff_schedule():
    SALON_ID = 50
    USER_ID = 51
    STAFF_ID = 52
    
    salon = Salon(salon_id=SALON_ID, vendor_id=1, name="Schedule Salon") 
    db.session.add(salon)

    user = User(user_id=USER_ID, name="Schedule User", email="schedule@test.com", role="barber")
    db.session.add(user)
    
    initial_schedule = {"Mon": "09:00-17:00"}
    staff_record = Staff(staff_id=STAFF_ID, salon_id=SALON_ID, user_id=USER_ID, title="Staffer", schedule=initial_schedule) 
    db.session.add(staff_record)
    
    db.session.commit()
    
    return SALON_ID, STAFF_ID

def test_update_staff_schedule_success_200(client, setup_staff_schedule):
    salon_id, staff_id = setup_staff_schedule
    
    NEW_SCHEDULE = {
        "Mon": "08:00-16:00", 
        "Tue": "08:00-16:00",
        "Sat": "10:00-14:00"
    }
    
    response = client.put(
        f"/salons/{salon_id}/staff/{staff_id}/schedule",
        data=json.dumps({"schedule": NEW_SCHEDULE}),
        content_type="application/json"
    )
    data = response.get_json()

    assert response.status_code == 200
    assert "staff" in data
    
    assert data["staff"]["schedule"] == NEW_SCHEDULE
    
    updated_staff = db.session.get(Staff, staff_id)
    assert updated_staff is not None
    assert updated_staff.schedule == NEW_SCHEDULE

def test_update_staff_schedule_not_found_404(client, setup_staff_schedule):
    salon_id, _ = setup_staff_schedule
    NON_EXISTENT_STAFF_ID = 999
    NEW_SCHEDULE = {"Mon": "08:00-16:00"}

    response = client.put(
        f"/salons/{salon_id}/staff/{NON_EXISTENT_STAFF_ID}/schedule",
        data=json.dumps({"schedule": NEW_SCHEDULE}),
        content_type="application/json"
    )
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"
    assert "Staff member not found" in data["message"]

def test_update_staff_schedule_missing_schedule_400(client, setup_staff_schedule):
    salon_id, staff_id = setup_staff_schedule
    
    response = client.put(
        f"/salons/{salon_id}/staff/{staff_id}/schedule",
        data=json.dumps({}),
        content_type="application/json"
    )
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_payload"
    assert "schedule is required" in data["message"]