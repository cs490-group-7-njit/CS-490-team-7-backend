import pytest
from app.models import Staff, db

@pytest.fixture
def setup_staff():
    staff_id = 1
    salon_id = 1
    title = "Stylist"
    staff = Staff(staff_id=staff_id, salon_id=salon_id, title=title)
    db.session.add(staff)
    db.session.commit()
    return staff_id

def test_create_staff_schedule_success_201(client, setup_staff):
    staff_id = setup_staff
    schedule_data = {
        "day_of_week": 1,
        "start_time": "09:00",
        "end_time": "17:00"
    }
    response = client.post(f"/staff/{staff_id}/schedules", json=schedule_data)
    data = response.get_json()
    assert response.status_code == 201
    assert "schedule" in data
    assert data["schedule"]["day_of_week"] == 1

def test_create_staff_schedule_missing_data_400(client, setup_staff):
    staff_id = setup_staff
    schedule_data = {
        "day_of_week": 1,
        "start_time": "09:00"
    }
    response = client.post(f"/staff/{staff_id}/schedules", json=schedule_data)
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "invalid_payload"

def test_create_staff_schedule_staff_not_found_404(client):
    non_existent_id = 999
    schedule_data = {
        "day_of_week": 1,
        "start_time": "09:00",
        "end_time": "17:00"
    }
    response = client.post(f"/staff/{non_existent_id}/schedules", json=schedule_data)
    data = response.get_json()
    assert response.status_code == 404
    assert data["error"] == "not_found"

def test_create_staff_schedule_invalid_time_format_400(client, setup_staff):
    staff_id = setup_staff
    schedule_data = {
        "day_of_week": 1,
        "start_time": "9am",
        "end_time": "5pm"
    }
    response = client.post(f"/staff/{staff_id}/schedules", json=schedule_data)
    data = response.get_json()
    assert response.status_code == 400
    assert data["error"] == "invalid_format"
