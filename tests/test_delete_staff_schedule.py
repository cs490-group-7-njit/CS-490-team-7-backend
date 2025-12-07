import pytest
from app.models import Staff, Schedule, db
from datetime import time

@pytest.fixture
def setup_data():
    staff_id = 1
    salon_id = 1
    title = "Manager"
    
    staff = Staff(staff_id=staff_id, salon_id=salon_id, title=title)
    db.session.add(staff)
    db.session.flush()

    schedule = Schedule(
        staff_id=staff_id,
        day_of_week=1,
        start_time=time(9, 0),
        end_time=time(17, 0)
    )
    db.session.add(schedule)
    db.session.commit()
    
    return staff_id, schedule.schedule_id

def test_delete_staff_schedule_success_200(client, setup_data):
    staff_id, schedule_id = setup_data
    response = client.delete(f"/staff/{staff_id}/schedules/{schedule_id}")
    assert response.status_code == 200
    deleted_schedule = db.session.get(Schedule, schedule_id)
    assert deleted_schedule is None

def test_delete_staff_schedule_not_found_404(client, setup_data):
    staff_id, _ = setup_data
    non_existent_schedule_id = 999
    response = client.delete(f"/staff/{staff_id}/schedules/{non_existent_schedule_id}")
    assert response.status_code == 404