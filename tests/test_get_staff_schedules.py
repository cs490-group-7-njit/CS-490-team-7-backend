import pytest
from app.models import Staff, Schedule, db

@pytest.fixture
def setup_staff_and_schedule():
    staff_id = 1
    staff = Staff(staff_id=staff_id, name="Test Staff")
    schedule1 = Schedule(staff_id=staff_id, week_start="2024-01-01", data={"Mon": "9-5"})
    schedule2 = Schedule(staff_id=staff_id, week_start="2024-01-08", data={"Tue": "9-5"})
    db.session.add_all([staff, schedule1, schedule2])
    db.session.commit()
    return staff_id


def test_get_staff_schedules_not_found_404(client):
    non_existent_id = 999
    response = client.get(f"/staff/{non_existent_id}/schedules")
    assert response.status_code == 404