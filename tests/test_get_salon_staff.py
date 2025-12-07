import pytest
from app.models import Salon, User, Staff, db

@pytest.fixture
def setup_staff_data():
    SALON_ID = 1
    
    salon = Salon(salon_id=SALON_ID, vendor_id=99, name="Test Staff Salon") 
    db.session.add(salon)

    user1 = User(user_id=10, name="Staff One", email="staff1@test.com", role="barber")
    user2 = User(user_id=11, name="Staff Two", email="staff2@test.com", role="barber")
    db.session.add_all([user1, user2])
    
    staff1 = Staff(user_id=10, salon_id=SALON_ID, title="Senior Stylist") 
    staff2 = Staff(user_id=11, salon_id=SALON_ID, title="Junior Stylist") 
    db.session.add_all([staff1, staff2])

    db.session.commit()
    
    return SALON_ID

def test_list_staff_success_200(client, setup_staff_data):
    salon_id = setup_staff_data
    
    response = client.get(f"/salons/{salon_id}/staff")
    data = response.get_json()

    assert response.status_code == 200
    
    assert "staff" in data
    assert isinstance(data["staff"], list)
    assert len(data["staff"]) == 2
    
    staff_ids = {member["user_id"] for member in data["staff"]}
    assert staff_ids == {10, 11}


def test_list_staff_salon_not_found_404(client):
    non_existent_salon_id = 999 
    
    response = client.get(f"/salons/{non_existent_salon_id}/staff")
    data = response.get_json()
    
    assert response.status_code == 404
    
    assert data["error"] == "not_found"
    assert "Salon not found" in data["message"]