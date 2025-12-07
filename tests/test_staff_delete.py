import pytest
from app.models import Salon, User, Staff, db
from sqlalchemy.exc import SQLAlchemyError

@pytest.fixture
def setup_staff_delete():
    """Sets up initial Salon, User, and Staff records for deletion tests."""
    SALON_ID = 11
    USER_ID = 21
    STAFF_ID = 2
    
    salon = Salon(salon_id=SALON_ID, vendor_id=1, name="Delete Test Salon") 
    db.session.add(salon)

    user = User(user_id=USER_ID, name="Staff To Delete", email="delete@test.com", role="barber")
    db.session.add(user)
    
    staff_record = Staff(staff_id=STAFF_ID, salon_id=SALON_ID, user_id=USER_ID, title="Removable Staff")
    db.session.add(staff_record)
    
    db.session.commit()
    
    return SALON_ID, STAFF_ID

def test_delete_staff_success_200(client, setup_staff_delete):
    """Tests successful deletion of a staff member."""
    salon_id, staff_id = setup_staff_delete
    
    response = client.delete(f"/salons/{salon_id}/staff/{staff_id}")
    data = response.get_json()

    assert response.status_code == 200
    assert "message" in data
    assert data["message"] == "Staff member deleted successfully"
    
    deleted_staff_record = Staff.query.get(staff_id)
    assert deleted_staff_record is None

def test_delete_staff_not_found_404(client, setup_staff_delete):
    """Tests deletion when the staff member ID is correct but already deleted (or wrong)."""
    salon_id, staff_id = setup_staff_delete
    
    non_existent_staff_id = staff_id + 100 

    response = client.delete(f"/salons/{salon_id}/staff/{non_existent_staff_id}")
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"
    assert "Staff member not found" in data["message"]

def test_delete_staff_wrong_salon_404(client, setup_staff_delete):
    """Tests deletion when the staff member exists but belongs to a different salon."""
    _, staff_id = setup_staff_delete
    
    wrong_salon_id = 999 

    response = client.delete(f"/salons/{wrong_salon_id}/staff/{staff_id}")
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"
    assert "Staff member not found" in data["message"]