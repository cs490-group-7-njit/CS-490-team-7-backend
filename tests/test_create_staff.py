import pytest
from app.models import Salon, User, Staff, db
from sqlalchemy.exc import SQLAlchemyError


@pytest.fixture
def setup_staff_creation():
    SALON_ID = 5
    USER_ID = 15
    
    salon = Salon(salon_id=SALON_ID, vendor_id=1, name="Creation Test Salon") 
    db.session.add(salon)

    user = User(user_id=USER_ID, name="New Staff User", email="newstaff@test.com", role="barber")
    db.session.add(user)
    
    db.session.commit()
    
    return SALON_ID, USER_ID


def test_create_staff_success_201(client, setup_staff_creation):
    salon_id, user_id = setup_staff_creation
    
    staff_data = {
        "user_id": user_id,
        "title": "Lead Stylist"
    }

    response = client.post(f"/salons/{salon_id}/staff", json=staff_data)
    data = response.get_json()

    assert response.status_code == 201
    assert "staff" in data
    assert data["staff"]["user_id"] == user_id
    assert data["staff"]["salon_id"] == salon_id
    assert data["staff"]["title"] == "Lead Stylist"
    
    new_staff_record = Staff.query.filter_by(user_id=user_id, salon_id=salon_id).first()
    assert new_staff_record is not None
    assert new_staff_record.title == "Lead Stylist"