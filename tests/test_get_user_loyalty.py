import pytest
from app.models import db, User, Salon, ClientLoyalty

@pytest.fixture
def setup_loyalty_data(app):
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()

        user1 = User(user_id=1, name='Loyal Client', email='loyal@example.com', role='client')
        user2 = User(user_id=2, name='New Client', email='new@example.com', role='client')
        
        salon_a = Salon(salon_id=101, vendor_id=99, name='Salon A', business_type='Barber', city='T', state='NJ', postal_code='12345', address_line1='1 Test St')
        salon_b = Salon(salon_id=102, vendor_id=99, name='Salon B', business_type='Barber', city='T', state='NJ', postal_code='12345', address_line1='2 Test St')

        loyalty_a = ClientLoyalty(client_id=1, salon_id=101, points_balance=50)
        loyalty_b = ClientLoyalty(client_id=1, salon_id=102, points_balance=100)
        
        db.session.add_all([user1, user2, salon_a, salon_b, loyalty_a, loyalty_b])
        db.session.commit()
        
        return 1

def test_get_user_loyalty_success_200(client, setup_loyalty_data):
    user_id = setup_loyalty_data

    response = client.get(f"/users/{user_id}/loyalty")
    data = response.get_json()

    assert response.status_code == 200
    assert data["user_id"] == user_id
    assert data["total_points"] == 150
    assert data["total_salons"] == 2
    assert len(data["loyalty_by_salon"]) == 2
    assert {"salon_id": 101, "salon_name": "Salon A", "points": 50} in data["loyalty_by_salon"]
    assert {"salon_id": 102, "salon_name": "Salon B", "points": 100} in data["loyalty_by_salon"]

def test_get_user_loyalty_not_found_404(client):
    non_existent_user_id = 999

    response = client.get(f"/users/{non_existent_user_id}/loyalty")
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "user_not_found"