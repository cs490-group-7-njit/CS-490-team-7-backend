import pytest
from app.models import db, User, Salon
from sqlalchemy.exc import SQLAlchemyError

@pytest.fixture
def setup_data(app):
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()

        user = User(user_id=1, name='Test User', email='user@test.com', role='client')
        salon = Salon(salon_id=101, name='Amazing Salon', vendor_id=99, is_published=True, verification_status='approved')
        
        db.session.add_all([user, salon])
        db.session.commit()
        
        return 1, 101, 999, 888

def test_add_favorite_salon_success_201(client, setup_data):
    user_id, salon_id, _, _ = setup_data
    url = f"/users/{user_id}/favorites/{salon_id}"
    
    response = client.post(url)
    
    assert response.status_code == 201
    assert response.get_json()["message"] == "Salon added to favorites"
    
    user = db.session.get(User, user_id)
    assert user.favorite_salons.count() == 1

def test_add_favorite_salon_user_not_found_404(client, setup_data):
    _, salon_id, non_existent_user_id, _ = setup_data
    url = f"/users/{non_existent_user_id}/favorites/{salon_id}"
    
    response = client.post(url)
    
    assert response.status_code == 404
    assert response.get_json()["error"] == "user_not_found"

def test_add_favorite_salon_salon_not_found_404(client, setup_data):
    user_id, _, _, non_existent_salon_id = setup_data
    url = f"/users/{user_id}/favorites/{non_existent_salon_id}"
    
    response = client.post(url)
    
    assert response.status_code == 404
    assert response.get_json()["error"] == "salon_not_found"

def test_add_favorite_salon_already_favorited_400(client, setup_data):
    user_id, salon_id, _, _ = setup_data
    url = f"/users/{user_id}/favorites/{salon_id}"
    
    client.post(url)
    
    response = client.post(url)
    
    assert response.status_code == 400
    assert response.get_json()["error"] == "already_favorited"