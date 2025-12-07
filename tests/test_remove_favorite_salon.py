import pytest
from app.models import db, User, Salon

@pytest.fixture
def setup_data(app):
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()

        user = User(user_id=1, name='Test User', email='user@test.com', role='client')
        salon_a = Salon(salon_id=101, name='Salon A', vendor_id=99, is_published=True, verification_status='approved')
        salon_b = Salon(salon_id=102, name='Salon B', vendor_id=99, is_published=True, verification_status='approved')
        
        db.session.add_all([user, salon_a, salon_b])
        user.favorite_salons.append(salon_a)
        db.session.commit()
        
        return 1, 101, 102, 999

def test_remove_favorite_salon_success_200(client, setup_data):
    user_id, favorited_salon_id, _, _ = setup_data
    url = f"/users/{user_id}/favorites/{favorited_salon_id}"
    
    response = client.delete(url)
    
    assert response.status_code == 200
    assert response.get_json()["message"] == "Salon removed from favorites"
    
    user = db.session.get(User, user_id)
    assert user.favorite_salons.count() == 0

def test_remove_favorite_salon_user_not_found_404(client, setup_data):
    _, favorited_salon_id, _, non_existent_user_id = setup_data
    url = f"/users/{non_existent_user_id}/favorites/{favorited_salon_id}"
    
    response = client.delete(url)
    
    assert response.status_code == 404
    assert response.get_json()["error"] == "user_not_found"

def test_remove_favorite_salon_not_favorited_404(client, setup_data):
    user_id, _, non_favorited_salon_id, _ = setup_data
    url = f"/users/{user_id}/favorites/{non_favorited_salon_id}"
    
    response = client.delete(url)
    
    assert response.status_code == 404
    assert response.get_json()["error"] == "not_favorited"