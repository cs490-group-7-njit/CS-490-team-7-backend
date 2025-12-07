import pytest
from app.models import db, User, AuthAccount
from werkzeug.security import generate_password_hash

@pytest.fixture
def setup_user_data(app):
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()

        # User model usually holds personal info like name, email, phone
        user = User(user_id=1, name='Original Name', email='test@example.com', role='client', phone='1234567890')
        
        # AuthAccount model only needs fields it actually defines, which seem to be user_id and password_hash.
        # *** FIX: Removed 'email' keyword argument from AuthAccount() ***
        auth_account = AuthAccount(user_id=1, password_hash=generate_password_hash('old_password'))
        
        db.session.add_all([user, auth_account])
        db.session.commit()
        
        return user.user_id

def test_update_profile_success_200(client, setup_user_data):
    user_id = setup_user_data
    update_data = {
        "name": "New Name",
        "phone": "9876543210"
    }
    
    response = client.put(f"/users/{user_id}", json=update_data)
    
    assert response.status_code == 200
    assert response.json["message"] == "Profile updated successfully"
    assert response.json["user"]["name"] == "New Name"
    assert response.json["user"]["phone"] == "9876543210"

def test_update_profile_not_found_404(client, setup_user_data):
    non_existent_id = 999
    update_data = {"name": "Ghost"}
    
    response = client.put(f"/users/{non_existent_id}", json=update_data)
    
    assert response.status_code == 404
    assert response.json["error"] == "user_not_found"

def test_update_profile_invalid_name_400(client, setup_user_data):
    user_id = setup_user_data
    update_data = {"name": " "}
    
    response = client.put(f"/users/{user_id}", json=update_data)
    
    assert response.status_code == 400
    assert response.json["error"] == "invalid_payload"
    assert "name cannot be blank" in response.json["message"]

def test_update_profile_update_password_200(client, setup_user_data):
    user_id = setup_user_data
    update_data = {"new_password": "new_secure_password"}
    
    response = client.put(f"/users/{user_id}", json=update_data)
    
    assert response.status_code == 200
    assert response.json["message"] == "Profile updated successfully"