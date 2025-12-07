import json
import pytest
from app.models import User, db

@pytest.fixture
def setup_user_for_verify():
    user = User(
        user_id=99,
        name="Verification Test User",
        email="verify@test.com", 
        role="vendor"
    )
    db.session.add(user)
    db.session.commit()
    return user.email

def test_verify_user_success_200(client, setup_user_for_verify):
    test_email = setup_user_for_verify 

    response = client.get(f"/users/verify?email={test_email}")
    data = response.get_json()

    assert response.status_code == 200
    assert "user" in data
    assert data["user"]["email"] == test_email
    assert data["user"]["role"] == "vendor"
    assert data["user"]["name"] == "Verification Test User"


def test_verify_user_not_found_404(client):
    non_existent_email = "nonexistent@test.com"

    response = client.get(f"/users/verify?email={non_existent_email}")
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"
    assert data["message"] == "user not found"


def test_verify_user_missing_email_400(client):
    response = client.get("/users/verify")
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_query"
    assert "email query parameter is required" in data["message"]