import json
import pytest
from unittest.mock import patch
from app.models import User, db


VALID_CLIENT_PAYLOAD = {
    "name": "Test Client",
    "email": "client@example.com",
    "password": "securepassword",
    "role": "client",
    "phone": "555-1212",
}


@pytest.fixture
def setup_existing_user():
    """Fixture to create a user for the duplicate email test."""
    user = User(name="Existing", email="exists@example.com", role="client")
    db.session.add(user)
    db.session.commit()
    return user




@patch("app.routes.generate_password_hash", return_value="mocked_hash")
@patch("app.routes._build_token", return_value="mocked_jwt")
def test_register_success_client(mock_build_token, mock_hash, client):
    """Test successful registration for a client (201 Created)."""
    
    response = client.post(
        "/auth/register",
        data=json.dumps(VALID_CLIENT_PAYLOAD),
        content_type="application/json"
    )
    
    data = response.get_json()

    assert response.status_code == 201
    assert "token" in data
    assert data["token"] == "mocked_jwt"
    assert data["user"]["email"] == VALID_CLIENT_PAYLOAD["email"]
    assert data["user"]["role"] == "client"

    new_user = User.query.filter_by(email=VALID_CLIENT_PAYLOAD["email"]).first()
    assert new_user is not None
    assert new_user.name == "Test Client"


def test_register_failure_missing_fields(client):
    """Test registration failure when required fields are missing (400 Bad Request)."""
    
    incomplete_payload = {"name": "Test User", "email": "only_two_fields@test.com"} 

    response = client.post(
        "/auth/register",
        data=json.dumps(incomplete_payload),
        content_type="application/json"
    )
    
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_payload"
    assert "name, email, and password are required" in data["message"]


def test_register_failure_duplicate_email(client, setup_existing_user):
    """Test registration failure when email already exists (409 Conflict)."""
    
    duplicate_payload = VALID_CLIENT_PAYLOAD.copy()
    duplicate_payload["email"] = "exists@example.com"  

    response = client.post(
        "/auth/register",
        data=json.dumps(duplicate_payload),
        content_type="application/json"
    )
    
    data = response.get_json()

    assert response.status_code == 409
    assert data["error"] == "conflict"
    assert "email address is already in use" in data["message"]


def test_register_failure_invalid_role(client):
    """Test registration failure when an invalid role is provided (400 Bad Request)."""
    
    invalid_role_payload = VALID_CLIENT_PAYLOAD.copy()
    invalid_role_payload["role"] = "admin" 

    response = client.post(
        "/auth/register",
        data=json.dumps(invalid_role_payload),
        content_type="application/json"
    )
    
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_role"
    assert "role must be 'client', 'vendor', or 'barber'" in data["message"]