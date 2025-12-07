import json
import pytest
from unittest.mock import patch, MagicMock
from app.models import User, db 


NEW_CLIENT_PAYLOAD = {
    "name": "Test Client",
    "email": "client@test.com",
    "password": "securepassword123",
    "role": "client",
    "phone": "555-1234",
}

DUPLICATE_EMAIL_PAYLOAD = {
    "name": "Duplicate User",
    "email": "duplicate@test.com",
    "password": "password",
}

@pytest.fixture
def setup_duplicate_user():
    """Fixture to ensure a user already exists for the conflict test."""
    user = User(name="Existing User", email="duplicate@test.com", role="client")
    db.session.add(user)
    db.session.commit()


@pytest.mark.parametrize("role", ["client", "vendor", "barber"])
@patch("app.routes.generate_password_hash", return_value="hashed_password")
@patch("app.routes._build_token", return_value="mocked_jwt_token")
def test_register_user_success(mock_build_token, mock_hash, client, role):
    """Test successful registration for different allowed roles (201 Created)."""
    payload = NEW_CLIENT_PAYLOAD.copy()
    payload["role"] = role
    payload["email"] = f"{role}@success.com" 

    response = client.post(
        "/auth/register",
        data=json.dumps(payload),
        content_type="application/json"
    )
    response_data = json.loads(response.data)

    assert response.status_code == 201
    assert "token" in response_data
    assert response_data["token"] == "mocked_jwt_token"
    assert response_data["user"]["email"] == payload["email"]
    assert response_data["user"]["role"] == role
    
    new_user = User.query.filter_by(email=payload["email"]).first()
    assert new_user is not None


def test_register_user_missing_required_fields(client):
    """Test failure when required fields (name, email, password) are missing (400 Bad Request)."""
    
    incomplete_payload = {"name": "Incomplete User"}

    response = client.post(
        "/auth/register",
        data=json.dumps(incomplete_payload),
        content_type="application/json"
    )
    response_data = json.loads(response.data)

    assert response.status_code == 400
    assert response_data["error"] == "invalid_payload"
    assert "name, email, and password are required" in response_data["message"]


def test_register_user_duplicate_email(client, setup_duplicate_user):
    """Test failure when the email already exists in the database (409 Conflict)."""
    
    response = client.post(
        "/auth/register",
        data=json.dumps(DUPLICATE_EMAIL_PAYLOAD),
        content_type="application/json"
    )
    response_data = json.loads(response.data)

    assert response.status_code == 409
    assert response_data["error"] == "conflict"
    assert "email address is already in use" in response_data["message"]