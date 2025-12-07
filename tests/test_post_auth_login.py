import pytest
from werkzeug.security import generate_password_hash
from app.models import User, AuthAccount, Staff, Salon, db # Added Staff and Salon for barber test


@pytest.fixture
def setup_login_user():
    PASSWORD = "testpassword123"
    
    user = User(
        user_id=101,
        name="Login Test User",
        email="login@test.com", 
        role="client" 
    )
    db.session.add(user)
    
    auth_account = AuthAccount(
        user_id=101,
        password_hash=generate_password_hash(PASSWORD),
    )
    db.session.add(auth_account)
    db.session.commit()
    
    return user.email, PASSWORD

@pytest.fixture
def setup_barber_user():
    PASSWORD = "barberpassword"
    
    salon = Salon(salon_id=201, name="The Test Barbershop")
    db.session.add(salon)
    
    barber_user = User(
        user_id=103,
        name="Test Barber",
        email="barber@test.com", 
        role="barber"
    )
    db.session.add(barber_user)
    
    staff_record = Staff(user_id=103, salon_id=201)
    db.session.add(staff_record)
    
    auth_account = AuthAccount(
        user_id=103,
        password_hash=generate_password_hash(PASSWORD),
    )
    db.session.add(auth_account)
    db.session.commit()
    
    return barber_user.email, PASSWORD, salon.salon_id, salon.name



def test_login_success_200(client, setup_login_user):
    """Test successful user login (200 OK) and token generation for a standard client."""
    email, password = setup_login_user
    
    payload = {"email": email, "password": password}
    
    response = client.post("/auth/login", json=payload)
    data = response.get_json()

    assert response.status_code == 200
    assert "token" in data
    assert "user" in data
    assert data["user"]["email"] == email
    assert data["user"]["role"] == "client"


def test_login_invalid_password_401(client, setup_login_user):
    """Test login with correct email but wrong password (401 Unauthorized)."""
    email, _ = setup_login_user
    
    payload = {"email": email, "password": "wrongpassword"}
    
    response = client.post("/auth/login", json=payload)
    data = response.get_json()

    assert response.status_code == 401
    assert data["error"] == "unauthorized"
    assert "invalid email or password" in data["message"]


def test_login_user_not_found_401(client):
    """Test login with an email that is not in the database (401 Unauthorized)."""
    payload = {"email": "notregistered@test.com", "password": "anypassword"}
    
    response = client.post("/auth/login", json=payload)
    data = response.get_json()

    assert response.status_code == 401
    assert data["error"] == "unauthorized"
    assert "invalid email or password" in data["message"]


def test_login_missing_fields_400(client):
    """Test login failure when 'email' or 'password' is missing from the payload (400 Bad Request)."""
    
    response_no_password = client.post("/auth/login", json={"email": "a@b.com"})
    data_no_password = response_no_password.get_json()
    assert response_no_password.status_code == 400
    assert data_no_password["error"] == "invalid_payload"

    response_no_email = client.post("/auth/login", json={"password": "123"})
    data_no_email = response_no_email.get_json()
    assert response_no_email.status_code == 400
    assert data_no_email["error"] == "invalid_payload"

    response_empty = client.post("/auth/login", json={})
    data_empty = response_empty.get_json()
    assert response_empty.status_code == 400
    assert data_empty["error"] == "invalid_payload"
    
