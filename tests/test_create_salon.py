import pytest
from flask import json
from app.extensions import db
from app.models import User, Salon 


@pytest.fixture(scope="function")
def setup_users(app):
    """
    Sets up a valid Vendor and a regular Client user.
    FIXED: Uses 'client' instead of the undefined 'customer' role.
    """
    with app.app_context():
        db.session.query(Salon).delete()
        db.session.query(User).delete()
        db.session.commit()

        vendor_user = User(name="Valid Vendor", email="valid.vendor@example.com", role="vendor")
        
        customer_user = User(name="Regular Client", email="client@example.com", role="client")
        
        db.session.add_all([vendor_user, customer_user])
        db.session.commit()
        
        return {
            "vendor_id": vendor_user.user_id,
            "client_id": customer_user.user_id 
        }

def test_create_salon_success_minimal(client, setup_users):
    """Test successful salon creation with only required fields (name, vendor_id)."""
    vendor_id = setup_users["vendor_id"]
    
    data = {
        "name": "Quick Test Salon",
        "vendor_id": vendor_id,
    }

    response = client.post("/salons", json=data)
    response_data = json.loads(response.data)

    assert response.status_code == 201
    assert response_data["salon"]["name"] == "Quick Test Salon"
    assert "id" in response_data["salon"] or "salon_id" in response_data["salon"]

def test_create_salon_failure_missing_required_field(client, setup_users):
    """Test failure when 'name' is missing."""
    data = {
        "vendor_id": setup_users["vendor_id"],
    }
    
    response = client.post("/salons", json=data)
    response_data = json.loads(response.data)

    assert response.status_code == 400
    assert "name and vendor_id are required" in response_data["message"]


def test_create_salon_failure_non_vendor_role(client, setup_users):
    """Test failure when trying to create a salon with a client ID."""
    client_id = setup_users["client_id"]
    data = {
        "name": "Unauthorized Salon",
        "vendor_id": client_id,
    }
    
    response = client.post("/salons", json=data)
    response_data = json.loads(response.data)

    assert response.status_code == 400
    assert response_data["error"] == "invalid_vendor"
    assert "valid vendor account" in response_data["message"]