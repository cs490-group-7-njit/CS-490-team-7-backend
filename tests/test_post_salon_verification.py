import json
import pytest
from app.models import Salon, User, db

VENDOR_USER_DATA = {
    "name": "Verification Vendor",
    "email": "verify@example.com",
    "role": "vendor",
}

TEST_SALON_DATA = {
    "name": "Ready to be Verified Salon",
    "description": "Needs a checkmark.",
    "business_type": "Hair Salon",
    "verification_status": "rejected", 
}

@pytest.fixture
def setup_unverified_salon(client):
    """Fixture to create a Vendor and a Salon with an initial non-pending status."""
    vendor = User(**VENDOR_USER_DATA)
    db.session.add(vendor)
    db.session.commit()
    
    salon = Salon(**TEST_SALON_DATA, vendor_id=vendor.user_id)
    db.session.add(salon)
    db.session.commit()
    
    return {
        "salon_id": salon.salon_id,
        "initial_status": salon.verification_status
    }


def test_submit_for_verification_success(client, setup_unverified_salon):
    """Test successful submission for verification (201 Created)."""
    salon_id = setup_unverified_salon['salon_id']
    
    response = client.post(
        f"/salons/{salon_id}/verification",
        data=json.dumps({}), 
        content_type="application/json"
    )
    response_data = json.loads(response.data)

    assert response.status_code == 201
    assert response_data["salon_id"] == salon_id
    assert response_data["verification_status"] == "pending"
    
    updated_salon = Salon.query.get(salon_id)
    assert updated_salon.verification_status == "pending"

def test_submit_for_verification_nonexistent_salon(client):
    """Test submission failure for a nonexistent salon ID (404 Not Found)."""
    non_existent_id = 999
    
    response = client.post(
        f"/salons/{non_existent_id}/verification",
        data=json.dumps({}),
        content_type="application/json"
    )
    response_data = json.loads(response.data)

    assert response.status_code == 404
    assert response_data["error"] == "not_found"
    assert "Salon not found" in response_data["message"]