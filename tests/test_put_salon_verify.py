import json
import pytest
from app.models import Salon, User, db

VENDOR_USER_DATA = {
    "name": "Verification Vendor",
    "email": "verify2@example.com",
    "role": "vendor",
}

TEST_SALON_DATA = {
    "name": "Tax ID Pending Salon",
    "description": "Needs a TIN.",
    "business_type": "Spa",
    "verification_status": "rejected", 
    "delay_notifications_data": {}, 
    "social_media_data": {},
}

VERIFICATION_PAYLOAD = {
    "business_tin": "12-3456789",
}

@pytest.fixture
def setup_unverified_salon(client):
    """Fixture to create a Vendor and a Salon ready for submission."""
    vendor = User(**VENDOR_USER_DATA)
    db.session.add(vendor)
    db.session.commit()
    
    salon = Salon(**TEST_SALON_DATA, vendor_id=vendor.user_id)
    db.session.add(salon)
    db.session.commit()
    
    return {
        "salon_id": salon.salon_id,
        "vendor_id": vendor.user_id
    }


def test_submit_for_verification_success(client, setup_unverified_salon):
    """Test successful submission for verification with required business_tin (200 OK)."""
    salon_id = setup_unverified_salon['salon_id']
    
    response = client.put(
        f"/salons/{salon_id}/verify",
        data=json.dumps(VERIFICATION_PAYLOAD),
        content_type="application/json"
    )
    response_data = json.loads(response.data)

    assert response.status_code == 200
    assert response_data["message"] == "Verification request submitted successfully."
    assert response_data["salon"]["id"] == salon_id
    assert response_data["salon"]["verification_status"] == "pending"
    
    updated_salon = Salon.query.get(salon_id)
    assert updated_salon.verification_status == "pending"
    


def test_submit_for_verification_missing_business_tin(client, setup_unverified_salon):
    """Test submission failure due to missing required 'business_tin' (400 Bad Request)."""
    salon_id = setup_unverified_salon['salon_id']
    
    # Missing 'business_tin'
    invalid_payload = {"some_other_key": "data"}

    response = client.put(
        f"/salons/{salon_id}/verify",
        data=json.dumps(invalid_payload),
        content_type="application/json"
    )
    response_data = json.loads(response.data)

    assert response.status_code == 400
    assert response_data["error"] == "invalid_payload"
    assert "business_tin is required" in response_data["message"]


def test_submit_for_verification_nonexistent_salon(client):
    """Test submission failure for a nonexistent salon ID (404 Not Found)."""
    non_existent_id = 999
    
    response = client.put(
        f"/salons/{non_existent_id}/verify",
        data=json.dumps(VERIFICATION_PAYLOAD),
        content_type="application/json"
    )
    response_data = json.loads(response.data)

    assert response.status_code == 404
    assert response_data["error"] == "not_found"
    assert "Salon not found" in response_data["message"]