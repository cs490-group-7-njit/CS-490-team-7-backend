import pytest
from datetime import datetime, timezone
from app.models import db, Salon, Review, User
from flask import json
from sqlalchemy import select

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def setup_data(app):
    with app.app_context():
       
        db.session.remove()
        db.drop_all()
        db.create_all()

        vendor_id = 1
        client_id = 2
        review_with_reply_id = 101
        review_no_reply_id = 102
        
        vendor = User(user_id=vendor_id, name='Vendor A', email='vendor@example.com', role='vendor')
        client = User(user_id=client_id, name='Client B', email='client@example.com', role='client')
        salon = Salon(salon_id=1, vendor_id=vendor_id, name='Vendor Salon', business_type='Barber', city='Testville', state='NJ', postal_code='12345', address_line1='123 Main St')
        
        review_with_reply = Review(review_id=review_with_reply_id, salon_id=1, client_id=client_id, rating=3, comment='Initial comment.', vendor_reply='Original reply.', vendor_reply_at=datetime.now(timezone.utc))
        review_no_reply = Review(review_id=review_no_reply_id, salon_id=1, client_id=client_id, rating=5, comment='Great service.')
        
        db.session.add_all([vendor, client, salon, review_with_reply, review_no_reply])
        db.session.commit()
        
        return review_with_reply_id, review_no_reply_id, vendor_id

def test_delete_vendor_reply_success_200(client, setup_data, app):
    review_id, _, vendor_id = setup_data
    
    response = client.delete(
        f"/reviews/{review_id}/reply?vendor_id={vendor_id}"
    )
    data = response.get_json()

    assert response.status_code == 200
    assert data["review"]["vendor_reply"] is None
    assert data["review"]["vendor_reply_at"] is None
    
    with app.app_context():
        updated_review = db.session.get(Review, review_id)
        assert updated_review.vendor_reply is None
        assert updated_review.vendor_reply_at is None

def test_delete_vendor_reply_no_reply_found_404(client, setup_data):
    _, review_id_no_reply, vendor_id = setup_data
    
    response = client.delete(
        f"/reviews/{review_id_no_reply}/reply?vendor_id={vendor_id}"
    )
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "no_reply_found"
    assert "does not have a vendor reply" in data["message"]

def test_delete_vendor_reply_review_not_found_404(client, setup_data):
    _, _, vendor_id = setup_data
    non_existent_review_id = 999
    
    response = client.delete(
        f"/reviews/{non_existent_review_id}/reply?vendor_id={vendor_id}"
    )
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "review_not_found"

def test_delete_vendor_reply_unauthorized_403(client, setup_data):
    review_id, _, _ = setup_data
    unauthorized_vendor_id = 999
    
    response = client.delete(
        f"/reviews/{review_id}/reply?vendor_id={unauthorized_vendor_id}"
    )
    data = response.get_json()

    assert response.status_code == 403
    assert data["error"] == "unauthorized"
    assert "You can only delete replies for your own salon" in data["message"]
