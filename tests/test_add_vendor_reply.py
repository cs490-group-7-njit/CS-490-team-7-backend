import pytest
from datetime import datetime
from app.models import db, Salon, Review, User
from flask import json
from sqlalchemy.exc import SQLAlchemyError

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
        review_id = 101

        vendor = User(user_id=vendor_id, name='Vendor A', email='vendor@example.com', role='vendor')
        client = User(user_id=client_id, name='Client B', email='client@example.com', role='client')
        salon = Salon(salon_id=1, vendor_id=vendor_id, name='Vendor Salon', business_type='Barber', city='Testville', state='NJ', postal_code='12345', address_line1='123 Main St')
        review = Review(review_id=review_id, salon_id=1, client_id=client_id, rating=3, comment='Average service.')
        
        db.session.add_all([vendor, client, salon, review])
        db.session.commit()
        
        return review_id, vendor_id, salon.salon_id

def test_add_vendor_reply_success_200(client, setup_data, app):
    review_id, vendor_id, _ = setup_data
    reply_text = "Thank you for your feedback. We will address this."
    
    response = client.post(
        f"/reviews/{review_id}/reply", 
        json={"vendor_reply": reply_text, "vendor_id": vendor_id}
    )
    data = response.get_json()

    assert response.status_code == 200
    assert data["message"] == "Reply added successfully"
    assert data["review"]["vendor_reply"] == reply_text
    
    with app.app_context():
        updated_review = Review.query.get(review_id)
        assert updated_review.vendor_reply == reply_text
        assert updated_review.vendor_reply_at is not None

def test_add_vendor_reply_empty_reply_400(client, setup_data):
    review_id, vendor_id, _ = setup_data
    
    response = client.post(
        f"/reviews/{review_id}/reply", 
        json={"vendor_reply": "", "vendor_id": vendor_id}
    )
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_payload"
    assert "vendor_reply cannot be empty" in data["message"]

def test_add_vendor_reply_unauthorized_403(client, setup_data):
    review_id, _, _ = setup_data
    unauthorized_vendor_id = 999
    
    response = client.post(
        f"/reviews/{review_id}/reply", 
        json={"vendor_reply": "Not my salon.", "vendor_id": unauthorized_vendor_id}
    )
    data = response.get_json()

    assert response.status_code == 403
    assert data["error"] == "unauthorized"
    assert "You can only reply to reviews for your own salon" in data["message"]

def test_add_vendor_reply_review_not_found_404(client, setup_data):
    _, vendor_id, _ = setup_data
    non_existent_review_id = 999
    
    response = client.post(
        f"/reviews/{non_existent_review_id}/reply", 
        json={"vendor_reply": "Reply text", "vendor_id": vendor_id}
    )
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "review_not_found"