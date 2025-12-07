import pytest
from datetime import datetime
from app.models import db, Salon, Review, User
from flask import json

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def setup_data(app):
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()

        user1 = User(user_id=1, name='Client A', email='clienta@example.com', role='client')
        salon1 = Salon(salon_id=1, vendor_id=1, name='Test Salon 1', business_type='Barber', city='Testville', state='NJ', postal_code='12345', address_line1='123 Main St')
        review1 = Review(review_id=101, salon_id=1, client_id=1, rating=3, comment='Could be better.', created_at=datetime(2023, 1, 1, 10, 0, 0))
        
        db.session.add_all([user1, salon1, review1])
        db.session.commit()
        
        return review1.review_id

def test_delete_review_success_200(client, setup_data, app):
    review_id = setup_data
    
    response = client.delete(
        f"/reviews/{review_id}"
    )
    data = response.get_json()

    assert response.status_code == 200
    assert data["message"] == "Review deleted successfully"
    
    with app.app_context():
        deleted_review = Review.query.get(review_id)
        assert deleted_review is None

def test_delete_review_not_found_404(client):
    response = client.delete(
        "/reviews/999"
    )
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "review_not_found"