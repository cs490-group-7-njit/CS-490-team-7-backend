import pytest
from datetime import datetime
from app.models import db, Salon, Review, User
from flask import json

@pytest.fixture
def client(app):
    return app.test_client()

def to_dict(self):
    return {
        "review_id": self.review_id,
        "salon_id": self.salon_id,
        "client_id": self.client_id,
        "rating": self.rating,
        "comment": self.comment,
        "created_at": self.created_at.isoformat()
    }

Review.to_dict = to_dict

@pytest.fixture
def setup_data(app):
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()

        user1 = User(user_id=1, name='Client A', email='clienta@example.com', role='client')
        salon1 = Salon(salon_id=1, vendor_id=1, name='Test Salon 1', business_type='Barber', city='Testville', state='NJ', postal_code='12345', address_line1='123 Main St')
        
        db.session.add_all([user1, salon1])
        db.session.commit()
        
        return salon1.salon_id, user1.user_id

def test_create_review_success_201(client, setup_data, app):
    salon_id, client_id = setup_data
    
    review_data = {
        "client_id": client_id,
        "rating": 5,
        "comment": "Best haircut ever!"
    }

    response = client.post(
        f"/salons/{salon_id}/reviews", 
        json=review_data
    )
    data = response.get_json()

    assert response.status_code == 201
    assert "review" in data
    assert data["review"]["rating"] == 5
    assert data["review"]["comment"] == "Best haircut ever!"
    
    with app.app_context():
        review_count = Review.query.filter_by(salon_id=salon_id, client_id=client_id).count()
        assert review_count == 1

def test_create_review_invalid_rating_400(client, setup_data):
    salon_id, client_id = setup_data
    
    review_data = {
        "client_id": client_id,
        "rating": 6,
        "comment": "Too high a rating"
    }

    response = client.post(
        f"/salons/{salon_id}/reviews", 
        json=review_data
    )
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_rating"

def test_create_review_missing_client_id_400(client, setup_data):
    salon_id, _ = setup_data
    
    review_data = {
        "rating": 5,
        "comment": "Missing client ID"
    }

    response = client.post(
        f"/salons/{salon_id}/reviews", 
        json=review_data
    )
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_payload"

def test_create_review_salon_not_found_404(client, setup_data):
    _, client_id = setup_data
    
    review_data = {
        "client_id": client_id,
        "rating": 4
    }

    response = client.post(
        "/salons/999/reviews", 
        json=review_data
    )
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "salon_not_found"