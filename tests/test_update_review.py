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
        review1 = Review(review_id=101, salon_id=1, client_id=1, rating=3, comment='Could be better.', created_at=datetime(2023, 1, 1, 10, 0, 0))
        
        db.session.add_all([user1, salon1, review1])
        db.session.commit()
        
        return review1.review_id

def test_update_review_success_update_all_fields_200(client, setup_data):
    review_id = setup_data
    update_data = {
        "rating": 5,
        "comment": "Absolutely fantastic service!"
    }

    response = client.put(
        f"/reviews/{review_id}", 
        json=update_data
    )
    data = response.get_json()

    assert response.status_code == 200
    assert "review" in data
    assert data["review"]["review_id"] == review_id
    assert data["review"]["rating"] == 5
    assert data["review"]["comment"] == "Absolutely fantastic service!"

def test_update_review_success_update_only_rating_200(client, setup_data):
    review_id = setup_data
    update_data = {
        "rating": 1
    }

    response = client.put(
        f"/reviews/{review_id}", 
        json=update_data
    )
    data = response.get_json()

    assert response.status_code == 200
    assert data["review"]["rating"] == 1
    assert data["review"]["comment"] == "Could be better."

def test_update_review_invalid_rating_high_400(client, setup_data):
    review_id = setup_data
    update_data = {
        "rating": 6
    }

    response = client.put(
        f"/reviews/{review_id}", 
        json=update_data
    )
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_rating"

def test_update_review_not_found_404(client):
    update_data = {
        "rating": 5
    }

    response = client.put(
        "/reviews/999", 
        json=update_data
    )
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "review_not_found"