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
        user2 = User(user_id=2, name='Client B', email='clientb@example.com', role='client')
        salon1 = Salon(salon_id=1, vendor_id=1, name='Test Salon 1', business_type='Barber', city='Testville', state='NJ', postal_code='12345', address_line1='123 Main St')
        
        db.session.add_all([user1, user2, salon1])
        db.session.commit()

        review1 = Review(review_id=101, salon_id=1, client_id=1, rating=5, comment='Great service!', created_at=datetime(2023, 1, 1, 10, 0, 0))
        review2 = Review(review_id=102, salon_id=1, client_id=2, rating=3, comment='It was okay.', created_at=datetime(2023, 1, 2, 10, 0, 0))
        review3 = Review(review_id=103, salon_id=1, client_id=1, rating=1, comment='Very bad.', created_at=datetime(2023, 1, 3, 10, 0, 0))

        db.session.add_all([review1, review2, review3])
        db.session.commit()
        
        return salon1.salon_id

def test_get_salon_reviews_success_default_sort_200(client, setup_data):
    salon_id = setup_data
    response = client.get(f"/salons/{salon_id}/reviews")
    data = response.get_json()

    assert response.status_code == 200
    assert "reviews" in data
    assert len(data["reviews"]) == 3
    assert data["total_reviews"] == 3
    assert data["average_rating"] == 3.0
    assert data["reviews"][0]["review_id"] == 103
    assert data["reviews"][2]["review_id"] == 101

def test_get_salon_reviews_sort_by_rating_asc_200(client, setup_data):
    salon_id = setup_data
    response = client.get(f"/salons/{salon_id}/reviews?sort_by=rating&order=asc")
    data = response.get_json()

    assert response.status_code == 200
    assert data["reviews"][0]["review_id"] == 103
    assert data["reviews"][1]["review_id"] == 102
    assert data["reviews"][2]["review_id"] == 101

def test_get_salon_reviews_filter_min_rating_200(client, setup_data):
    salon_id = setup_data
    response = client.get(f"/salons/{salon_id}/reviews?min_rating=4")
    data = response.get_json()

    assert response.status_code == 200
    assert len(data["reviews"]) == 1
    assert data["filtered_count"] == 1
    assert data["reviews"][0]["rating"] == 5

def test_get_salon_reviews_pagination_limit_1_200(client, setup_data):
    salon_id = setup_data
    response = client.get(f"/salons/{salon_id}/reviews?limit=1&offset=0")
    data = response.get_json()

    assert response.status_code == 200
    assert len(data["reviews"]) == 1
    assert data["reviews"][0]["review_id"] == 103
    assert data["pagination"]["total"] == 3
    assert data["pagination"]["has_more"] == True

def test_get_salon_reviews_not_found_404(client):
    response = client.get("/salons/999/reviews")
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "salon_not_found"