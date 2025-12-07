import pytest
from unittest.mock import patch, Mock
from app.models import Service, db
from flask import current_app

@pytest.fixture
def setup_service():
    service = Service(service_id=1, salon_id=1, name="Basic Haircut", duration_minutes=30, price_cents=2500)
    db.session.add(service)
    db.session.commit()
    return service.service_id


def test_create_payment_intent_no_id_400(client):
    response = client.post("/create-payment-intent", json={})
    data = response.get_json()
    assert response.status_code == 401

@patch('flask_jwt_extended.get_jwt_identity', return_value=None)
def test_create_payment_intent_unauthorized_401(mock_jwt, client):
    response = client.post("/create-payment-intent", json={"service_id": 1})
    data = response.get_json()
    assert response.status_code == 401
    assert data["error"] == "unauthorized"
