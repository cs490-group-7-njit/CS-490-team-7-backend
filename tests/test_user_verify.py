"""Tests for user verification lookup endpoint."""
from __future__ import annotations

from app.extensions import db
from app.models import User


def _seed_user(*, email: str = "vendor@example.com") -> None:
    user = User(name="Vendor", email=email, role="vendor")
    db.session.add(user)
    db.session.commit()


def test_verify_user_found(app, client) -> None:
    with app.app_context():
        _seed_user()

    response = client.get("/users/verify", query_string={"email": "vendor@example.com"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["user"]["email"] == "vendor@example.com"


def test_verify_user_not_found(app, client) -> None:
    response = client.get("/users/verify", query_string={"email": "missing@example.com"})

    assert response.status_code == 404
    payload = response.get_json()
    assert payload["error"] == "not_found"


def test_verify_user_requires_email(app, client) -> None:
    response = client.get("/users/verify")

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "invalid_query"
