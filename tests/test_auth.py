"""Tests for vendor authentication."""
from __future__ import annotations

from datetime import datetime, timezone

from werkzeug.security import generate_password_hash

from app.extensions import db
from app.models import AuthAccount, User


def _create_user_with_auth(*, role: str, password: str, email: str = "vendor@example.com") -> None:
    user = User(name="Vendor", email=email, role=role)
    db.session.add(user)
    db.session.flush()

    auth = AuthAccount(
        user_id=user.user_id,
        password_hash=generate_password_hash(password),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.session.add(auth)
    db.session.commit()


def test_login_success(app, client) -> None:
    with app.app_context():
        _create_user_with_auth(role="vendor", password="Secret123!")

    response = client.post(
        "/auth/login",
        json={"email": "vendor@example.com", "password": "Secret123!"},
    )

    assert response.status_code == 200
    body = response.get_json()
    assert "token" in body and body["token"]
    assert body["user"]["email"] == "vendor@example.com"


def test_login_invalid_password(app, client) -> None:
    with app.app_context():
        _create_user_with_auth(role="vendor", password="Secret123!", email="wrong@example.com")

    response = client.post(
        "/auth/login",
        json={"email": "wrong@example.com", "password": "BadPass"},
    )

    assert response.status_code == 401
    body = response.get_json()
    assert body["error"] == "unauthorized"


def test_login_client_allowed(app, client) -> None:
    with app.app_context():
        _create_user_with_auth(role="client", password="Secret123!", email="client@example.com")

    response = client.post(
        "/auth/login",
        json={"email": "client@example.com", "password": "Secret123!"},
    )

    assert response.status_code == 200
    body = response.get_json()
    assert "token" in body and body["token"]
    assert body["user"]["email"] == "client@example.com"
    assert body["user"]["role"] == "client"
