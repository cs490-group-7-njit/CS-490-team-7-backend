"""Tests for the database health endpoint."""
from __future__ import annotations

from app import create_app


def test_database_health_endpoint_ok() -> None:
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    client = app.test_client()

    response = client.get("/db-health")

    assert response.status_code == 200
    assert response.json == {"database": "ok"}
