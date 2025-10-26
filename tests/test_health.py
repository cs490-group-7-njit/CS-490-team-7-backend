"""Smoke tests for the health endpoint."""
from __future__ import annotations

from app import create_app


def test_health_endpoint() -> None:
    app = create_app({"TESTING": True})
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json == {"status": "ok"}
