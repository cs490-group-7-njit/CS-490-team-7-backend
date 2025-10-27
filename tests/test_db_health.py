"""Tests for the database health endpoint."""
from __future__ import annotations


def test_database_health_endpoint_ok(client) -> None:
    response = client.get("/db-health")

    assert response.status_code == 200
    assert response.json == {"database": "ok"}
