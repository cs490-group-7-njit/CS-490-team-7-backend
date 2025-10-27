"""Tests for the salons listing endpoint."""
from __future__ import annotations

from datetime import datetime

from app.extensions import db
from app.models import Salon, User


def test_list_salons_returns_only_published_salons(app, client) -> None:
    with app.app_context():
        vendor = User(name="Vicky Vendor", email="vicky@example.com", role="vendor")
        db.session.add(vendor)
        db.session.flush()

        published = Salon(
            vendor_id=vendor.user_id,
            name="The Cutting Edge",
            address_line1="123 Shear St",
            city="New York",
            state="NY",
            postal_code="10001",
            phone="212-555-0101",
            is_published=True,
            verification_status="approved",
            created_at=datetime(2024, 1, 1, 10, 0, 0),
        )
        unpublished = Salon(
            vendor_id=vendor.user_id,
            name="Hidden Styles",
            is_published=False,
            verification_status="pending",
        )

        db.session.add_all([published, unpublished])
        db.session.commit()

    response = client.get("/salons")

    assert response.status_code == 200
    payload = response.get_json()
    assert isinstance(payload, dict)
    assert "salons" in payload
    assert len(payload["salons"]) == 1

    salon_data = payload["salons"][0]
    assert salon_data["name"] == "The Cutting Edge"
    assert salon_data["vendor"]["name"] == "Vicky Vendor"
    assert salon_data["verification_status"] == "approved"
