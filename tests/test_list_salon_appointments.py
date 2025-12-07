import pytest
from datetime import datetime, date, time
from app.models import db, Appointment, Salon, User, Staff
from flask import json

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def setup_data(app):
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()

        user1 = User(user_id=1, name='Vendor User', email='vendor@example.com', role='vendor')
        user2 = User(user_id=2, name='Staff User', email='staff@example.com', role='barber')
        salon = Salon(salon_id=1, vendor_id=1, name='The Barbershop', business_type='Barber', city='Testville', state='NJ', postal_code='12345', address_line1='123 Main St')
        staff = Staff(staff_id=1, title='Senior Barber', salon_id=1, user_id=2)

        today = date.today()
        
        appt1 = Appointment(
            appointment_id=101,
            salon_id=1,
            staff_id=1,
            service_id=1,
            client_id=3,
            starts_at=datetime.combine(today, time(10, 0)),
            ends_at=datetime.combine(today, time(11, 0)),
            status='booked'
        )
        
        appt2 = Appointment(
            appointment_id=102,
            salon_id=1,
            staff_id=1,
            service_id=2,
            client_id=4,
            starts_at=datetime.combine(today, time(9, 0)),
            ends_at=datetime.combine(today, time(10, 0)),
            status='completed'
        )
        
        def to_dict(self):
            return {
                "appointment_id": self.appointment_id,
                "salon_id": self.salon_id,
                "status": self.status,
                "starts_at": self.starts_at.isoformat()
            }

        Appointment.to_dict = to_dict

        db.session.add_all([user1, user2, salon, staff, appt1, appt2])
        db.session.commit()
        
        return salon.salon_id

def test_list_salon_appointments_success_200(client, setup_data):
    salon_id = setup_data
    response = client.get(f"/salons/{salon_id}/appointments")
    data = response.get_json()

    assert response.status_code == 200
    assert "appointments" in data
    assert len(data["appointments"]) == 2
    assert data["appointments"][0]["appointment_id"] == 101
    assert data["appointments"][1]["appointment_id"] == 102

def test_list_salon_appointments_filter_status_200(client, setup_data):
    salon_id = setup_data
    response = client.get(f"/salons/{salon_id}/appointments?status=booked")
    data = response.get_json()

    assert response.status_code == 200
    assert len(data["appointments"]) == 1
    assert data["appointments"][0]["status"] == "booked"

def test_list_salon_appointments_filter_date_200(client, setup_data):
    salon_id = setup_data
    today_str = date.today().isoformat()
    response = client.get(f"/salons/{salon_id}/appointments?date={today_str}")
    data = response.get_json()

    assert response.status_code == 200
    assert len(data["appointments"]) == 2

def test_list_salon_appointments_salon_not_found_404(client):
    response = client.get("/salons/999/appointments")
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"
    assert "Salon not found" in data["message"]

def test_list_salon_appointments_invalid_date_400(client, setup_data):
    salon_id = setup_data
    response = client.get(f"/salons/{salon_id}/appointments?date=not-a-date")
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_date"
    assert "Date must be in YYYY-MM-DD format" in data["message"]