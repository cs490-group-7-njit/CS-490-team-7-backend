import pytest
from datetime import datetime, timedelta, time
from app.models import Appointment, Service, db, User, Salon, Staff, Schedule
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

        user = User(user_id=1, name='Test Client', email='client@example.com', role='client')
        vendor = User(user_id=2, name='Vendor User', email='vendor@example.com', role='vendor')
        salon = Salon(salon_id=1, vendor_id=2, name='Test Salon', business_type='Barber', city='Testville', state='NJ', postal_code='12345', address_line1='123 Main St')
        staff = Staff(staff_id=1, salon_id=1, title='Barber 1', user_id=1)
        service = Service(service_id=1, salon_id=1, name='Consultation', duration_minutes=30, price_cents=5000)

        schedule = Schedule(staff_id=1, day_of_week=1, start_time=time(9, 0), end_time=time(17, 0))

        original_start = datetime.now().replace(hour=10, minute=0, second=0, microsecond=0) + timedelta(days=1)
        while original_start.weekday() != 0:
            original_start += timedelta(days=1)
        original_end = original_start + timedelta(minutes=30)

        appointment = Appointment(
            appointment_id=10, 
            salon_id=1,
            staff_id=1, 
            service_id=1, 
            client_id=1, 
            starts_at=original_start, 
            ends_at=original_end, 
            status='booked'
        )
        
        db.session.add_all([user, vendor, salon, staff, service, schedule, appointment])
        db.session.commit()
        
        new_start = original_start.replace(hour=11, minute=0, second=0, microsecond=0)
        
        conflict_start = original_start
        
        return appointment.appointment_id, new_start.isoformat(), conflict_start.isoformat()

def test_reschedule_appointment_success_200(client, setup_data):
    appointment_id, new_start_iso, _ = setup_data
    
    response = client.put(
        f"/appointments/{appointment_id}/reschedule",
        data=json.dumps({"starts_at": new_start_iso}),
        content_type="application/json"
    )
    data = response.get_json()

    assert response.status_code == 200
    assert data["appointment"]["starts_at"] == new_start_iso.replace("+00:00", "Z")

def test_reschedule_appointment_conflict_409(client, setup_data):
    appointment_id, _, conflict_start_iso = setup_data
    
    with client.application.app_context():
        db.session.add(Appointment(
            appointment_id=11,
            salon_id=1,
            staff_id=1,
            service_id=1,
            client_id=1,
            starts_at=datetime.fromisoformat(conflict_start_iso),
            ends_at=datetime.fromisoformat(conflict_start_iso) + timedelta(minutes=30),
            status='booked'
        ))
        db.session.commit()

    response = client.put(
        f"/appointments/{appointment_id}/reschedule",
        data=json.dumps({"starts_at": conflict_start_iso}),
        content_type="application/json"
    )
    data = response.get_json()

    assert response.status_code == 409
    assert data["error"] == "conflict"
    assert "Time slot conflicts with another appointment" in data["message"]

def test_reschedule_appointment_not_found_404(client):
    non_existent_id = 999
    response = client.put(
        f"/appointments/{non_existent_id}/reschedule",
        data=json.dumps({"starts_at": "2050-01-01T10:00:00Z"}),
        content_type="application/json"
    )
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"
    assert "Appointment not found" in data["message"]

def test_reschedule_appointment_invalid_status_400(client, setup_data):
    appointment_id, new_start_iso, _ = setup_data
    
    with client.application.app_context():
        appointment = Appointment.query.get(appointment_id)
        appointment.status = "completed"
        db.session.commit()
    
    response = client.put(
        f"/appointments/{appointment_id}/reschedule",
        data=json.dumps({"starts_at": new_start_iso}),
        content_type="application/json"
    )
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "cannot_reschedule"
    assert "Cannot reschedule an appointment with status 'completed'" in data["message"]