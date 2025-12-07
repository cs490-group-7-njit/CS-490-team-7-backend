import pytest
from datetime import datetime, timedelta
from app.models import Appointment, Service, db, User, Salon, Staff
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
        service = Service(service_id=1, salon_id=1, name='Haircut', duration_minutes=60, price_cents=5000)

        # Appointment to be cancelled
        appointment_booked = Appointment(
            appointment_id=10, 
            salon_id=1,
            staff_id=1, 
            service_id=1, 
            client_id=1, 
            starts_at=datetime.now() + timedelta(days=1), 
            ends_at=datetime.now() + timedelta(days=1, minutes=60), 
            status='booked'
        )
        
        # Appointment already completed (cannot be cancelled)
        appointment_completed = Appointment(
            appointment_id=11, 
            salon_id=1,
            staff_id=1, 
            service_id=1, 
            client_id=1, 
            starts_at=datetime.now() - timedelta(days=1, minutes=60), 
            ends_at=datetime.now() - timedelta(days=1), 
            status='completed'
        )

        db.session.add_all([user, vendor, salon, staff, service, appointment_booked, appointment_completed])
        db.session.commit()
        
        return appointment_booked.appointment_id, appointment_completed.appointment_id

def test_delete_appointment_success_200(client, setup_data):
    appointment_id, _ = setup_data
    
    response = client.delete(f"/appointments/{appointment_id}")
    data = response.get_json()

    assert response.status_code == 200
    assert data["message"] == "Appointment cancelled successfully"
    assert data["appointment"]["status"] == "cancelled"

def test_delete_appointment_not_found_404(client):
    non_existent_id = 999
    response = client.delete(f"/appointments/{non_existent_id}")
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"
    assert "Appointment not found" in data["message"]

def test_delete_appointment_invalid_status_400(client, setup_data):
    _, completed_appointment_id = setup_data
    
    response = client.delete(f"/appointments/{completed_appointment_id}")
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "cannot_cancel"
    assert "Cannot cancel an appointment with status 'completed'" in data["message"]