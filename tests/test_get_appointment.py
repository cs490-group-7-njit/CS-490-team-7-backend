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
        try:
            db.session.remove()
            db.drop_all()
        except Exception:
            pass

        db.create_all()

        vendor_user = User(user_id=100, name='Vendor User', email='vendor@example.com', role='vendor')
        client_user = User(user_id=101, name='Test Client', email='client@example.com', role='client')

        salon = Salon(
            salon_id=1, 
            vendor_id=100, 
            name='Test Salon', 
            business_type='Barber', 
            city='Testville', 
            state='NJ',
            postal_code='12345',
            address_line1='123 Main St',
            phone='555-1234'
        )

        staff = Staff(staff_id=1, salon_id=1, title='Barber 1', user_id=101)
        
        service = Service(service_id=1, salon_id=1, name='Consultation', duration_minutes=30, price_cents=5000)
        
        start_time = datetime.now() + timedelta(days=1)
        end_time = start_time + timedelta(minutes=30)
        
        appointment = Appointment(
            appointment_id=5, 
            salon_id=1,
            staff_id=1, 
            service_id=1, 
            client_id=101, 
            starts_at=start_time, 
            ends_at=end_time, 
            status='booked', 
            notes='Initial note'
        )
        
        db.session.add_all([vendor_user, client_user, salon, staff, service, appointment])
        db.session.commit()
        
        yield 5
        db.session.remove()
        db.drop_all()

def test_get_appointment_success_200(client, setup_data):
    appointment_id = setup_data
    response = client.get(f"/appointments/{appointment_id}")
    data = response.get_json()

    assert response.status_code == 200
    
    if 'id' in data['appointment']:
        assert data["appointment"]["id"] == appointment_id
    else:
        assert data["appointment"]["appointment_id"] == appointment_id

    assert data["appointment"]["status"] == "booked"
    assert data["appointment"]["notes"] == "Initial note"
    assert data["appointment"]["client"]["id"] == 101
    assert data["appointment"]["salon"]["name"] == "Test Salon"
    assert data["appointment"]["service"]["price_cents"] == 5000
    assert data["appointment"]["staff"]["staff_id"] == 1

def test_get_appointment_not_found_404(client):
    non_existent_id = 999
    response = client.get(f"/appointments/{non_existent_id}")
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"
    assert "Appointment not found" in data["message"]