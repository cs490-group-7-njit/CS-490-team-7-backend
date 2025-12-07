import pytest
from datetime import datetime, date, time
from app.models import db, Appointment, Salon, User, Staff, Service, ClientLoyalty, Notification
from flask import json
from sqlalchemy.exc import SQLAlchemyError

@pytest.fixture
def client(app):
    return app.test_client()

def to_dict(self):
    return {
        "appointment_id": self.appointment_id,
        "salon_id": self.salon_id,
        "status": self.status,
        "client_id": self.client_id,
        "starts_at": self.starts_at.isoformat() if self.starts_at else None,
        "service": {"price_cents": self.service.price_cents if self.service else 0}
    }

Appointment.to_dict = to_dict

@pytest.fixture
def setup_data(app):
    with app.app_context():
        db.session.remove()
        db.drop_all()
        db.create_all()

        vendor_user = User(user_id=1, name='Vendor User', email='vendor@example.com', role='vendor')
        staff_user = User(user_id=2, name='Staff User', email='staff@example.com', role='barber')
        client_user = User(user_id=3, name='Client User', email='client@example.com', role='client')
        
        salon = Salon(salon_id=1, vendor_id=1, name='The Barbershop', business_type='Barber', city='Testville', state='NJ', postal_code='12345', address_line1='123 Main St')
        staff = Staff(staff_id=1, title='Senior Barber', salon_id=1, user_id=2)
        service = Service(service_id=1, salon_id=1, name='Haircut', price_cents=2500, duration_minutes=60)
        
        today = date.today()
        
        appt_booked = Appointment(
            appointment_id=101,
            salon_id=1,
            staff_id=1,
            service_id=1,
            service=service,
            client_id=3,
            starts_at=datetime.combine(today, time(10, 0)),
            ends_at=datetime.combine(today, time(11, 0)),
            status='booked'
        )
        
        db.session.add_all([vendor_user, staff_user, client_user, salon, staff, service, appt_booked])
        db.session.commit()
        
        return 101 

def test_update_appointment_status_to_completed_200(client, setup_data, app):
    appointment_id = setup_data
    
    response = client.put(
        f"/appointments/{appointment_id}/status", 
        json={"status": "completed"}
    )
    data = response.get_json()

    assert response.status_code == 200
    assert data["appointment"]["status"] == "completed"

    with app.app_context():
        updated_appt = Appointment.query.get(appointment_id)
        assert updated_appt.status == "completed"
        
        loyalty = ClientLoyalty.query.filter_by(client_id=3, salon_id=1).first()
        assert loyalty is not None
        assert loyalty.points_balance == 25
        
        notification = Notification.query.filter_by(appointment_id=appointment_id).first()
        assert notification is not None
        assert "You earned 25 loyalty points" in notification.message

def test_update_appointment_status_invalid_status_400(client, setup_data):
    appointment_id = setup_data
    
    response = client.put(
        f"/appointments/{appointment_id}/status", 
        json={"status": "in_progress"}
    )
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_status"

def test_update_appointment_status_not_found_404(client):
    response = client.put(
        "/appointments/999/status", 
        json={"status": "completed"}
    )
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"