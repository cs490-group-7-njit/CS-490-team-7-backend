import pytest
from datetime import datetime, timedelta
from app.models import Appointment, Service, db, User, Salon, Staff
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
        
        user = User(user_id=100, name='Test Client', email='test@example.com', role='client')

        salon = Salon(salon_id=1, vendor_id=100, name='Test Salon', business_type='Barber', city='Testville', state='NJ')
        
        staff = Staff(staff_id=1, salon_id=1, title='Barber 1')
        
        service = Service(service_id=1, salon_id=1, name='Consultation', duration_minutes=30, price_cents=5000)
        
        start_time = datetime.now() + timedelta(days=1)
        end_time = start_time + timedelta(minutes=30)
        
        appointment = Appointment(
            appointment_id=5, 
            salon_id=1, 
            staff_id=1,
            service_id=1, 
            client_id=100, 
            starts_at=start_time, 
            ends_at=end_time, 
            status='booked', 
            notes='Initial note'
        )
        
        db.session.add_all([user, salon, staff, service, appointment])
        db.session.commit()
        
        yield 5
        db.session.remove()
        db.drop_all()

def test_update_appointment_success_200(client, setup_data, app):
    appointment_id = setup_data
    new_starts_at = (datetime.now() + timedelta(days=2)).isoformat(timespec='seconds')
    new_notes = "Updated note with details."
    payload = {
        "starts_at": new_starts_at,
        "notes": new_notes,
        "status": "completed"
    }
    
    response = client.put(f"/appointments/{appointment_id}", json=payload)
    data = response.get_json()

    assert response.status_code == 200
    assert data["message"] == "Appointment updated successfully"
    assert data["appointment"]["id"] == appointment_id
    assert data["appointment"]["status"] == "completed"
    assert data["appointment"]["notes"] == new_notes

    with app.app_context():
        updated_appointment = db.session.get(Appointment, appointment_id)
        assert updated_appointment.status == "completed"
        assert updated_appointment.notes == new_notes
        expected_starts_at = datetime.fromisoformat(new_starts_at)
        assert updated_appointment.starts_at.replace(microsecond=0) == expected_starts_at.replace(microsecond=0)

def test_update_appointment_not_found_404(client, app):
    non_existent_id = 999
    payload = {"notes": "Test"}
    
    response = client.put(f"/appointments/{non_existent_id}", json=payload)
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"
    assert "Appointment not found" in data["message"]