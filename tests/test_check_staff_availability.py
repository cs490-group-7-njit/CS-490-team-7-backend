import pytest
from datetime import datetime, date, time, timedelta
from app.models import db, Staff, Schedule, Appointment, Salon, User
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

        user = User(user_id=1, name='Test Staff User', email='staff@example.com', role='barber') 
        salon = Salon(salon_id=1, vendor_id=1, name='Test Salon', business_type='Barber', city='Testville', state='NJ', postal_code='12345', address_line1='123 Main St')
        
        staff_id = 1
        staff = Staff(staff_id=staff_id, title='Test Staff', salon_id=1, user_id=1)

        tuesday_schedule = Schedule(
            staff_id=staff_id, 
            day_of_week=2, 
            start_time=time(9, 0), 
            end_time=time(17, 0)
        )
        
        today = date.today()
        days_ahead = (2 - today.isoweekday()) % 7 
        if days_ahead == 0: 
            days_ahead = 7
        target_date = today + timedelta(days=days_ahead) 
        
        appointment_conflict = Appointment(
            appointment_id=1,
            salon_id=1,
            staff_id=staff_id,
            service_id=1,
            client_id=1,
            starts_at=datetime.combine(target_date, time(10, 0)),
            ends_at=datetime.combine(target_date, time(11, 0)),
            status='booked'
        )

        db.session.add_all([user, salon, staff, tuesday_schedule, appointment_conflict])
        db.session.commit()
        
        return staff_id

def test_check_staff_availability_success_200(client, setup_data):
    staff_id = setup_data
    
    today = date.today()
    days_ahead = (2 - today.isoweekday()) % 7
    if days_ahead == 0:
        days_ahead = 7
    target_date = today + timedelta(days=days_ahead)
    target_date_str = target_date.isoformat()

    response = client.get(
        f"/staff/{staff_id}/availability?date={target_date_str}&duration_minutes=60"
    )
    data = response.get_json()

    assert response.status_code == 200
    assert "available_slots" in data
    assert len(data["available_slots"]) > 0 
    
    expected_start_time = f"{target_date_str}T09:00:00"
    booked_time = f"{target_date_str}T10:00:00"
    after_booked_time = f"{target_date_str}T11:00:00"

    assert expected_start_time in data["available_slots"]
    assert booked_time not in data["available_slots"] 
    assert after_booked_time in data["available_slots"]


def test_check_staff_availability_missing_params_400(client, setup_data):
    staff_id = setup_data
    
    response = client.get(f"/staff/{staff_id}/availability?date=2099-01-01")
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_payload"
    assert "date (YYYY-MM-DD) and duration_minutes are required" in data["message"]

def test_check_staff_availability_invalid_date_400(client, setup_data):
    staff_id = setup_data
    
    response = client.get(f"/staff/{staff_id}/availability?date=invalid-date&duration_minutes=30")
    data = response.get_json()

    assert response.status_code == 400
    assert data["error"] == "invalid_payload"
    assert "date must be in YYYY-MM-DD format" in data["message"]

def test_check_staff_availability_staff_not_found_404(client):
    non_existent_staff_id = 999
    response = client.get(
        f"/staff/{non_existent_staff_id}/availability?date=2099-01-01&duration_minutes=30"
    )
    data = response.get_json()

    assert response.status_code == 404
    assert data["error"] == "not_found"
    assert "Staff not found" in data["message"]

def test_check_staff_availability_no_schedule_200(client, setup_data):
    staff_id = setup_data
    today = date.today()
    days_ahead = (7 - today.isoweekday()) % 7 
    if days_ahead == 0:
        days_ahead = 7
    target_date = today + timedelta(days=days_ahead)
    target_date_str = target_date.isoformat()
    
    response = client.get(
        f"/staff/{staff_id}/availability?date={target_date_str}&duration_minutes=30"
    )
    data = response.get_json()

    assert response.status_code == 200
    assert data["available_slots"] == []