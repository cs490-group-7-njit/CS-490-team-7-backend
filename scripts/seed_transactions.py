#!/usr/bin/env python3
"""
Seed script to create fake transaction history for testing UC 2.19.
Run this script to populate the database with fake payment data.
"""

import sys
import os
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app, db
from app.models import Transaction, Appointment, PaymentMethod, User

def seed_transactions():
    """Create fake transactions for testing."""
    app = create_app()
    
    with app.app_context():
        print("🔄 Seeding fake transaction history...")
        
        # Get some existing appointments and users
        appointments = Appointment.query.limit(10).all()
        
        if not appointments:
            print("❌ No appointments found. Please create some appointments first.")
            return
        
        # Create fake transactions for each appointment
        transaction_statuses = ["completed", "pending", "completed", "refunded", "completed"]
        created_count = 0
        
        for i, appointment in enumerate(appointments):
            # Check if transaction already exists for this appointment
            existing = Transaction.query.filter_by(appointment_id=appointment.appointment_id).first()
            if existing:
                print(f"⏭️  Transaction already exists for appointment {appointment.appointment_id}")
                continue
            
            # Create transaction
            status = transaction_statuses[i % len(transaction_statuses)]
            transaction_date = appointment.created_at - timedelta(days=i)
            
            transaction = Transaction(
                user_id=appointment.client_id,
                appointment_id=appointment.appointment_id,
                payment_method_id=1,  # Use first payment method
                amount_cents=appointment.service.price_cents if appointment.service else 3000,
                status=status,
                transaction_date=transaction_date,
            )
            
            db.session.add(transaction)
            created_count += 1
            print(f"✅ Created transaction for appointment {appointment.appointment_id} (${transaction.amount_cents/100:.2f}) - Status: {status}")
        
        db.session.commit()
        print(f"\n✨ Successfully created {created_count} fake transactions!")
        print("\nTransaction Summary:")
        
        # Show summary
        total_transactions = Transaction.query.count()
        total_amount = db.session.query(db.func.sum(Transaction.amount_cents)).scalar() or 0
        
        print(f"  Total transactions: {total_transactions}")
        print(f"  Total amount: ${total_amount/100:.2f}")
        print(f"  Transactions by status:")
        
        for status in ["completed", "pending", "failed", "refunded"]:
            count = Transaction.query.filter_by(status=status).count()
            if count > 0:
                print(f"    - {status}: {count}")

if __name__ == "__main__":
    seed_transactions()
