#!/usr/bin/env python3
"""
Seed script to create fake payment methods for testing UC 2.18.
Run this script to populate the database with fake credit cards.
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app, db
from app.models import PaymentMethod, User

def seed_payment_methods():
    """Create fake payment methods for testing."""
    app = create_app()
    
    with app.app_context():
        print("🔄 Seeding fake payment methods...")
        
        # Get some existing users (clients)
        users = User.query.filter_by(role="client").limit(5).all()
        
        if not users:
            print("❌ No client users found. Please create some clients first.")
            return
        
        # Fake credit cards for testing
        fake_cards = [
            {"name": "Visa", "number": "4532123456789010", "brand": "Visa"},
            {"name": "Mastercard", "number": "5425233433109903", "brand": "Mastercard"},
            {"name": "American Express", "number": "378282246310005", "brand": "American Express"},
        ]
        
        created_count = 0
        
        for user in users:
            # Check if this user already has payment methods
            existing_count = PaymentMethod.query.filter_by(user_id=user.user_id).count()
            
            if existing_count > 0:
                print(f"⏭️  User {user.name} already has {existing_count} payment method(s)")
                continue
            
            # Add 1-2 payment methods per user
            for i, card in enumerate(fake_cards[:2]):
                payment_method = PaymentMethod(
                    user_id=user.user_id,
                    card_holder_name=user.name,
                    card_number_last_four=card["number"][-4:],
                    card_brand=card["brand"],
                    expiry_month=12,
                    expiry_year=2027,
                    is_default=(i == 0),  # First card is default
                )
                
                db.session.add(payment_method)
                created_count += 1
                print(f"✅ Added {card['brand']} card for {user.name} (***{card['number'][-4:]})")
        
        db.session.commit()
        print(f"\n✨ Successfully created {created_count} fake payment methods!")
        
        # Show summary
        total_methods = PaymentMethod.query.count()
        default_methods = PaymentMethod.query.filter_by(is_default=True).count()
        
        print(f"\nPayment Methods Summary:")
        print(f"  Total methods: {total_methods}")
        print(f"  Default methods: {default_methods}")
        print(f"\nSample cards for testing:")
        for card in fake_cards:
            print(f"  - {card['brand']}: {card['number']} (Last 4: {card['number'][-4:]})")

if __name__ == "__main__":
    seed_payment_methods()
