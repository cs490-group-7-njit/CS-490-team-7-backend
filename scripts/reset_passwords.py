#!/usr/bin/env python3
"""Reset all test user passwords to 'Password123!'"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app
from app.extensions import db
from app.models import AuthAccount, User
from werkzeug.security import generate_password_hash

def reset_passwords():
    app = create_app()
    with app.app_context():
        print("🔄 Resetting passwords...")
        
        password = "Password123!"
        hashed = generate_password_hash(password)
        
        # Get all users
        users = User.query.all()
        updated_count = 0
        
        for user in users:
            auth = AuthAccount.query.filter_by(user_id=user.user_id).first()
            if auth:
                auth.password_hash = hashed
                updated_count += 1
                print(f"✅ Reset password for {user.email}")
        
        db.session.commit()
        print(f"\n✨ Successfully reset {updated_count} passwords!")
        print(f"\nAll users can now login with:")
        print(f"  Email: <any user email>")
        print(f"  Password: {password}")

if __name__ == "__main__":
    reset_passwords()
