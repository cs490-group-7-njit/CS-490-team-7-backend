"""Utility to seed or update user account passwords for local development."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

# Ensure the project root is on sys.path so ``app`` can be imported when the script is executed directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.extensions import db
from app.models import AuthAccount, User


def set_password(email: str, password: str, role: str = "vendor") -> None:
    app = create_app()

    # Validate role
    valid_roles = ["client", "vendor", "admin"]
    if role not in valid_roles:
        print(f"Error: Invalid role '{role}'. Valid roles are: {', '.join(valid_roles)}")
        return

    # Set default names based on role
    default_names = {
        "client": "Client User",
        "vendor": "Vendor User", 
        "admin": "Admin User"
    }

    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user is None:
            user = User(name=default_names[role], email=email, role=role)
            db.session.add(user)
            db.session.flush()
            print(f"Created new {role} user: {email}")
        else:
            # Update existing user's role if different
            if user.role != role:
                print(f"Updating user role from '{user.role}' to '{role}'")
                user.role = role

        account = AuthAccount.query.filter_by(user_id=user.user_id).first()
        if account is None:
            account = AuthAccount(user_id=user.user_id)
            db.session.add(account)
            print(f"Created auth account for user: {email}")

        account.password_hash = generate_password_hash(password)
        db.session.commit()

        print(f"Password for {role} user '{email}' has been set successfully.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Set a user password for local testing.")
    parser.add_argument("email", help="User email address")
    parser.add_argument("password", help="Plain-text password to hash and store")
    parser.add_argument(
        "--role", 
        choices=["client", "vendor", "admin"], 
        default="vendor",
        help="User role (default: vendor)"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    set_password(args.email, args.password, args.role)


if __name__ == "__main__":
    main()
