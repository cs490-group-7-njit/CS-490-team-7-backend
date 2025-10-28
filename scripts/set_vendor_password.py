"""Utility to seed or update vendor account passwords for local development."""
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


def set_password(email: str, password: str) -> None:
    app = create_app()

    with app.app_context():
        user = User.query.filter_by(email=email).first()
        if user is None:
            user = User(name="Vendor", email=email, role="vendor")
            db.session.add(user)
            db.session.flush()

        account = AuthAccount.query.filter_by(user_id=user.user_id).first()
        if account is None:
            account = AuthAccount(user_id=user.user_id)
            db.session.add(account)

        account.password_hash = generate_password_hash(password)
        db.session.commit()

        print(f"Password for {email} has been set.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Set a vendor password for local testing.")
    parser.add_argument("email", help="Vendor email address")
    parser.add_argument("password", help="Plain-text password to hash and store")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    set_password(args.email, args.password)


if __name__ == "__main__":
    main()
