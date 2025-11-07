#!/usr/bin/env python3
"""Initialize database tables"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app
from app.extensions import db

def init_database():
    app = create_app()
    with app.app_context():
        db.create_all()
        print("✅ Database tables initialized successfully")

if __name__ == "__main__":
    init_database()
