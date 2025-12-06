#!/usr/bin/env python3
"""Add missing columns to products table for backend product management feature"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app
from app.extensions import db
from sqlalchemy import text


def migrate_products_table():
    """Add category and is_available columns to products table if they don't exist"""
    app = create_app()
    with app.app_context():
        try:
            # Check if columns exist
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('products')]
            
            print("📋 Existing columns in products table:", columns)
            
            # Add category column if missing
            if 'category' not in columns:
                print("➕ Adding 'category' column...")
                db.session.execute(text(
                    "ALTER TABLE products ADD COLUMN category VARCHAR(100) AFTER stock_quantity"
                ))
                print("✅ Added 'category' column")
            else:
                print("✓ 'category' column already exists")
            
            # Add is_available column if missing
            if 'is_available' not in columns:
                print("➕ Adding 'is_available' column...")
                db.session.execute(text(
                    "ALTER TABLE products ADD COLUMN is_available BOOLEAN NOT NULL DEFAULT 1 AFTER category"
                ))
                print("✅ Added 'is_available' column")
            else:
                print("✓ 'is_available' column already exists")
            
            db.session.commit()
            print("\n✅ Migration completed successfully!")
            
            # Show final schema
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('products')]
            print("📋 Final columns in products table:", columns)
            
        except Exception as e:
            print(f"❌ Migration failed: {e}")
            db.session.rollback()
            sys.exit(1)

if __name__ == "__main__":
    migrate_products_table()
