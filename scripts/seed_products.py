#!/usr/bin/env python3
"""Seed the database with sample products for salons."""
import sys
from pathlib import Path

# Add the parent directory to the path so we can import the app
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app, db
from app.models import Product, Salon

def seed_products():
    """Add sample products to salons."""
    app = create_app()
    
    with app.app_context():
        # Get all salons
        salons = Salon.query.all()
        
        if not salons:
            print("❌ No salons found in database. Please create salons first.")
            return
        
        print(f"📍 Found {len(salons)} salons")
        
        # Sample products
        sample_products = [
            {
                "name": "Premium Hair Shampoo",
                "description": "Moisturizing shampoo with natural ingredients",
                "price_cents": 1800,  # $18.00
                "stock_quantity": 50,
                "category": "Hair Care"
            },
            {
                "name": "Deep Conditioning Mask",
                "description": "Intensive hair repair treatment",
                "price_cents": 3200,  # $32.00
                "stock_quantity": 30,
                "category": "Hair Care"
            },
            {
                "name": "Leave-in Conditioner",
                "description": "Lightweight conditioning spray",
                "price_cents": 1200,  # $12.00
                "stock_quantity": 75,
                "category": "Hair Care"
            },
            {
                "name": "Hair Growth Oil",
                "description": "Promotes hair growth and scalp health",
                "price_cents": 2500,  # $25.00
                "stock_quantity": 40,
                "category": "Hair Care"
            },
            {
                "name": "Styling Gel",
                "description": "Strong hold styling gel for all hair types",
                "price_cents": 1000,  # $10.00
                "stock_quantity": 60,
                "category": "Styling"
            },
        ]
        
        # Add products to each salon
        for salon in salons:
            existing_count = Product.query.filter_by(salon_id=salon.salon_id or salon.id).count()
            
            if existing_count > 0:
                print(f"⏭️  Salon {salon.name} already has products ({existing_count}). Skipping...")
                continue
            
            salon_id = salon.salon_id or salon.id
            print(f"📦 Adding products to {salon.name} (ID: {salon_id})...")
            
            for product_data in sample_products:
                product = Product(
                    salon_id=salon_id,
                    name=product_data["name"],
                    description=product_data["description"],
                    price_cents=product_data["price_cents"],
                    stock_quantity=product_data["stock_quantity"],
                    category=product_data["category"],
                    is_available=True
                )
                db.session.add(product)
                print(f"  ✓ Added: {product_data['name']} (${product_data['price_cents']/100:.2f})")
        
        db.session.commit()
        print("\n✅ Products seeded successfully!")
        
        # Verify
        total_products = Product.query.count()
        print(f"📊 Total products in database: {total_products}")

if __name__ == "__main__":
    seed_products()
