# UC 1.5 Backend Database Migration

## Date: October 27, 2025

### Changes Made
Added missing columns to the `salons` table required for UC 1.5 (Submit for Verification):

```sql
ALTER TABLE salons 
ADD COLUMN description LONGTEXT COLLATE utf8mb4_general_ci AFTER name,
ADD COLUMN business_type VARCHAR(100) COLLATE utf8mb4_general_ci AFTER description;
```

### Columns Added
1. **description** - LONGTEXT
   - Purpose: Store salon description/about information
   - Used by: UC 1.3 (Publish Shop), UC 1.4 (Manage Shop Details)
   
2. **business_type** - VARCHAR(100)
   - Purpose: Store salon business type/category
   - Used by: UC 1.3 (Publish Shop), UC 1.4 (Manage Shop Details)

### Migration Method
Applied directly via Python script to development database using SQLAlchemy.

```python
from app import create_app, db
from sqlalchemy import text

app = create_app()
with app.app_context():
    db.session.execute(text("""
        ALTER TABLE salons 
        ADD COLUMN description LONGTEXT COLLATE utf8mb4_general_ci AFTER name,
        ADD COLUMN business_type VARCHAR(100) COLLATE utf8mb4_general_ci AFTER description
    """))
    db.session.commit()
```

### Verification
✅ Endpoints tested:
- GET /salons - Successfully returns salons with new columns
- PUT /salons/:id - Successfully updates description and business_type
- PUT /salons/:id/verify - Successfully submits for verification

### Related Use Cases
- UC 1.3 - Publish Shop
- UC 1.4 - Manage Shop Details
- UC 1.5 - Submit Salon for Verification (Frontend)

## Date: December 1, 2025

## Add `gateway_payment_id` to `transactions` table (Payment integration)

### Purpose
Add a column to store the external payment gateway identifier (e.g. Stripe PaymentIntent id) so payments can be reconciled and webhooks can update transaction records.

### SQL
```sql
ALTER TABLE transactions
ADD COLUMN gateway_payment_id VARCHAR(255) NULL AFTER payment_method_id,
ADD UNIQUE INDEX idx_gateway_payment_id (gateway_payment_id);
```

### Python (SQLAlchemy) example
```python
from app import create_app, db
from sqlalchemy import text

app = create_app()
with app.app_context():
    db.session.execute(text("""
        ALTER TABLE transactions 
        ADD COLUMN gateway_payment_id VARCHAR(255) NULL AFTER payment_method_id,
        ADD UNIQUE INDEX idx_gateway_payment_id (gateway_payment_id);
    """))
    db.session.commit()
```

### Notes
- If you use Alembic or another migration tool, create a migration that adds this column instead of running raw SQL.
- The unique constraint on `gateway_payment_id` prevents race conditions where multiple requests could attempt to create duplicate transactions for the same payment.
- After applying the migration, run tests and verify the `transactions` table now has the `gateway_payment_id` column with a unique constraint.

