# Milestone 4: Before/After Service Images

## Database Migration

### Date: December 4, 2025

### New Table: `appointment_images`

This table stores before/after transformation photos linked to specific appointments, allowing clients to view their transformations and vendors to showcase portfolio examples.

```sql
CREATE TABLE appointment_images (
  image_id INT PRIMARY KEY AUTO_INCREMENT,
  appointment_id INT NOT NULL,
  image_type ENUM('before', 'after', 'other') NOT NULL,
  image_url VARCHAR(500) NOT NULL,
  s3_key VARCHAR(500),
  description LONGTEXT,
  uploaded_by_id INT,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (appointment_id) REFERENCES appointments(appointment_id) ON DELETE CASCADE,
  FOREIGN KEY (uploaded_by_id) REFERENCES users(user_id) ON DELETE SET NULL,
  INDEX idx_appointment (appointment_id),
  INDEX idx_type (image_type),
  INDEX idx_created (created_at)
);
```

### Columns Explained

| Column | Type | Purpose |
|--------|------|---------|
| `image_id` | INT (PK) | Unique identifier |
| `appointment_id` | INT (FK) | Links to appointment |
| `image_type` | ENUM | 'before', 'after', or 'other' |
| `image_url` | VARCHAR(500) | S3 HTTPS URL |
| `s3_key` | VARCHAR(500) | S3 object key for deletion |
| `description` | LONGTEXT | Optional transformation notes |
| `uploaded_by_id` | INT (FK) | User who uploaded |
| `created_at` | DATETIME | Upload timestamp |

### Backend API Endpoints

**POST** `/appointments/{id}/images`
- Upload before/after image
- Authorization: Client or vendor on appointment
- Multipart form data with `image`, `type`, `description`
- Returns: 201 with created image object
- Storage: AWS S3 with automatic key generation

**GET** `/appointments/{id}/images`
- Retrieve all images for appointment
- Returns: Images grouped by type (before, after, other)
- Accessible by: Client, vendor, or admin

**DELETE** `/appointments/{id}/images/{imageId}`
- Delete image (removes from S3 and database)
- Authorization: Uploader or admin
- Returns: 200 on success

**GET** `/services/{id}/images`
- Get portfolio images for a service
- Aggregates before/after from all completed appointments
- Public endpoint (visible to clients browsing services)

### AWS S3 Integration

**Bucket:** `beautiful-hair-images`
**Key Format:** `appointment-images/{appointmentId}/{type}_{uuid}.{ext}`

Example: `appointment-images/123/after_a1b2c3d4-e5f6.jpg`

### Frontend Components

**ServiceImagesPage.jsx**
- Upload form for before/after pairs
- Side-by-side preview
- Gallery view with filtering
- Delete functionality

**AppointmentDetailsPage** (enhancement)
- Show images for completed appointments
- Allow clients to upload their own photos

### AWS Credentials

Ensure EC2 instance has IAM role with S3 access:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::beautiful-hair-images/*"
    }
  ]
}
```

### Migration Script

```python
from app import create_app, db
from app.models import AppointmentImage

app = create_app()

with app.app_context():
    # Create the table
    db.create_all()
    print("✓ appointment_images table created successfully")
```

### Verification

After running migration, verify:

```python
from app.models import AppointmentImage
from app import create_app

app = create_app()
with app.app_context():
    # Test table exists
    image = AppointmentImage.query.first()
    print(f"✓ Table exists: {image is None or image.image_id}")
```

### Rollback

If needed to remove the table:

```python
from app import create_app, db
app = create_app()

with app.app_context():
    db.session.execute("DROP TABLE IF EXISTS appointment_images")
    db.session.commit()
    print("✓ Table removed")
```

### Related Features

- UC 2.17: View Before/After Service Images (Client)
- UC 1.8: Manage Service Portfolio (Vendor)
- UC 3.0: System Statistics (Analytics of popular transformations)
