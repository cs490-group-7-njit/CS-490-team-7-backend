# CS-490 Team 7 Backend

Flask-based REST API for the SalonHub project. 

## Getting Started
1. Create a virtual environment (optional but recommended):
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the automated tests:
   ```bash
   pytest
   ```
4. Configure the database connection (optional for SQLite fallback):
   - Copy `.env.example` to `.env`; the app loads this automatically via `python-dotenv`.
   - Example MySQL URI (root user without password): `mysql+pymysql://root@localhost:3306/salonhub`
5. Start the development server:
   ```bash
   python run.py
   ```
   By default the API listens on `http://127.0.0.1:5000`. Set `PORT` or `FLASK_DEBUG=1` as needed.

## API Surface
- `GET /health` – returns `{ "status": "ok" }` for uptime checks.
- `GET /db-health` – executes `SELECT 1` through SQLAlchemy to verify the database connection.
- `GET /salons` – lists up to twelve published salons with their vendor details.

## Database Integration
- SQLAlchemy models live in `app/models.py` and mirror the MySQL schema defined under `../devops/SCHEMA.sql`.
- `DATABASE_URL` should point to a provisioned MySQL instance (e.g., `mysql+pymysql://root@localhost:3306/salonhub`).
- For automated tests we fall back to an in-memory SQLite database; tables are created/dropped per test session.

## Project Structure
```
app/
  __init__.py    # Application factory + config
  extensions.py  # Shared Flask extensions (SQLAlchemy)
  models.py      # SQLAlchemy models (users, salons, etc.)
  routes.py      # HTTP blueprints
run.py           # Local development entry point
requirements.txt # Python dependencies (Flask, CORS, SQLAlchemy, pytest)
tests/           # Pytest-based unit tests
```

## Next Steps
- Expand the model layer to cover additional tables (appointments, services, products).
- Add authentication, business logic, and CRUD routes under `app/` using modular blueprints.
- Configure linting/formatting (e.g., Ruff, Black) and CI once team standards are decided.
