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
4. Start the development server:
   ```bash
   python run.py
   ```
   By default the API listens on `http://127.0.0.1:5000`. Set `PORT` or `FLASK_DEBUG=1` as needed.

## API Surface
- `GET /health` – returns `{ "status": "ok" }` for uptime checks. Expand this module with additional routes as features land.

## Project Structure
```
app/            # Flask application package (factory + blueprints)
run.py          # Local development entry point
requirements.txt# Python dependencies (Flask, CORS, pytest)
tests/          # Pytest-based unit tests
```

## Next Steps
- Connect to the MySQL schema defined in `../devops/` once database access is available.
- Add authentication, business logic, and additional routes under `app/` using blueprints.
- Configure linting/formatting (e.g., Ruff, Black) and CI once team standards are decided.
