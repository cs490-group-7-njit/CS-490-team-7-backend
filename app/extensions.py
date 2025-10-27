"""Shared Flask extensions for the application."""
from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy

# SQLAlchemy database instance shared across the app.
db = SQLAlchemy()
