"""Application factory for the CS-490 Team 7 backend."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS
from flasgger import Swagger  

from .extensions import db
from .routes import bp as api_bp
from .routes_extended import bp_ext as api_ext_bp

# Load environment variables from a local .env file if present.
load_dotenv()


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure a Flask application instance."""
    app = Flask(__name__, instance_relative_config=False)

    # Ensure the instance directory exists so SQLite can create a file there when used as the fallback DB.
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    default_db_path = Path(app.instance_path) / "app.db"
    default_db_uri = f"sqlite:///{default_db_path}"

    # Default configuration values; override via `test_config` or environment variables.
    app.config.from_mapping(
        SECRET_KEY="dev",
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", default_db_uri),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config is not None:
        app.config.update(test_config)

    # Allow the React dev server to call our API without CORS issues during development.
    # Accept both localhost and 127.0.0.1 on dev ports, including 5001 for this backend
    CORS(app, resources={r"/*": {
        "origins": [
            "http://localhost:5173",
            "http://localhost:5174",
            "http://localhost:5175",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5174",
            "http://127.0.0.1:5175",
            "http://localhost:4173",

            # PRODUCTION FRONTEND (S3 URL)
            "http://beautifulhair.s3-website.us-east-2.amazonaws.com",

            # PRODUCTION BACKEND (EC2 public IP)
            "http://3.129.138.4",
     
        ],
        "supports_credentials": True
    }}, allow_headers=["Content-Type", "Authorization"], methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

    # --- CORRECTED CONFIG ---
    app.config["SWAGGER"] = {
        "title": "SalonHub API",
        "uiversion": 3,
        "version": "1.0.0",
        "description": "API documentation for the CS-490 Team 7 backend.",
        
        # REQUIRED FOR THE "AUTHORIZE" BUTTON
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
            }
        }
    }
    Swagger(app)
    # ------------------------------------

    db.init_app(app)

    # Import models so they are registered with SQLAlchemy metadata.
    from . import models  # noqa: F401

    app.register_blueprint(api_bp)
    app.register_blueprint(api_ext_bp)

    return app