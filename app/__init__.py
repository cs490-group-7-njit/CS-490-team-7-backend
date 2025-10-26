"""Application factory for the CS-490 Team 7 backend."""
from __future__ import annotations

from flask import Flask
from flask_cors import CORS

from .routes import bp as api_bp


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure a Flask application instance."""
    app = Flask(__name__, instance_relative_config=False)

    # Default configuration values; override via `test_config` or env variables.
    app.config.from_mapping(SECRET_KEY="dev")

    if test_config is not None:
        app.config.update(test_config)

    # Allow the React dev server to call our API without CORS issues during development.
    CORS(app, resources={r"/*": {"origins": "*"}})

    app.register_blueprint(api_bp)

    return app
