"""CLI entry point for running the Flask development server."""
from __future__ import annotations

import os

from app import create_app


def main() -> None:
    """Run the Flask development server."""
    flask_app = create_app()
    debug_enabled = os.environ.get("FLASK_DEBUG", "0") in {"1", "true", "True"}
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug_enabled)


if __name__ == "__main__":
    main()
