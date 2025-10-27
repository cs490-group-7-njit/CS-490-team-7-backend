"""pytest configuration for path management."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is available on sys.path so tests can import the app package.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
