from __future__ import annotations
import os
from app import create_app

def main() -> None:
    flask_app = create_app()

    # show what routes are actually mounted
    print("\n=== URL MAP ===")
    for r in sorted(flask_app.url_map.iter_rules(), key=lambda x: x.rule):
        print(r)
    print("===============\n")

    debug_enabled = os.environ.get("FLASK_DEBUG", "0") in {"1", "true", "True"}
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug_enabled)

if __name__ == "__main__":
    main()
