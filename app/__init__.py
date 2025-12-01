from flask import Flask
from flask_cors import CORS
from .extensions import db
from .routes import register_routes

def create_app(config_object=None):
    app = Flask(__name__, instance_relative_config=True)

    if config_object:
        app.config.from_object(config_object)
    else:
        app.config.from_envvar("APP_SETTINGS", silent=True)

    db.init_app(app)

    # Allow frontend to talk to backend
    CORS(app,
         origins=["*"],   # Later you can restrict to your S3 domain
         supports_credentials=True,
         allow_headers=["Content-Type"],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    )

    register_routes(app)

    return app
