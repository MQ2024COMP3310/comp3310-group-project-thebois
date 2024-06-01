from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from pathlib import Path

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()


def create_app():
    app = Flask(__name__)

    # hide sensitive keys and URI in environment variables
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DB_URI")
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "jwt-secret")

    CWD = Path(os.path.dirname(__file__))
    app.config["UPLOAD_DIR"] = CWD / "uploads"

    db.init_app(app)

    # JWT setup
    jwt = JWTManager(app)

    # Rate Limiter
    limiter = Limiter(
        get_remote_address, app=app, default_limits=["200 per day", "50 per hour"]
    )

    # blueprint for auth parts of app
    from .auth import auth as auth_blueprint

    app.register_blueprint(auth_blueprint, url_prefix="/auth")

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint

    app.register_blueprint(main_blueprint)

    return app
