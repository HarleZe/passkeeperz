from flask import Flask
from .models import init_db

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        init_db()

    return app

