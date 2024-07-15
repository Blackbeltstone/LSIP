import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'main.login'
csrf = CSRFProtect()

def create_app():
    """Factory function to create and configure the Flask application."""
    app = Flask(__name__, instance_relative_config=True)
    
    # Load configuration
    if os.getenv('FLASK_ENV') == 'production':
        app.config.from_object('config.ProductionConfig')
    else:
        app.config.from_object('config.DevelopmentConfig')
    
    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        logger.warning("Instance folder already exists or cannot be created")

    # Upload folder
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    logger.info("Extensions initialized")

    # Register blueprints
    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    logger.info("Blueprints registered")

    return app

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    from app.models import Admin
    return Admin.query.get(int(user_id))
