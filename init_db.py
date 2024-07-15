from app import create_app, db
from app.models import Admin
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app instance
app = create_app()

with app.app_context():
    try:
        # Create all database tables
        db.create_all()
        logger.info("Database tables created")

        # Create initial admin user
        admin_username = 'Stone'
        admin_password = 'Simpson'

        if not Admin.query.filter_by(username=admin_username).first():
            admin = Admin(username=admin_username)
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            logger.info(f'Admin user created with username "{admin_username}" and password "{admin_password}".')
        else:
            logger.info(f'Admin user "{admin_username}" already exists.')

    except Exception as e:
        logger.error(f"Error initializing the database: {e}")
        raise
