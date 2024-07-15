from flask_login import UserMixin
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import logging

# Initialize logging
logger = logging.getLogger(__name__)

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)
        logger.info("Password set for admin user: %s", self.username)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class City(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f"<City {self.name}>"

class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    city_id = db.Column(db.Integer, db.ForeignKey('city.id'), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    owner_name = db.Column(db.String(100), nullable=False)
    unique_token = db.Column(db.String(16), unique=True, nullable=False, default=lambda: uuid.uuid4().hex[:16])
    qr_code_path = db.Column(db.String(200), nullable=False)
    city = db.relationship('City', backref=db.backref('addresses', lazy=True))

    def __repr__(self):
        return f"<Address {self.address}>"

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address_id = db.Column(db.Integer, db.ForeignKey('address.id'), nullable=False)
    plumbing_install_date = db.Column(db.String(100), nullable=True)
    water_softener_usage = db.Column(db.String(100), nullable=True)
    primary_plumbing_type = db.Column(db.String(100), nullable=False)
    primary_plumbing_photo = db.Column(db.String(100), nullable=False)
    secondary_plumbing_type = db.Column(db.String(100), nullable=True)
    secondary_plumbing_photo = db.Column(db.String(100), nullable=True)
    comments = db.Column(db.Text, nullable=True)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    address = db.relationship('Address', backref=db.backref('submissions', lazy=True))

    def __repr__(self):
        return f"<Submission {self.id} for address {self.address_id}>"
