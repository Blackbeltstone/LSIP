import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default_secret_key')
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///' + os.path.join(os.getcwd(), 'instance', 'site.db'))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', os.path.join('app', 'static', 'uploads'))
    QR_FOLDER = os.environ.get('QR_FOLDER', os.path.join('app', 'static', 'qr_codes'))
    ALLOWED_EXTENSIONS = set(os.environ.get('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,gif').split(','))

class ProductionConfig(Config):
    DEBUG = False

class DevelopmentConfig(Config):
    DEBUG = True
