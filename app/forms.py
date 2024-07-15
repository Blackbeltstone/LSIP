from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, FileField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Optional, Length, EqualTo, ValidationError
from flask_wtf.file import FileAllowed
import logging

# Initialize logging
logger = logging.getLogger(__name__)

class SubmissionForm(FlaskForm):
    """Form for submitting plumbing installation details."""
    plumbing_install_date = SelectField('Plumbing install date', choices=[
        ('', 'Select Date Range'),
        ('Unknown', 'Unknown'),
        ('Before 1989', 'Before 1989'),
        ('Between 1989 and 2014', 'Between 1989 and 2014'),
        ('After 2014', 'After 2014')
    ], validators=[Optional()])

    water_softener_usage = SelectField('Water softener usage', choices=[
        ('', 'Select Usage'),
        ('Yes', 'Yes'),
        ('No', 'No'),
        ('Unknown', 'Unknown')
    ], validators=[Optional()])

    primary_plumbing_type = SelectField('Primary plumbing type', choices=[
        ('', 'Primary Pipe Type'),
        ('Lead', 'Lead'),
        ('Copper', 'Copper'),
        ('Copper with Lead Solder', 'Copper with Lead Solder'),
        ('Galvanized Steel', 'Galvanized Steel'),
        ('PVC (Polyvinyl Chloride)', 'PVC (Polyvinyl Chloride)'),
        ('HDPE (High-Density Polyethylene)', 'HDPE (High-Density Polyethylene)'),
        ('PEX (Cross-Linked Polyethylene)', 'PEX (Cross-Linked Polyethylene)'),
        ('Other Non Lead', 'Other Non Lead'),
        ('Unable to Identify', 'Unable to Identify')
    ], default='', validators=[DataRequired(message="Please select a primary plumbing type")])

    primary_plumbing_photo = FileField('Primary plumbing photo', validators=[DataRequired(), FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    secondary_plumbing_type = SelectField('Secondary plumbing type (optional)', choices=[
        ('', 'Secondary Pipe Type'),
        ('Lead', 'Lead'),
        ('Copper', 'Copper'),
        ('Copper with Lead Solder', 'Copper with Lead Solder'),
        ('Galvanized Steel', 'Galvanized Steel'),
        ('PVC (Polyvinyl Chloride)', 'PVC (Polyvinyl Chloride)'),
        ('HDPE (High-Density Polyethylene)', 'HDPE (High-Density Polyethylene)'),
        ('PEX (Cross-Linked Polyethylene)', 'PEX (Cross-Linked Polyethylene)'),
        ('Other Non Lead', 'Other Non Lead')
    ], validators=[Optional()])

    secondary_plumbing_photo = FileField('Secondary plumbing photo (optional)', validators=[Optional(), FileAllowed(['jpg', 'png', 'jpeg'], 'Images only!')])
    comments = TextAreaField('Comments', validators=[Optional()])  # Added comments field
    submit = SubmitField('Submit')

class UploadForm(FlaskForm):
    """Form for uploading city data via an Excel file."""
    city_name = StringField('City Name', validators=[DataRequired()])
    excel_file = FileField('Excel File', validators=[DataRequired(), FileAllowed(['xlsx', 'xls'], 'Excel files only!')])
    submit = SubmitField('Upload')

    def validate_city_name(self, field):
        """Custom validator for city name to ensure no duplicate city names."""
        from app.models import City
        if City.query.filter_by(name=field.data).first():
            logger.warning(f"City name '{field.data}' already exists.")
            raise ValidationError('City name already exists. Please choose a different name.')

class LoginForm(FlaskForm):
    """Form for admin login."""
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AdminRegistrationForm(FlaskForm):
    """Form for registering a new admin."""
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, field):
        """Custom validator for username to ensure no duplicate usernames."""
        from app.models import Admin
        if Admin.query.filter_by(username=field.data).first():
            logger.warning(f"Username '{field.data}' already exists.")
            raise ValidationError('Username already exists. Please choose a different username.')
