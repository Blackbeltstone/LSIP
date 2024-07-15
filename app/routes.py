from flask import Blueprint, current_app, jsonify, request, send_file, send_from_directory, make_response, redirect, url_for, flash, render_template
from werkzeug.utils import secure_filename
import pandas as pd
from app import db
from app.models import City, Address, Admin, Submission
from app.forms import SubmissionForm, UploadForm, LoginForm, AdminRegistrationForm
from flask_login import login_user, current_user, logout_user, login_required
import qrcode
import os
import io
from fpdf import FPDF
import xlsxwriter
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask_wtf.csrf import CSRFProtect, generate_csrf

bp = Blueprint('main', __name__)
csrf = CSRFProtect()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
        logger.info(f"Created directory: {directory}")

def save_file(form_file, folder):
    filename = secure_filename(form_file.filename)
    file_path = os.path.join(folder, filename)
    form_file.save(file_path)
    logger.info(f"Saved file: {file_path}")
    return file_path

def generate_qr_code(data, filename):
    qr_codes_dir = 'app/static/qr_codes'
    ensure_directory_exists(qr_codes_dir)
    img = qrcode.make(data)
    img_path = os.path.join(qr_codes_dir, filename)
    img.save(img_path)
    logger.info(f"Generated QR code: {img_path}")
    return img_path

def import_data(file_path, city_name):
    df = pd.read_excel(file_path, engine='openpyxl')
    df.fillna("Unknown", inplace=True)

    city = City.query.filter_by(name=city_name).first()
    if not city:
        city = City(name=city_name)
        db.session.add(city)
        db.session.commit()
        logger.info(f"Created new city: {city_name}")
    
    for index, row in df.iterrows():
        address = row['Address']
        owner_name = row['Owner']
        
        unique_token = os.urandom(8).hex()
        
        # Replace '192.168.1.10' with your actual local IP address
        local_ip = '192.168.0.65'
        port = '5000'
        url = f'http://{local_ip}:{port}/property/{unique_token}'

        qr_filename = f'{unique_token}.png'
        qr_code_path = generate_qr_code(url, qr_filename)

        new_address = Address(
            city_id=city.id, 
            address=address, 
            owner_name=owner_name, 
            unique_token=unique_token, 
            qr_code_path=qr_code_path
        )
        db.session.add(new_address)
    
    db.session.commit()
    logger.info(f"Imported data for city: {city_name}")


@bp.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.admin'))
    form = LoginForm()
    if form.validate_on_submit():
        user = Admin.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            logger.info(f"User logged in: {user.username}")
            return redirect(url_for('main.admin'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
            logger.warning("Login attempt failed")
    return render_template('login.html', form=form)

@bp.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
        return jsonify({"filename": filename}), 200
    return jsonify({"error": "File not allowed"}), 400

@bp.route('/api/login', methods=['POST'])
@csrf.exempt
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = Admin.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        logger.info(f"API User logged in: {user.username}")
        return jsonify({"message": "Login successful"}), 200
    else:
        logger.warning("API login attempt failed")
        return jsonify({"message": "Login unsuccessful"}), 401

@bp.route('/api/get_csrf_token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    response = jsonify({'csrf_token': token})
    response.set_cookie('csrf_token', token)
    return response

@bp.route('/api/cities', methods=['GET'])
def get_cities():
    cities = City.query.all()
    city_names = [city.name for city in cities]
    return jsonify(city_names)

@bp.route('/api/addresses', methods=['GET'])
def get_addresses():
    city_name = request.args.get('city')
    city = City.query.filter_by(name=city_name).first()
    if city:
        addresses = Address.query.filter_by(city_id=city.id).all()
        address_list = [address.address for address in addresses]
        return jsonify(address_list)
    else:
        return jsonify([]), 404

@bp.route('/api/submit_property', methods=['POST'])
@csrf.exempt
def submit_property():
    data = request.form
    primary_plumbing_photo = None
    secondary_plumbing_photo = None

    # Retrieve the address from the database using the provided address_id
    address_id = data['address_id']
    address = Address.query.get(address_id)

    if not address:
        return jsonify({"error": "Address not found"}), 404

    # Create directory for city if it doesn't exist
    city_name = address.city.name.replace(" ", "")
    address_str = address.address.replace(" ", "").replace(".", "").replace(",", "").replace("/", "")

    city_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], city_name)
    if not os.path.exists(city_folder):
        os.makedirs(city_folder)

    # Save primary plumbing photo
    if 'primary_plumbing_photo' in request.files:
        file = request.files['primary_plumbing_photo']
        if file and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f"{address_str}_primary.{ext}")
            file_path = os.path.join(city_folder, filename)
            file.save(file_path)
            primary_plumbing_photo = os.path.join(city_name, filename)

    # Save secondary plumbing photo
    if 'secondary_plumbing_photo' in request.files:
        file = request.files['secondary_plumbing_photo']
        if file and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = secure_filename(f"{address_str}_secondary.{ext}")
            file_path = os.path.join(city_folder, filename)
            file.save(file_path)
            secondary_plumbing_photo = os.path.join(city_name, filename)

    # Create a new submission
    new_submission = Submission(
        address_id=address_id,
        plumbing_install_date=data['plumbing_install_date'],
        water_softener_usage=data['water_softener_usage'],
        primary_plumbing_type=data['primary_plumbing_type'],
        primary_plumbing_photo=primary_plumbing_photo,
        secondary_plumbing_type=data['secondary_plumbing_type'],
        secondary_plumbing_photo=secondary_plumbing_photo,
        comments=data.get('comments', '')
    )

    db.session.add(new_submission)
    db.session.commit()
    return jsonify({"message": "Submission successful"}), 200




@bp.route("/logout")
def logout():
    logout_user()
    logger.info("User logged out")
    return redirect(url_for('main.login'))

@bp.route("/")
@bp.route("/home")
def home():
    return render_template('home.html')

@bp.route("/admin", methods=['GET', 'POST'])
@login_required
def admin():
    form = UploadForm()
    if form.validate_on_submit():
        city_name = form.city_name.data
        file_path = save_file(form.excel_file.data, current_app.config['UPLOAD_FOLDER'])
        try:
            import_data(file_path, city_name)
            flash('File successfully uploaded and data imported', 'success')
            logger.info(f"File uploaded and data imported for city: {city_name}")
        except Exception as e:
            flash(f'Error importing data: {e}', 'danger')
            logger.error(f"Error importing data: {e}")
        return redirect(url_for('main.admin'))
    
    cities = City.query.all()
    return render_template('admin.html', form=form, cities=cities)

@bp.route("/city/<string:city_name>")
def city_properties(city_name):
    city = City.query.filter_by(name=city_name).first_or_404()
    properties = Address.query.filter_by(city_id=city.id).all()
    return render_template('city.html', city=city, properties=properties)

@bp.route("/property/<string:unique_token>", methods=['GET', 'POST'])
def property(unique_token):
    address = Address.query.filter_by(unique_token=unique_token).first_or_404()
    form = SubmissionForm()
    
    if form.validate_on_submit():
        primary_plumbing_photo = None
        secondary_plumbing_photo = None

        city_name = address.city.name.replace(" ", "")
        address_str = address.address.replace(" ", "").replace(".", "").replace(",", "").replace("/", "")

        city_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], city_name)
        if not os.path.exists(city_folder):
            os.makedirs(city_folder)

        if form.primary_plumbing_photo.data:
            file = form.primary_plumbing_photo.data
            if file and allowed_file(file.filename):
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(f"{address_str}_primary.{ext}")
                file_path = os.path.join(city_folder, filename)
                file.save(file_path)
                primary_plumbing_photo = os.path.join(city_name, filename)

        if form.secondary_plumbing_photo.data:
            file = form.secondary_plumbing_photo.data
            if file and allowed_file(file.filename):
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(f"{address_str}_secondary.{ext}")
                file_path = os.path.join(city_folder, filename)
                file.save(file_path)
                secondary_plumbing_photo = os.path.join(city_name, filename)

        submission = Submission(
            address_id=address.id,
            plumbing_install_date=form.plumbing_install_date.data,
            water_softener_usage=form.water_softener_usage.data,
            primary_plumbing_type=form.primary_plumbing_type.data,
            primary_plumbing_photo=primary_plumbing_photo,
            secondary_plumbing_type=form.secondary_plumbing_type.data,
            secondary_plumbing_photo=secondary_plumbing_photo,
            comments=form.comments.data
        )

        db.session.add(submission)
        db.session.commit()
        flash('Your submission has been recorded!', 'success')
        logger.info(f"New submission recorded for address: {address.address}")
        return redirect(url_for('main.thank_you'))
    else:
        logger.debug(f"Form validation failed: {form.errors}")
    
    return render_template('property.html', form=form, address=address)

@bp.route("/thank_you")
def thank_you():
    return render_template('thank_you.html')

def save_picture(form_picture):
    random_hex = os.urandom(8).hex()
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.config['UPLOAD_FOLDER'], picture_fn)
    form_picture.save(picture_path)
    logger.info(f"Saved picture: {picture_path}")
    return picture_fn

@bp.route("/qr_codes/<filename>")
def qr_code(filename):
    return send_from_directory('static/qr_codes', filename)

@bp.route("/city/<string:city_name>/submissions")
@login_required
def city_submissions(city_name):
    city = City.query.filter_by(name=city_name).first_or_404()
    sort_by = request.args.get('sort_by', 'plumbing_install_date')
    sort_order = request.args.get('sort_order', 'asc')
    filters = request.args.getlist('filter')

    query = Submission.query.join(Address).filter(Address.city_id == city.id)

    if sort_order == 'desc':
        query = query.order_by(db.desc(getattr(Submission, sort_by)))
    else:
        query = query.order_by(getattr(Submission, sort_by))

    submissions = query.all()

    return render_template('city_submissions.html', city=city, submissions=submissions, sort_by=sort_by, sort_order=sort_order, filters=filters)

@bp.route("/export_city_data/<string:city_name>")
@login_required
def export_city_data(city_name):
    city = City.query.filter_by(name=city_name).first_or_404()
    addresses = Address.query.filter_by(city_id=city.id).all()
    
    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output, {'in_memory': True})
    worksheet = workbook.add_worksheet()

    worksheet.write(0, 0, 'Address')
    worksheet.write(0, 1, 'Owner Name')
    worksheet.write(0, 2, 'Plumbing Install Date')
    worksheet.write(0, 3, 'Water Softener Usage')
    worksheet.write(0, 4, 'Primary Plumbing Type')
    worksheet.write(0, 5, 'Primary Plumbing Photo')
    worksheet.write(0, 6, 'Secondary Plumbing Type')
    worksheet.write(0, 7, 'Secondary Plumbing Photo')

    row = 1
    for address in addresses:
        submissions = Submission.query.filter_by(address_id=address.id).all()
        for submission in submissions:
            worksheet.write(row, 0, address.address)
            worksheet.write(row, 1, address.owner_name)
            worksheet.write(row, 2, submission.plumbing_install_date)
            worksheet.write(row, 3, submission.water_softener_usage)
            worksheet.write(row, 4, submission.primary_plumbing_type)
            worksheet.write(row, 5, submission.primary_plumbing_photo)
            worksheet.write(row, 6, submission.secondary_plumbing_type)
            worksheet.write(row, 7, submission.secondary_plumbing_photo)
            row += 1

    workbook.close()
    output.seek(0)
    logger.info(f"Exported city data for {city_name}")

    return send_file(output, download_name=f'{city_name}_data.xlsx', as_attachment=True)

@bp.route("/export_qr_codes/<string:city_name>")
@login_required
def export_qr_codes(city_name):
    city = City.query.filter_by(name=city_name).first_or_404()
    addresses = Address.query.filter_by(city_id=city.id).all()
    
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    for address in addresses:
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Address: {address.address}", ln=True, align='L')
        pdf.cell(200, 10, txt=f"Owner Name: {address.owner_name}", ln=True, align='L')
        pdf.cell(200, 10, txt=f"QR Code:", ln=True, align='L')
        pdf.image(f'app/static/qr_codes/{address.unique_token}.png', x=10, y=50, w=100)
        
    response = make_response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={city_name}_qr_codes.pdf'
    logger.info(f"Exported QR codes for {city_name}")
    return response

@bp.route("/register_admin", methods=['GET', 'POST'])
@login_required
def register_admin():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.home'))

    form = AdminRegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        admin = Admin(username=form.username.data, password=hashed_password)
        db.session.add(admin)
        db.session.commit()
        flash('New admin registered successfully!', 'success')
        logger.info(f"New admin registered: {admin.username}")
        return redirect(url_for('main.admin'))
    return render_template('register_admin.html', form=form)

def delete_file(file_path):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Deleted file: {file_path}")
        else:
            logger.warning(f"File not found: {file_path}")
    except Exception as e:
        logger.error(f"Error deleting file {file_path}: {e}")

@bp.route("/delete_city", methods=['GET'])
@login_required
def delete_city():
    city_name = request.args.get('city_name')
    try:
        city = City.query.filter_by(name=city_name).first_or_404()
        addresses = Address.query.filter_by(city_id=city.id).all()
        for address in addresses:
            submissions = Submission.query.filter_by(address_id=address.id).all()
            for submission in submissions:
                if submission.primary_plumbing_photo:
                    delete_file(os.path.join(current_app.config['UPLOAD_FOLDER'], submission.primary_plumbing_photo))
                if submission.secondary_plumbing_photo:
                    delete_file(os.path.join(current_app.config['UPLOAD_FOLDER'], submission.secondary_plumbing_photo))
                db.session.delete(submission)
            delete_file(os.path.join('app/static/qr_codes', os.path.basename(address.qr_code_path)))
            db.session.delete(address)
        db.session.delete(city)
        db.session.commit()
        flash(f'City "{city_name}" and all associated data have been deleted.', 'success')
        logger.info(f'City "{city_name}" deleted.')
    except Exception as e:
        flash(f'Error deleting city: {e}', 'danger')
        logger.error(f"Error deleting city: {e}")
    return redirect(url_for('main.admin'))

