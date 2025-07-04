from flask import Flask, request, session, redirect, url_for, render_template, flash
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os
import uuid
from dotenv import load_dotenv
from boto3.dynamodb.conditions import Attr
from flask import jsonify

# Load environment variables
load_dotenv()

# Flask App Initialization
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'temporary_key_for_development')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email, role):
        self.id = id
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('users')
    response = table.get_item(Key={'id': user_id})
    if 'Item' in response:
        return User(
            id=response['Item']['id'],
            email=response['Item']['email'],
            role=response['Item']['role']
        )
    return None

# Register is_logged_in as a template global
@app.context_processor
def inject_is_logged_in():
    return dict(is_logged_in=is_logged_in)

# App Configuration
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')

# DynamoDB Tables
MEDICATIONS_TABLE_NAME = os.environ.get('MEDICATIONS_TABLE_NAME', 'MedicationsTable')
REMINDERS_TABLE_NAME = os.environ.get('REMINDERS_TABLE_NAME', 'RemindersTable')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'False').lower() == 'true'

# Table Names from .env
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'UsersTable')
APPOINTMENTS_TABLE_NAME = os.environ.get('APPOINTMENTS_TABLE_NAME', 'AppointmentsTable')

# Database helper functions
class Database:
    def __init__(self):
        self.users = {}
        self.appointments = {}
        self.next_user_id = 1
        self.next_appointment_id = 1

    def get_user(self, email):
        return self.users.get(email)

    def get_appointments(self, email, role):
        if role == 'doctor':
            return [appointment for appointment in self.appointments.values()
                    if appointment.get('doctor_email') == email]
        elif role == 'patient':
            return [appointment for appointment in self.appointments.values()
                    if appointment.get('patient_email') == email]
        return []

    def add_user(self, user_data):
        user_data['id'] = self.next_user_id
        self.users[user_data['email']] = user_data
        self.next_user_id += 1
        return user_data

    def add_appointment(self, appointment_data):
        appointment_data['appointment_id'] = str(self.next_appointment_id)
        self.appointments[str(self.next_appointment_id)] = appointment_data
        self.next_appointment_id += 1
        return appointment_data

    def get_user_medications(self, user_id):
        response = medications_table.query(
            KeyConditionExpression='user_id = :user_id',
            ExpressionAttributeValues={
                ':user_id': user_id
            }
        )
        return response.get('Items', [])

    def add_medication(self, user_id, medication_data):
        medication_id = str(uuid.uuid4())
        medication = {
            'id': medication_id,
            'user_id': user_id,
            'name': medication_data['name'],
            'dosage': medication_data['dosage'],
            'frequency': medication_data['frequency'],
            'start_date': medication_data['start_date'],
            'end_date': medication_data.get('end_date'),
            'created_at': datetime.now().isoformat()
        }
        medications_table.put_item(Item=medication)
        return medication

    def update_medication(self, medication_id, user_id, medication_data):
        medications_table.update_item(
            Key={'id': medication_id, 'user_id': user_id},
            UpdateExpression='SET #name = :name, dosage = :dosage, frequency = :frequency, end_date = :end_date',
            ExpressionAttributeNames={'#name': 'name'},
            ExpressionAttributeValues={
                ':name': medication_data['name'],
                ':dosage': medication_data['dosage'],
                ':frequency': medication_data['frequency'],
                ':end_date': medication_data.get('end_date')
            }
        )

    def delete_medication(self, medication_id, user_id):
        medications_table.delete_item(
            Key={'id': medication_id, 'user_id': user_id}
        )

    def create_reminder(self, user_id, medication_id, scheduled_time):
        reminder_id = str(uuid.uuid4())
        reminder = {
            'id': reminder_id,
            'user_id': user_id,
            'medication_id': medication_id,
            'scheduled_time': scheduled_time,
            'status': 'scheduled',
            'created_at': datetime.now().isoformat()
        }
        reminders_table.put_item(Item=reminder)
        return reminder

db = Database()

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Helper Functions
# -------------------------------
def is_logged_in():
    return 'email' in session and 'role' in session

def get_user_role(email):
    try:
        response = user_table.get_item(Key={'email': email})
        return response['Item']['role'] if 'Item' in response else None
    except Exception as e:
        logger.error(f"Error fetching user role for {email}: {e}")
        return None

def send_email(to_email, subject, body):
    if not ENABLE_EMAIL:
        logger.info(f"[Email Skipped] Subject: {subject} to {to_email}")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        server.quit()

        logger.info(f"Email sent to {to_email}")
    except Exception as e:
        logger.error(f"Email sending failed: {e}")

def publish_to_sns(message, subject="Salon Notification"):
    if not ENABLE_SNS:
        logger.info("[SNS Skipped] Message: {}".format(message))
        return
    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        logger.info(f"SNS published: {response['MessageId']}")
    except Exception as e:
        logger.error(f"SNS publish failed: {e}")

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        age = request.form['age']
        gender = request.form['gender']
        role = request.form['role']

        # Check if user already exists
        existing_user = db.get_user(email)
        if existing_user:
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        # Create new user
        user_data = {
            'email': email,
            'name': name,
            'password': generate_password_hash(password),
            'age': int(age),
            'gender': gender,
            'role': role,
            'created_at': datetime.utcnow().isoformat()
        }
        db.add_user(user_data)

        # Send welcome email
        send_email(email, 'Welcome to HealthCare App', 
            f"Dear {name},\n\nWelcome to our healthcare application!\n\nYour account has been successfully created.\n\nBest regards,\nHealthCare App Team")

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login User (Doctor/Patient)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        user = db.get_user(email)
        if user and check_password_hash(user['password'], password) and user['role'] == role:
            session['email'] = email
            session['role'] = role
            session['name'] = user.get('name', '')
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email, password, or role', 'danger')
    
    return render_template('login.html')

# Logout User
@app.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))

    email = session['email']
    role = session['role']

    try:
        if role == 'doctor':
            appointments = db.get_appointments(email, role)
            return render_template('doctor_dashboard.html', appointments=appointments)

        elif role == 'patient':
            appointments = db.get_appointments(email, role)
            # Get list of doctors for booking new appointments
            doctors = [user for user in db.users.values() if user.get('role') == 'doctor']
            return render_template('patient_dashboard.html', appointments=appointments, doctors=doctors)

        return render_template('book_appointment.html')

    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('An error occurred while loading your dashboard.', 'danger')
        return redirect(url_for('login'))

# Route for booking appointments
@app.route('/book_appointment', methods=['GET', 'POST'])
def book_appointment():
    if not is_logged_in():
        flash('Please log in to continue.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        doctor_email = request.form['doctor_email']
        doctor_name = request.form['doctor_name']
        appointment_date = request.form['appointment_date']
        symptoms = request.form['symptoms']
        patient_email = session['email']
        patient_name = session['name']

        # Create appointment item
        appointment_data = {
            'doctor_email': doctor_email,
            'doctor_name': doctor_name,
            'patient_email': patient_email,
            'patient_name': patient_name,
            'appointment_date': appointment_date,
            'symptoms': symptoms,
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat()
        }

        try:
            appointment = db.add_appointment(appointment_data)

            # Notify doctor via email or SNS
            notification_msg = (
                f"New appointment booked with Dr. {doctor_name} on {appointment_date}.\n"
                f"Patient: {patient_name}\nSymptoms: {symptoms}"
            )

            send_email(doctor_email, "New Appointment Notification", notification_msg)
            publish_to_sns(notification_msg, subject="New Appointment Booked")

            flash('Appointment booked successfully.', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            logger.error(f"Failed to book appointment: {e}")
            flash("An error occurred while booking the appointment. Please try again.", "danger")
            return redirect(url_for("book_appointment"))

    # Get list of doctors for selection
    doctors = [user for user in db.users.values() if user.get('role') == 'doctor']

    return render_template('book_appointment.html', doctors=doctors)

# Root Route
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/medication_tracker')
@login_required
def medication_tracker():
    user_id = session.get('user_id')
    medications = db.get_user_medications(user_id)
    return render_template('medication_tracker.html', medications=medications)

@app.route('/add_medication', methods=['POST'])
@login_required
def add_medication():
    try:
        user_id = session.get('user_id')
        medication_data = {
            'name': request.form['medication_name'],
            'dosage': request.form['dosage'],
            'frequency': int(request.form['frequency']),
            'start_date': request.form['start_date'],
            'end_date': request.form.get('end_date')
        }
        
        # Add medication to database
        medication = db.add_medication(user_id, medication_data)
        
        # Create reminders based on frequency
        start_date = datetime.fromisoformat(request.form['start_date'])
        end_date = datetime.fromisoformat(request.form.get('end_date')) if request.form.get('end_date') else None
        
        # Calculate daily reminder times (evenly distributed)
        frequency = int(request.form['frequency'])
        hours_per_dose = 24 / frequency
        current_time = start_date
        
        while current_time.date() <= (end_date.date() if end_date else datetime.max.date()):
            for i in range(frequency):
                reminder_time = current_time + timedelta(hours=i * hours_per_dose)
                db.create_reminder(user_id, medication['id'], reminder_time.isoformat())
            current_time += timedelta(days=1)
        
        flash('Medication added successfully!', 'success')
        return redirect(url_for('medication_tracker'))
    except Exception as e:
        flash(f'Error adding medication: {str(e)}', 'error')
        return redirect(url_for('medication_tracker'))

@app.route('/edit_medication/<medication_id>', methods=['POST'])
@login_required
def edit_medication(medication_id):
    try:
        user_id = session.get('user_id')
        medication_data = {
            'name': request.form['medication_name'],
            'dosage': request.form['dosage'],
            'frequency': int(request.form['frequency']),
            'start_date': request.form['start_date'],
            'end_date': request.form.get('end_date')
        }
        db.update_medication(medication_id, user_id, medication_data)
        flash('Medication updated successfully!', 'success')
        return redirect(url_for('medication_tracker'))
    except Exception as e:
        flash(f'Error updating medication: {str(e)}', 'error')
        return redirect(url_for('medication_tracker'))

@app.route('/delete_medication/<medication_id>', methods=['POST'])
@login_required
def delete_medication(medication_id):
    try:
        user_id = session.get('user_id')
        db.delete_medication(medication_id, user_id)
        flash('Medication deleted successfully!', 'success')
        return redirect(url_for('medication_tracker'))
    except Exception as e:
        flash(f'Error deleting medication: {str(e)}', 'error')
        return redirect(url_for('medication_tracker'))

# Route for viewing appointments
@app.route('/view_appointment/<appointment_id>')
def view_appointment(appointment_id):
    try:
        appointment = appointment_table.get_item(Key={'appointment_id': appointment_id}).get('Item')
        if not appointment:
            flash('Appointment not found.', 'danger')
            return redirect(url_for('dashboard'))

        if session['role'] == 'doctor' and appointment['doctor_email'] != session['email']:
            flash('You are not authorized to view this appointment.', 'danger')
            return redirect(url_for('dashboard'))
        elif session['role'] == 'patient' and appointment['patient_email'] != session['email']:
            flash('You are not authorized to view this appointment.', 'danger')
            return redirect(url_for('dashboard'))

        return render_template('view_appointment.html', appointment=appointment)

    except Exception as e:
        logger.error(f"Error retrieving appointment: {e}")
        flash("Error retrieving appointment.", 'danger')
        return redirect(url_for('dashboard'))

# Route for submitting diagnosis
@app.route('/submit_diagnosis/<appointment_id>', methods=['POST'])
def submit_diagnosis(appointment_id):
    """Submit diagnosis for an appointment"""
    try:
        # Validate appointment exists
        appointment = appointment_table.get_item(Key={'appointment_id': appointment_id}).get('Item')
        if not appointment:
            return jsonify({'error': 'Appointment not found'}), 404

        # Validate user is authorized
        if session['role'] != 'doctor' or appointment['doctor_email'] != session['email']:
            return jsonify({'error': 'Unauthorized'}), 403

        # Get diagnosis data
        diagnosis = request.form.get('diagnosis')
        treatment_plan = request.form.get('treatment_plan')
        
        if not diagnosis or not treatment_plan:
            return jsonify({'error': 'Diagnosis and treatment plan are required'}), 400

        # Update appointment
        appointment_table.update_item(
            Key={'appointment_id': appointment_id},
            UpdateExpression="SET diagnosis = :diag, treatment_plan = :tp, status = :status, updated_at = :dt",
            ExpressionAttributeValues={
                ':diag': diagnosis,
                ':tp': treatment_plan,
                ':status': 'completed',
                ':dt': datetime.utcnow().isoformat()
            }
        )

        # Send email notification
        if ENABLE_EMAIL:
            patient_email = appointment['patient_email']
            patient_name = appointment.get('patient_name', 'Patient')
            doctor_name = session.get('name', 'your doctor')

            patient_msg = (
                f"Dear {patient_name},\n\n"
                f"Your appointment with Dr. {doctor_name} has been completed.\n\n"
                f"Diagnosis: {diagnosis}\n\n"
                f"Treatment Plan: {treatment_plan}\n\n"
            )
            send_email(patient_email, "Appointment Completed - Diagnosis Available", patient_msg)

        flash("Diagnosis submitted successfully.", "success")
        return redirect(url_for("dashboard"))

    except Exception as e:
        logger.error(f"Submit diagnosis error: {e}")
        flash("An error occurred while submitting the diagnosis. Please try again.", "danger")
        return redirect(url_for("dashboard"))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    email = session['email']
    try:
        user = db.get_user(email)
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            # Update user profile
            name = request.form.get('name')
            age = request.form.get('age')
            gender = request.form.get('gender')

            # Update user data
            user['name'] = name
            user['age'] = int(age)
            user['gender'] = gender

            # Update specialization only for doctors
            if session['role'] == 'doctor' and 'specialization' in request.form:
                user['specialization'] = request.form['specialization']

            # Reflect name change in session
            session['name'] = name
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('profile'))

        return render_template('profile.html', user=user)

    except Exception as e:
        logger.error(f"Profile error: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# Health check endpoint for AWS load balancers
@app.route('/health')
def health():
    return {'status': 'healthy'}, 200

# Run the Flask app
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)