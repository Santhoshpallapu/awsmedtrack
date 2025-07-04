# Healthcare App

A Flask-based healthcare application that allows patients to book appointments with doctors and track their medical history.

## Prerequisites

- Python 3.8 or higher
- AWS Account (for DynamoDB and SNS)
- Gmail Account (for email notifications)

## Setup Instructions

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the project root with the following variables:
```
SECRET_KEY=your_secret_key_here
AWS_REGION_NAME=ap-south-1

# DynamoDB Table Names
USERS_TABLE_NAME=UsersTable
APPOINTMENTS_TABLE_NAME=AppointmentsTable

# Email Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=your_email@gmail.com
SENDER_PASSWORD=your_app_specific_password
ENABLE_EMAIL=True

# SNS Configuration
SNS_TOPIC_ARN=your_sns_topic_arn
ENABLE_SNS=True

# Flask Configuration
FLASK_ENV=development
PORT=5000
```

4. Create the required DynamoDB tables:
- UsersTable (with email as primary key)
- AppointmentsTable (with appointment_id as primary key)

5. Run the application:
```bash
python app.py
```

## Features

- User registration and authentication
- Patient appointment booking
- Doctor dashboard for managing appointments
- Email notifications for appointments
- SMS notifications via AWS SNS
- Profile management for both doctors and patients

## Project Structure

- `app.py`: Main Flask application
- `templates/`: HTML templates
- `static/`: CSS, JavaScript, and other static files
- `requirements.txt`: Python dependencies
- `.env`: Environment variables (DO NOT commit to version control)

## Security Notes

- Never commit your `.env` file to version control
- Use app-specific passwords for email accounts
- Keep AWS credentials secure
- Use HTTPS in production environment
