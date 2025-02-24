from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from datetime import datetime
import pandas as pd
import re
from models import db, User, Event, Match, Booking
from functools import wraps
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration using environment variables
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"postgresql://{os.getenv('DATABASE_USER')}:{os.getenv('DATABASE_PASSWORD')}@"
    f"{os.getenv('DATABASE_HOST')}/{os.getenv('DATABASE_NAME')}"
)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
mail = Mail(app)
migrate = Migrate(app, db)

# Token serializer for email verification
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Password strength checker
def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session or session['email'] not in ['admin@example.com', "spkibet@gmail.com"]:
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def process_csv(file):
    df = pd.read_csv(file)
    with db.session.no_autoflush:
        for _, row in df.iterrows():
            event = Event.query.filter_by(name=row['Event_x']).first()
            if not event:
                event = Event(name=row['Event_x'], date=datetime(2019, 5, 22))
                db.session.add(event)
                db.session.commit()

            user1 = User.query.filter_by(email=row['Email address_x']).first()
            if not user1:
                user1 = User(
                    email=row['Email address_x'],
                    password=generate_password_hash('unregistered_placeholder'),
                    verified=False
                )
                db.session.add(user1)
            
            user2 = User.query.filter_by(email=row['Email address_y']).first()
            if not user2:
                user2 = User(
                    email=row['Email address_y'],
                    password=generate_password_hash('unregistered_placeholder'),
                    verified=False
                )
                db.session.add(user2)
            
            db.session.commit()

            if not Match.query.filter_by(event_id=event.id, user1_id=user1.id, user2_id=user2.id).first():
                match = Match(
                    event_id=event.id,
                    user1_id=user1.id,
                    user2_id=user2.id,
                    user1_name=row['Your name_x'],
                    user2_name=row['Your name_y'],
                    user1_decision=row['Date_Decision_x'],
                    user2_decision=row['Date_Decision_y']
                )
                db.session.add(match)
        db.session.commit()

@app.route('/')
def index():
    current_date = datetime(2025, 2, 24)
    upcoming_events = Event.query.filter(Event.date >= current_date).order_by(Event.date.asc()).all()
    past_events = Event.query.filter(Event.date < current_date).order_by(Event.date.desc()).limit(5).all()
    return render_template('index.html', upcoming_events=upcoming_events, past_events=past_events)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.verified:
                flash('Please verify your email before logging in.', 'warning')
                return redirect(url_for('login'))
            session['email'] = email
            flash('Logged in successfully!', 'success')
            if email in ['admin@example.com', "spkibet@gmail.com"]:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if not is_valid_password(password):
            return render_template('register.html', error='Password must be at least 8 characters long and include uppercase, lowercase, and a special character.')
        
        if User.query.filter_by(email=email).first():
            existing_user = User.query.filter_by(email=email).first()
            if not existing_user.verified:
                existing_user.password = generate_password_hash(password, method='pbkdf2:sha256')
                existing_user.verified = False
                db.session.commit()
                token = serializer.dumps(email, salt='email-verification')
                verify_url = url_for('verify_email', token=token, _external=True)
                msg = Message('Verify Your Email - Speed Dating Hub', recipients=[email])
                msg.body = f'Click the link to verify your email: {verify_url}\nThis link expires in 1 hour.'
                mail.send(msg)
                flash('A verification email has been sent. Please check your inbox.', 'success')
                return redirect(url_for('login'))
            return render_template('register.html', error='Email already registered')
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_password, verified=False)
        db.session.add(new_user)
        db.session.commit()

        token = serializer.dumps(email, salt='email-verification')
        verify_url = url_for('verify_email', token=token, _external=True)
        msg = Message('Verify Your Email - Speed Dating Hub', recipients=[email])
        msg.body = f'Click the link to verify your email: {verify_url}\nThis link expires in 1 hour.'
        mail.send(msg)

        flash('A verification email has been sent. Please check your inbox.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user and not user.verified:
            user.verified = True
            db.session.commit()
            flash('Email verified successfully! You can now log in.', 'success')
        else:
            flash('Invalid or already verified token.', 'danger')
    except SignatureExpired:
        flash('The verification link has expired. Please register again.', 'danger')
    return redirect(url_for('login'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password_token', token=token, _external=True)
            msg = Message('Password Reset - Speed Dating Hub', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_url}\nThis link expires in 1 hour.'
            mail.send(msg)
            flash('A password reset email has been sent. Please check your inbox.', 'success')
        else:
            flash('No account found with that email.', 'danger')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Invalid reset token.', 'danger')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            if password != confirm_password:
                return render_template('reset_password_token.html', token=token, error='Passwords do not match.')
            if not is_valid_password(password):
                return render_template('reset_password_token.html', token=token, error='Password must be at least 8 characters long and include uppercase, lowercase, and a special character.')
            
            user.password = generate_password_hash(password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Password reset successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        
        return render_template('reset_password_token.html', token=token)
    except SignatureExpired:
        flash('The reset link has expired. Please request a new one.', 'danger')
        return redirect(url_for('reset_password'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    email = session['email']
    user = User.query.filter_by(email=email).first()
    
    matches = Match.query.filter((Match.user1_id == user.id) | (Match.user2_id == user.id)).all()
    event_ids = {match.event_id for match in matches}
    events = Event.query.filter(Event.id.in_(event_ids)).all()
    
    selected_event_id = request.form.get('event', events[0].id if events else None)
    filtered_matches = [m for m in matches if m.event_id == int(selected_event_id)] if selected_event_id else matches
    
    match_data = []
    for match in filtered_matches:
        if match.user1_id == user.id:
            match_data.append({
                'other_email': match.user2.email,
                'other_name': match.user2_name,
                'your_decision': match.user1_decision,
                'their_decision': match.user2_decision
            })
        else:
            match_data.append({
                'other_email': match.user1.email,
                'other_name': match.user1_name,
                'your_decision': match.user2_decision,
                'their_decision': match.user1_decision
            })
    
    return render_template('dashboard.html', matches=match_data, events=events, selected_event=selected_event_id)

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    if request.method == 'POST':
        if 'csv_file' in request.files:
            file = request.files['csv_file']
            if file and file.filename.endswith('.csv'):
                process_csv(file)
                flash('CSV data uploaded successfully!', 'success')
            else:
                flash('Please upload a valid CSV file.', 'danger')
        
        elif 'event_name' in request.form:
            name = request.form['event_name']
            date = datetime.strptime(request.form['event_date'], '%Y-%m-%d')
            capacity = int(request.form['capacity'])
            new_event = Event(name=name, date=date, capacity=capacity)
            db.session.add(new_event)
            db.session.commit()
            flash('New event added successfully!', 'success')
    
    events = Event.query.all()
    return render_template('admin.html', events=events)

@app.route('/book_event/<int:event_id>', methods=['POST'])
def book_event(event_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=session['email']).first()
    event = Event.query.get_or_404(event_id)
    
    if Booking.query.filter_by(user_id=user.id, event_id=event_id).first():
        flash('You have already booked this event.', 'warning')
        return redirect(url_for('index'))
    
    current_bookings = Booking.query.filter_by(event_id=event_id).count()
    if current_bookings >= event.capacity:
        flash('This event is fully booked.', 'danger')
        return redirect(url_for('index'))
    
    booking = Booking(user_id=user.id, event_id=event_id)
    db.session.add(booking)
    db.session.commit()
    
    msg = Message('Event Booking Confirmation - Speed Dating Hub', recipients=[user.email])
    msg.body = f'You have successfully booked {event.name} on {event.date.strftime("%B %d, %Y")}. Enjoy the event!'
    mail.send(msg)
    
    flash('Event booked successfully! Check your email for confirmation.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)