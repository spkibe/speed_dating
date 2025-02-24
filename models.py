from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    verified = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.email}>'

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    capacity = db.Column(db.Integer, nullable=False, default=50)

    def __repr__(self):
        return f'<Event {self.name}>'

class Match(db.Model):
    __tablename__ = 'matches'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user1_name = db.Column(db.String(100), nullable=True)  # Name from CSV
    user2_name = db.Column(db.String(100), nullable=True)  # Name from CSV
    user1_decision = db.Column(db.String(20), nullable=False)
    user2_decision = db.Column(db.String(20), nullable=False)

    event = db.relationship('Event', backref='matches')
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])

    def __repr__(self):
        return f'<Match {self.user1.email} - {self.user2.email}>'

class Booking(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    booking_date = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='bookings')
    event = db.relationship('Event', backref='bookings')

    def __repr__(self):
        return f'<Booking {self.user.email} - {self.event.name}>'