from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import re
from flask import flash
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

def user_exists(email):
    return User.query.filter_by(email=email).first() is not None

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=True)

def init_db(app):
    db.init_app(app)
    bcrypt.init_app(app)
    with app.app_context():
        db.create_all()

def is_strong_password(password):
    pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$')
    return bool(pattern.match(password))

def register_user(username, email, password):
    if not is_strong_password(password):
        flash('Password must be at least 8 characters and include uppercase, lowercase, number, and special character.', 'danger')
        return False
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return True

def validate_login(username, password):
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        return user
    return None

def add_menu_item(name, price, description):
    new_item = MenuItem(name=name, price=price, description=description)
    db.session.add(new_item)
    db.session.commit()

def delete_menu_item(item_id):
    item = MenuItem.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()

def get_all_menu_items():
    return MenuItem.query.all()

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(100), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    item = db.relationship('MenuItem', backref=db.backref('orders', lazy=True))

def place_order(customer_name, item_id, quantity):
    new_order = Order(customer_name=customer_name, item_id=item_id, quantity=quantity)
    db.session.add(new_order)
    db.session.commit()

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(80), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    people = db.Column(db.Integer, nullable=False)

def make_reservation(customer_name, date, time, people):
    reservation = Reservation(customer_name=customer_name, date=date, time=time, people=people)
    db.session.add(reservation)
    db.session.commit()

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)

def add_review(username, rating, comment):
    new_review = Review(username=username, rating=rating, comment=comment)
    db.session.add(new_review)
    db.session.commit()

def get_all_reviews():
    return Review.query.all()

def get_all_orders():
    return Order.query.all()

def validate_user(email, password):
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        return user
    return None

def get_user_by_email(email):
    return User.query.filter_by(email=email).first()

__all__ = ['db', 'init_db', 'register_user', 'validate_login', 'add_menu_item', 'get_all_menu_items', 'delete_menu_item', 'place_order']
