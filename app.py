from flask import Flask, render_template, request, redirect, url_for, session, flash
from utils.db_helper import db, init_db, register_user, validate_login, add_menu_item, get_all_menu_items, delete_menu_item, place_order, get_all_orders, make_reservation, add_review, get_all_reviews, user_exists, get_user_by_email
import os
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///caf_feline.db'
init_db(app)
bcrypt=Bcrypt(app)

print("DB absolute path:", os.path.abspath("caf_feline.db"))

@app.route('/')
def home():
    menu = get_all_menu_items()
    return render_template('index.html', username=session.get('username'), menu=menu)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        if user_exists(email):
            flash('User already exists with that email.', 'warning')
            return redirect(url_for('register'))

        register_user(username, email, password)
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')  # create this file if it doesn't exist

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user_by_email(email)

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
            
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/admin/add', methods=['GET', 'POST'])
def admin_add():
    if session.get('username') != 'admin':
        return redirect('/')
    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])
        description = request.form['description']
        add_menu_item(name, price, description)
        flash(f'Item "{name}" added to menu.', 'success')
        return redirect('/')
    return render_template('admin_add.html')

@app.route('/admin/delete/<int:item_id>')
def admin_delete(item_id):
    if session.get('username') != 'admin':
        return redirect('/')
    delete_menu_item(item_id)
    flash('Item deleted.', 'info')
    return redirect('/')

@app.route('/order', methods=['GET', 'POST'])
def order():
    if request.method == 'POST':
        customer_name = request.form['customer_name']
        item_id = int(request.form['item_id'])
        quantity = int(request.form['quantity'])
        place_order(customer_name, item_id, quantity)
        flash('Order placed successfully!', 'success')
        return redirect('/')
    menu = get_all_menu_items()
    return render_template('order.html', menu=menu)

@app.route('/admin/orders')
def admin_orders():
    if session.get('username') != 'admin':
        return redirect('/')
    orders = get_all_orders()
    return render_template('admin_orders.html', orders=orders)

@app.route('/reserve', methods=['GET', 'POST'])
def reserve():
    if request.method == 'POST':
        name = request.form['name']
        date = request.form['date']
        time = request.form['time']
        people = int(request.form['people'])
        make_reservation(name, date, time, people)
        flash('Reservation made successfully!', 'success')
        return redirect('/')
    return render_template('reserve.html')

@app.route('/reviews', methods=['GET', 'POST'])
def reviews():
    if request.method == 'POST':
        username = session.get('username', 'Anonymous')
        rating = int(request.form['rating'])
        comment = request.form['comment']
        add_review(username, rating, comment)
        flash('Thanks for your review!', 'success')
        return redirect('/reviews')
    
    all_reviews = get_all_reviews()
    return render_template('reviews.html', reviews=all_reviews)

if __name__ == '__main__':
    app.run(debug=True)