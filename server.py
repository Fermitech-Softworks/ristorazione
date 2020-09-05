from enum import Enum, IntEnum
from flask import Flask, session, url_for, redirect, request, render_template, abort
from flask_babel import Babel, gettext
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
import datetime
import functools
from fuzzywuzzy import process

import requests

app = Flask(__name__)
babel = Babel(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['LANGUAGES'] = {
    'en': 'English',
    'it': 'Italian'
}
app.secret_key = "testing"
app.config['UPLOAD_FOLDER'] = "./static"
ALLOWED_EXTENSIONS = set(['txt', 'md', 'pdf', 'doc', 'docx'])
db = SQLAlchemy(app)

# DB classes go beyond this point


ordersTable = db.Table('orders', db.metadata,
                       db.Column('tableId', db.Integer, db.ForeignKey('table.tid')),
                       db.Column('plateId', db.Integer, db.ForeignKey('plate.cid')),
                       db.Column('quantity', db.Integer, nullable=False))

subscriptionTable = db.Table('subs', db.metadata,
                             db.Column('restaurantId', db.Integer, db.ForeignKey('restaurant.rid')),
                             db.Column('subId', db.Integer, db.ForeignKey('subscription.sid')),
                             db.Column('nextPayment', db.DateTime, nullable=False))


class User(db.Model):
    __tablename__ = "user"
    email = db.Column(db.String, primary_key=True)
    password = db.Column(db.LargeBinary, nullable=False)
    name = db.Column(db.String, nullable=False)
    surname = db.Column(db.String, nullable=False)
    type = db.Column(db.Integer, nullable=False)
    restaurant = db.relationship("Restaurant", back_populates="employees")
    restaurantId = db.Column(db.Integer, db.ForeignKey("restaurant.rid"))


class Restaurant(db.Model):
    __tablename__ = "restaurant"
    rid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    employees = db.relationship("User", back_populates="restaurant")
    menus = db.relationship("Menu", back_populates="restaurant")
    tax = db.Column(db.Float, nullable=False)
    tables = db.relationship("Table", back_populates="restaurant")
    subbed = db.relationship("Subscription", secondary=subscriptionTable, back_populates="restaurants")


class Subscription(db.Model):
    __tablename__ = "subscription"
    sid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    monthlyCost = db.Column(db.Float, nullable=False)
    level = db.Column(db.Integer, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # Number of months
    restaurants = db.relationship("Restaurant", secondary=subscriptionTable, back_populates="subbed")


class Table(db.Model):
    __tablename__ = "table"
    tid = db.Column(db.Integer, primary_key=True)
    restaurant = db.relationship("Restaurant", back_populates="tables")
    restaurantId = db.Column(db.Integer, db.ForeignKey("restaurant.rid"), primary_key=True)
    token = db.Column(db.String(10))
    plates = db.relationship("Plate", secondary=ordersTable, back_populates="ordered")


class Menu(db.Model):
    __tablename__ = "menu"
    mid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Integer, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)
    restaurant = db.relationship("Restaurant", back_populates="menus")
    restaurantId = db.Column(db.Integer, db.ForeignKey("restaurant.rid"))
    topLevelCategories = db.relationship("Category", back_populates="menu")


class Category(db.Model):
    __tablename__ = "category"
    cid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Integer, nullable=False)
    menuId = db.Column(db.Integer, db.ForeignKey("menu.mid"))
    menu = db.relationship("Menu", back_populates="topLevelCategories")
    parentId = db.Column(db.Integer, db.ForeignKey("category.cid"))
    children = db.relationship("Category", backref=db.backref('parent', remote_side=[cid]))
    plates = db.relationship("Plate", back_populates="category")


class Plate(db.Model):
    __tablename__ = "plate"
    cid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    ingredients = db.Column(db.String)
    cost = db.Column(db.Float, nullable=False)
    category = db.relationship("Category", back_populates="plates")
    category_id = db.Column(db.Integer, db.ForeignKey("category.cid"))
    ordered = db.relationship("Table", secondary=ordersTable, back_populates="plates")


# UTILITIES

class UserType(IntEnum):
    undefined = 0
    waiter = 1
    owner = 2
    platformAdmin = 3


def login(email, password):
    user = User.query.filter_by(email=email).first()
    try:
        return bcrypt.checkpw(bytes(password, encoding="utf-8"), user.password)
    except AttributeError:
        # Se non esiste l'Utente
        return False


def find_user(email):
    return User.query.filter_by(email=email).first()


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Decorators


def login_or_403(f):
    @functools.wraps(f)
    def func(*args, **kwargs):
        if not session.get("email"):
            abort(403)
            return
        return f(*args, **kwargs)

    return func


def clearance_level(minimum):
    def decorator(f):
        @functools.wraps(f)
        @login_or_403
        def func(*args, **kwargs):
            utente = find_user(session.get("email"))
            if utente.type < minimum:
                abort(403)
                return
            return f(*args, utente=utente, **kwargs)


def login_or_redirect(f):
    @functools.wraps(f)
    def func(*args, **kwargs):
        if not session.get("email"):
            return redirect(url_for('page_home'))
        return f(*args, **kwargs)

    return func


@babel.localeselector
def get_locale():
    return request.accept_languages.best_match(app.config['LANGUAGES'].keys())


# Error pages with cats


@app.errorhandler(400)
def page_400(_):
    return render_template('error.htm', e=400, invert=True), 400


@app.errorhandler(403)
def page_403(_):
    return render_template('error.htm', e=403, invert=True), 403


@app.errorhandler(404)
def page_404(_):
    return render_template('error.htm', e=404, invert=True), 404


@app.errorhandler(500)
def page_500(_):
    return render_template('error.htm', e=500, invert=True), 500


# Pages for the guests


@app.route('/')
@login_or_redirect
def page_root():
    del session['email']
    return redirect(url_for('page_home'))


@app.route('/home')
def page_home():
    return render_template("home.htm")


@app.route('/login', methods=['GET', 'POST'])
def page_login():
    if request.method == 'GET':
        return render_template("login.htm", invert=True)
    email = request.form.get("email")
    password = request.form.get("password")
    if not email or not password:
        abort(400)
        return
    if login(email, password):
        session['email'] = email
        return redirect(url_for('page_dashboard'))
    else:
        abort(403)


@app.route('/register', methods=['GET', 'POST'])
def page_register():
    if request.method == 'GET':
        return render_template("register.htm", invert=True)
    name = request.form.get("email")
    surname = request.form.get("surname")
    email = request.form.get("email")
    password = request.form.get("password")
    p = bytes(password, encoding="utf-8")
    ash = bcrypt.hashpw(p, bcrypt.gensalt())
    newUser = User(name=name, surname=surname, email=email, password=ash, type=UserType.undefined)
    db.session.add(newUser)
    db.session.commit()
    return redirect(url_for('page_login'))


@app.route("/dashboard")
@login_or_403
def page_dashboard():
    user = find_user(session['email'])
    return render_template("dashboard.htm", user=user)


@app.route("/restaurant/add", methods=['GET', 'POST'])
@login_or_403
def page_restaurant_add():
    user = find_user(session['email'])
    if request.method == 'GET':
        return render_template("Restaurant/addOrMod.htm", user=user)
    if user.type < UserType.owner:
        user.type = UserType.owner
    name = request.form.get("name")
    tax = float(request.form.get("tax"))
    numberOfTables = int(request.form.get("numberOfTables"))
    newRestaurant = Restaurant(name=name, tax=tax)
    db.session.add(newRestaurant)
    db.session.commit()
    user.restaurantId = newRestaurant.rid
    for i in range(0, numberOfTables, 1):
        db.session.add(Table(tid=i, restaurantId=newRestaurant.rid))
    db.session.commit()
    return redirect(url_for('page_dashboard'))


@app.route("/search", methods=['POST'])
def page_search():
    searchKey = request.form.get("search")
    restaurants = Restaurant.query.all()
    result = dict()
    for restaurant in restaurants:
        v = []
        v.append(restaurant.name)
        value = process.extract(searchKey, v)
        if int(value[0][1]) >= 60:
            result[restaurant] = int(value[0][1])
    result = sorted(result.items(), key=lambda x: x[1], reverse=True)
    print(result)
    return render_template("Restaurant/list.htm", restaurants=result, invert=True, mode="search")


@app.route("/about")
def page_about():
    return render_template("about.htm")


if __name__ == "__main__":
    # Aggiungi sempre le tabelle non esistenti al database, senza cancellare quelle vecchie
    print("Ciao")
    db.create_all()
    user = User.query.filter_by(type=UserType.platformAdmin).all()
    if len(user) == 0:
        p = bytes("password", encoding="utf-8")
        ash = bcrypt.hashpw(p, bcrypt.gensalt())
        newUser = User(email="lorenzo.balugani@gmail.com", name="Lorenzo", surname="Balugani", type=3, password=ash)
        db.session.add(newUser)
        db.session.commit()
    app.run(debug=True, host='0.0.0.0')
