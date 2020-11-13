from enum import Enum, IntEnum
from flask import Flask, session, url_for, redirect, request, render_template, abort, flash
from flask_babel import Babel, gettext
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import werkzeug.middleware.proxy_fix
from sqlalchemy import text, desc
import bcrypt
import os
import datetime
import functools
from fuzzywuzzy import process
from flask_socketio import SocketIO, send, join_room, leave_room, emit, Namespace, disconnect
import random
import string
import urllib3
import base64
import json
import pyimgur
import requests
import stripe
import calendar
import urllib

app = Flask(__name__)
babel = Babel(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['LANGUAGES'] = {
    'en': 'English',
    'it': 'Italian'
}
app.secret_key = "testing"
app.config['UPLOAD_FOLDER'] = "C:\\Users\\loren\\Documents\\GitHub\\ristorazione\\uploads"
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
db = SQLAlchemy(app)
socketio = SocketIO(app)
imgur_id = os.getenv('imgurId')
imgur_secret = os.getenv('imgurSecret')
stripe_public = os.getenv('stripePublic')
stripe_private = os.getenv('stripePrivate')
base_url = os.getenv('baseUrl')
reverse_proxy_app = werkzeug.middleware.proxy_fix.ProxyFix(app=app, x_for=1, x_proto=0, x_host=1, x_port=0, x_prefix=0)
paymentSessions = []

# DB classes go beyond this point


class User(db.Model):
    __tablename__ = "user"
    email = db.Column(db.String, primary_key=True)
    password = db.Column(db.LargeBinary, nullable=False)
    name = db.Column(db.String, nullable=False)
    surname = db.Column(db.String, nullable=False)
    isAdmin = db.Column(db.Boolean, nullable=False)
    work = db.relationship("Work", back_populates="user", cascade="all, delete")


class Restaurant(db.Model):
    __tablename__ = "restaurant"
    rid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    city = db.Column(db.String)
    address = db.Column(db.String)
    state = db.Column(db.String)
    description = db.Column(db.String)
    link = db.Column(db.String)
    work = db.relationship("Work", back_populates="restaurant", cascade="all, delete")
    menus = db.relationship("MenuAssociation", back_populates="restaurant", cascade="all, delete")
    ownedPlates = db.relationship("Plate", back_populates="restaurant", cascade="all, delete")
    tax = db.Column(db.Float, nullable=False)
    tables = db.relationship("Table", back_populates="restaurant", cascade="all, delete")
    sub = db.relationship("SubscriptionAssociation", back_populates="restaurant", cascade="all, delete")
    orders = db.relationship("Order", back_populates="restaurant", cascade="all, delete")


class Work(db.Model):
    __tablename__ = "work"
    userEmail = db.Column(db.String, db.ForeignKey('user.email'), primary_key=True)
    restaurantId = db.Column(db.Integer, db.ForeignKey('restaurant.rid'), primary_key=True)
    type = db.Column(db.Integer, nullable=False)
    user = db.relationship("User", back_populates="work")
    restaurant = db.relationship("Restaurant", back_populates="work")


class Subscription(db.Model):
    __tablename__ = "subscription"
    sid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    monthlyCost = db.Column(db.Float, nullable=False)
    level = db.Column(db.Integer, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # Number of months
    sub = db.relationship("SubscriptionAssociation", back_populates="subscription", cascade="all, delete")


class SubscriptionAssociation(db.Model):
    __tablename__ = "subscriptionsAssociation"
    restaurantId = db.Column(db.Integer, db.ForeignKey('restaurant.rid'), primary_key=True)
    subscriptionId = db.Column(db.Integer, db.ForeignKey('subscription.sid'), primary_key=True)
    restaurant = db.relationship("Restaurant", back_populates="sub")
    subscription = db.relationship("Subscription", back_populates="sub")
    last_validity = db.Column(db.DateTime, nullable=False)


class Table(db.Model):
    __tablename__ = "table"
    tid = db.Column(db.Integer, primary_key=True)
    restaurant = db.relationship("Restaurant", back_populates="tables")
    restaurantId = db.Column(db.Integer, db.ForeignKey("restaurant.rid"), primary_key=True)
    token = db.Column(db.String(6))
    order = db.relationship("Order", back_populates="table")


class Menu(db.Model):
    __tablename__ = "menu"
    mid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Integer, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)
    restaurants = db.relationship("MenuAssociation", back_populates="menu", cascade="all, delete")
    topLevelCategories = db.relationship("Category", back_populates="menu", cascade="all, delete")


class MenuAssociation(db.Model):
    __tablename__ = "menuAssociation"
    menuId = db.Column(db.Integer, db.ForeignKey('menu.mid'), primary_key=True)
    restaurantId = db.Column(db.Integer, db.ForeignKey('restaurant.rid'), primary_key=True)
    menu = db.relationship("Menu", back_populates="restaurants")
    restaurant = db.relationship("Restaurant", back_populates="menus")


class Category(db.Model):
    __tablename__ = "category"
    cid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Integer, nullable=False)
    menuId = db.Column(db.Integer, db.ForeignKey("menu.mid"))
    menu = db.relationship("Menu", back_populates="topLevelCategories")
    parentId = db.Column(db.Integer, db.ForeignKey("category.cid"))
    children = db.relationship("Category", backref=db.backref('parent', remote_side=[cid]), cascade="all, delete")
    plates = db.relationship("CategoryAssociation", back_populates="category", cascade="all, delete")

    def toJson(self):
        return {'cid': self.cid, 'name': self.name}


class Plate(db.Model):
    __tablename__ = "plate"
    pid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    ingredients = db.Column(db.String)
    cost = db.Column(db.Float, nullable=False)
    link = db.Column(db.String)
    categories = db.relationship("CategoryAssociation", back_populates="plate", cascade="all, delete")
    order = db.relationship("Order", back_populates="plate", cascade="all, delete")
    restaurant_id = db.Column(db.Integer, db.ForeignKey("restaurant.rid"), nullable=False)
    restaurant = db.relationship("Restaurant", back_populates="ownedPlates")

    def toJson(self):
        return {'pid': self.pid, 'name': self.name, 'description': self.description, 'ingredients': self.ingredients,
                'cost': self.cost, 'link': self.link}


class CategoryAssociation(db.Model):
    __tablename__ = "categoryAssociation"
    plateId = db.Column(db.Integer, db.ForeignKey('plate.pid'), primary_key=True)
    categoryId = db.Column(db.Integer, db.ForeignKey('category.cid'), primary_key=True)
    plate = db.relationship("Plate", back_populates="categories")
    category = db.relationship("Category", back_populates="plates")


class Order(db.Model):
    __tablename__ = "order"
    oid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    restaurantId = db.Column(db.Integer, db.ForeignKey('restaurant.rid'), nullable=False)
    tableId = db.Column(db.Integer, db.ForeignKey('table.tid'), nullable=False)
    plateId = db.Column(db.Integer, db.ForeignKey('plate.pid'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Integer, nullable=False, default=0)
    table = db.relationship("Table", back_populates="order")
    plate = db.relationship("Plate", back_populates="order")
    restaurant = db.relationship("Restaurant", back_populates="orders")
    specialReq = db.Column(db.String)
    costOverride = db.Column(db.Float)


class Transaction(db.Model):
    __tablename__ = "transaction"
    paymentId = db.Column(db.String, primary_key=True)
    sid = db.Column(db.Integer, primary_key=True)
    rid = db.Column(db.Integer, primary_key=True)
    enabled = db.Column(db.Boolean, default=True)


# UTILITIES

class UserType(IntEnum):
    undefined = 0
    waiter = 1
    owner = 2
    admin = 3


class OrderType(IntEnum):
    submitted = 0
    accepted = 1
    delivered = 2


def uploadToImgur(filename):
    im = pyimgur.Imgur(imgur_id)
    up_image = im.upload_image(filename, title="")
    return up_image.link


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


def createToken(table):
    while True:
        token = ''.join(random.choice("abcdefghijklmopqrstuvwxyz1234567890") for i in range(6))
        check = Table.query.filter_by(token=token, restaurantId=table.restaurantId).first()
        if not check:
            return token


# Decorators


def login_or_403(f):
    @functools.wraps(f)
    def func(*args, **kwargs):
        if not session.get("email"):
            abort(403)
            try:
                disconnect()
            except Exception:
                pass
            return
        return f(*args, **kwargs)

    return func


def admin_or_403(f):
    @functools.wraps(f)
    def func(*args, **kwargs):
        if not session.get("email") or not find_user(session.get("email")).isAdmin:
            abort(403)
            try:
                disconnect()
            except Exception:
                pass
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

        return func

    return decorator


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
    newUser = User(name=name, surname=surname, email=email, password=ash, isAdmin=False)
    db.session.add(newUser)
    db.session.commit()
    return redirect(url_for('page_login'))


@app.route('/user/<string:email>/edit', methods=['POST'])
@login_or_403
def page_user_edit(email):
    user = find_user(session['email'])
    if user.email != email:
        abort(403)
    pass
    if request.form['password'] != '':
        user.passeword = bcrypt.hashpw(bytes(request.form['password'], encoding='utf-8'), bcrypt.gensalt())
    user.name = request.form['name']
    user.surname = request.form['surname']
    db.session.commit()
    return redirect(url_for('page_dashboard'))


@app.route("/dashboard")
@login_or_403
def page_dashboard():
    user = find_user(session['email'])
    restaurants = Restaurant.query.join(Work).join(User).filter_by(email=user.email).all()
    if not restaurants:
        mode = 1
    return render_template("dashboard.htm", user=user, restaurants=restaurants)


@app.route("/restaurant/add", methods=['GET', 'POST'])
@login_or_403
def page_restaurant_add():
    user = find_user(session['email'])
    if request.method == 'GET':
        return render_template("Restaurant/addOrMod.htm", user=user)
    name = request.form.get("name")
    tax = float(request.form.get("tax"))
    numberOfTables = int(request.form.get("numberOfTables"))
    address = request.form.get("address")
    city = request.form.get("city")
    state = request.form.get("state")
    desc = request.form.get("desc")
    url = None
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '' and file and allowed_file(file.filename):
            path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(path)
            try:
                url = uploadToImgur(path)
            except Exception as e:
                url = None
                print(e)
                pass
            file.close()
            os.remove(path)
    newRestaurant = Restaurant(name=name, tax=tax, city=city, address=address, state=state, description=desc, link=url)
    db.session.add(newRestaurant)
    db.session.commit()
    user.restaurantId = newRestaurant.rid
    for i in range(0, numberOfTables, 1):
        t = Table(tid=i, restaurantId=newRestaurant.rid)
        token = createToken(t)
        t.token = token
        db.session.add(t)
    newWork = Work(userEmail=user.email, restaurantId=newRestaurant.rid, type=UserType.owner)
    db.session.add(newWork)
    db.session.commit()
    return redirect(url_for('page_dashboard'))


@app.route("/restaurant/edit/<int:rid>", methods=['GET', 'POST'])
@login_or_403
def page_restaurant_edit(rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(restaurantId=rid, userEmail=user.email).first()
    if not check:
        abort(403)
        return
    restaurant = Restaurant.query.get_or_404(rid)
    if request.method == 'GET':
        return render_template("Restaurant/addOrMod.htm", user=user, restaurant=restaurant)
    restaurant.name = request.form.get("name")
    restaurant.tax = float(request.form.get("tax"))
    restaurant.address = request.form.get("address")
    restaurant.city = request.form.get("city")
    restaurant.state = request.form.get("state")
    restaurant.description = request.form['desc']
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '' and file and allowed_file(file.filename):
            path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(path)
            try:
                url = uploadToImgur(path)
                restaurant.link = url
            except Exception as e:
                url = None
                print(e)
                pass
            file.close()
            os.remove(path)
    db.session.commit()
    return redirect(url_for('page_restaurant_management', rid=rid))


@app.route("/restaurant/<int:rid>/info", methods=['GET', 'POST'])
def page_restaurant_info(rid):
    restaurant = Restaurant.query.get_or_404(rid)
    return render_template("Restaurant/info.htm", restaurant=restaurant, address=urllib.parse.quote(restaurant.address), state=urllib.parse.quote(restaurant.state), city=urllib.parse.quote(restaurant.city))


@app.route("/restaurant/<int:rid>/management", methods=['GET'])  # Needs a frontend!
@login_or_403
def page_restaurant_management(rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(restaurantId=rid, userEmail=user.email).first()
    if not check:
        abort(403)
        return
    data = Restaurant.query.filter_by(rid=rid).first()
    return render_template("Restaurant/management.htm", data=data, user=user)


@app.route("/restaurant/<int:rid>/add_waiterOrOwner/<int:mode>", methods=['POST'])
@login_or_403
def page_restaurant_add_waiter_or_owner(rid, mode):
    user = find_user(session['email'])
    check = Work.query.filter_by(restaurantId=rid, userEmail=user.email, type=2).first()
    if not check:
        abort(403)
        return
    email = request.form.get('email')
    human = User.query.get_or_404(email)
    isAlreadyRelated = Work.query.filter_by(restaurantId=rid, userEmail=human.email).first()
    if isAlreadyRelated:
        db.session.delete(isAlreadyRelated)
    if mode == 0:
        newWork = Work(userEmail=human.email, restaurantId=rid, type=1)
    else:
        newWork = Work(userEmail=human.email, restaurantId=rid, type=2)
    db.session.add(newWork)
    db.session.commit()
    return "200 - Success"


@app.route("/restaurant/<int:rid>/getOwners", methods=['POST'])
@login_or_403
def page_restaurant_get_owners(rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(restaurantId=rid, userEmail=user.email, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    msg = ""
    owners = Work.query.filter(Work.restaurantId == rid, Work.type == UserType.owner).all()
    for owner in owners:
        msg = msg + """
        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td><i class="material-icons">delete</i></td>
        </tr>
        """.format(owner.user.name, owner.user.surname, owner.user.email)
    return msg


@app.route("/restaurant/<int:rid>/getWaiters", methods=['POST'])
@login_or_403
def page_restaurant_get_waiters(rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(restaurantId=rid, userEmail=user.email, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    msg = ""
    waiters = Work.query.filter(Work.restaurantId == rid, Work.type == UserType.waiter).all()
    for waiter in waiters:
        msg = msg + """
        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td><i class="material-icons">delete</i></td>
        </tr>
        """.format(waiter.user.name, waiter.user.surname, waiter.user.email)
    return msg


# Todo: add a subscription check

@app.route("/menu/add/<int:rid>", methods=['GET', 'POST'])
@login_or_403
def page_menu_add(rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    if request.method == "GET":
        return render_template("Menu/addOrMod.htm", user=user, rid=rid)
    else:
        name = request.form.get("name")
        newMenu = Menu(name=name, enabled=True)
        db.session.add(newMenu)
        db.session.commit()
        newAssociation = MenuAssociation(restaurantId=rid, menuId=newMenu.mid)
        db.session.add(newAssociation)
        db.session.commit()
        return redirect(url_for("page_menu_details", mid=newMenu.mid, rid=rid))


@app.route("/menu/edit/<int:mid>/<int:rid>", methods=['GET', 'POST'])
@login_or_403
def page_menu_edit(mid, rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    menu = Menu.query.get_or_404(mid)
    if request.method == 'GET':
        return render_template("Menu/addOrMod.htm", user=user, rid=rid, menu=menu)
    menu.name = request.form.get("name")
    db.session.commit()
    return redirect(url_for('page_restaurant_management', rid=rid))


@app.route("/restaurant/<int:rid>/menu/<int:mid>")
def page_menu_inspect(rid, mid):
    menu = Menu.query.get_or_404(mid)
    if not menu.enabled:
        abort(403)
    return render_template("Menu/inspect.htm", menu=menu, rid=rid)


@app.route("/restaurant/<int:rid>/menu/details/<int:mid>", methods=['GET'])
@login_or_403
def page_menu_details(rid, mid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    menu = Menu.query.filter_by(mid=mid).first()
    return render_template("Menu/details.htm", menu=menu, user=user, rid=rid)


@app.route("/restaurant/<int:rid>/menu/<int:mid>/category/add/<int:cid>", methods=['GET', 'POST'])
@login_or_403
def page_category_add(rid, mid, cid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    check2 = MenuAssociation.query.filter_by(menuId=mid, restaurantId=rid).first()
    if not check or not check2:
        abort(403)
        return
    if request.method == "GET":
        categories = Category.query.filter_by(mid=mid).all()
        return render_template("Menu/Category/addOrMod.htm", user=user, mid=mid, categories=categories)
    else:
        name = request.form.get('name')
        if int(cid) != 0:
            subcategory = request.form.get('subcategorySelect')
            newCat = Category(name=name, parentId=cid)
        else:
            newCat = Category(name=name, menuId=mid)
        db.session.add(newCat)
        db.session.commit()
        return "200 success"


@app.route("/restaurant/<int:rid>/dish/add", methods=['GET', 'POST'])
@login_or_403
def page_dish_add(rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    if request.method == "GET":
        return render_template("Menu/Plate/addOrMod.htm", user=user, rid=rid)
    name = request.form.get('name')
    description = request.form.get('description')
    ingredients = request.form.get('ingredients')
    cost = float(request.form.get('cost'))
    url = None
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '' and file and allowed_file(file.filename):
            path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(path)
            try:
                url = uploadToImgur(path)
            except Exception as e:
                url = None
                print(e)
                pass
            file.close()
            os.remove(path)
    newDish = Plate(name=name, description=description, ingredients=ingredients, cost=cost, restaurant_id=rid, link=url)
    db.session.add(newDish)
    db.session.commit()
    print(rid)
    return redirect(url_for("page_restaurant_management", rid=rid))


@app.route("/restaurant/<int:rid>/category/<int:cid>/edit", methods=['GET', 'POST'])
@login_or_403
def page_category_edit(rid, cid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    category = Category.query.get_or_404(cid)
    if request.method == "GET":
        return render_template("Menu/Category/edit.htm", user=user, rid=rid, category=category)
    category.name = request.form.get('name')
    db.session.commit()
    return redirect(url_for('page_menu_details', rid=rid, mid=category.menuId))


@app.route("/plate/edit/<int:pid>/<int:rid>", methods=['GET', 'POST'])
@login_or_403
def page_dish_edit(pid, rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    plate = Plate.query.get_or_404(pid)
    if request.method == "GET":
        return render_template("Menu/Plate/addOrMod.htm", user=user, rid=rid, plate=plate)
    plate.name = request.form.get("name")
    plate.description = request.form.get("description")
    plate.ingredients = request.form.get("ingredients")
    plate.cost = float(request.form.get("cost"))
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '' and file and allowed_file(file.filename):
            path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(path)
            try:
                url = uploadToImgur(path)
                plate.link = url
            except Exception as e:
                url = None
                print(e)
                pass
            file.close()
            os.remove(path)
    db.session.commit()
    return redirect(url_for("page_restaurant_management", rid=rid))


@app.route("/restaurant/<int:rid>/dish/get", methods=['POST'])
def page_dish_get(rid):
    dishes = Plate.query.filter_by(restaurant_id=rid).all()
    catid = request.form.get('cid')
    dishlist = []
    for dish in dishes:
        dishlist.append(dish.toJson())
    response = {'response': dishlist}
    return response


@app.route("/restaurant/<int:rid>/menu/<int:mid>/dish/add/<int:cid>", methods=["POST"])
@login_or_403
def page_dish_add_menu(rid, mid, cid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    plateid = request.form.get('pid')
    check2 = Plate.query.filter_by(restaurant_id=rid, pid=plateid).first()
    if not check and not check2:
        abort(403)
        return
    newCat = CategoryAssociation(plateId=plateid, categoryId=cid)
    db.session.add(newCat)
    db.session.commit()
    return "200 success"


@app.route("/menu/<int:mid>/category/<int:cid>/getComponents", methods=["POST"])
def page_menu_get_components(mid, cid):
    categories = Category.query.filter_by(parentId=cid).all()
    dishes = CategoryAssociation.query.join(Plate).filter(CategoryAssociation.categoryId == cid).all()
    catlist = []
    dishlist = []
    for cat in categories:
        catlist.append(cat.toJson())
    for dish in dishes:
        dishlist.append(dish.plate.toJson())
    response = {'response': {'categories': catlist, 'dishes': dishlist}}
    return response


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
    return render_template("Restaurant/list.htm", restaurants=result, invert=True, mode="search")


@app.route("/restaurant/<int:rid>/tables")
@login_or_403
def page_restaurant_tables(rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid).first()
    if not check or check.type < UserType.waiter:
        abort(403)
    tables = Table.query.filter_by(restaurantId=rid).all()
    orders_pending = Order.query.filter_by(restaurantId=rid, status=OrderType.submitted).all()
    orders_tbd = Order.query.filter_by(restaurantId=rid, status=OrderType.accepted).all()
    orders_complete = Order.query.filter_by(restaurantId=rid, status=OrderType.delivered).all()
    return render_template("Restaurant/tables.htm", user=user, tables=tables, rid=rid, op=orders_pending, ot=orders_tbd,
                           oc=orders_complete)


@app.route("/table/<int:tid>/getToken", methods=['POST'])
@login_or_403
def page_table_get_token(tid):
    rid = request.form.get('rid')
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid).first()
    if not check or check.type < UserType.waiter:
        abort(403)
    table = Table.query.get_or_404((tid, rid))
    return {'token': table.token}


@app.route("/table/<int:tid>/getOrders", methods=['POST'])
@login_or_403
def page_table_get_orders(tid):
    rid = request.form.get('rid')
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid).first()
    if not check or check.type < UserType.waiter:
        abort(403)
    table = Table.query.get_or_404((tid, rid))
    response = {'orders': []}
    for order in table.order:
        custom = "false"
        cost = order.plate.cost
        if order.specialReq:
            custom = "true"
            if order.costOverride:
                cost=order.costOverride
        tmp = {'pid': order.plate.pid, 'name': order.plate.name, 'cost': cost, 'qty': order.quantity, 'custom': custom, 'oid':order.oid, 'rid':order.restaurantId, 'tid':tid}
        response['orders'].append(tmp)
    return response


@app.route("/order/<int:oid>/setCustom", methods=['POST'])
@login_or_403
def page_order_setCustom(oid):
    rid = request.form.get('rid')
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid).first()
    if not check or check.type < UserType.waiter:
        abort(403)
    order = Order.query.get_or_404(oid)
    order.costOverride = float(request.form.get('costOverride'))
    order.specialReq = request.form.get('special')
    db.session.commit()
    return "200"


@app.route("/order/<int:oid>/getPlate", methods=['POST'])
@login_or_403
def page_order_getPlate(oid):
    rid = request.form.get('rid')
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid).first()
    if not check or check.type < UserType.waiter:
        abort(403)
    order = Order.query.get_or_404(oid)
    ans = order.plate.toJson()
    cost = order.costOverride
    if not order.costOverride:
        cost = 0
    ans['override']={'desc': order.specialReq, 'cost': cost, 'tid': order.tableId, 'oid': order.oid}
    return ans


@app.route("/table/<int:tid>/close", methods=['POST'])
@login_or_403
def page_table_close(tid):
    rid = request.form.get('rid')
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid).first()
    if not check or check.type < UserType.waiter:
        abort(403)
    table = Table.query.get_or_404((tid, rid))
    response = {'orders': []}
    for order in table.order:
        if order.costOverride:
            cost=order.costOverride
            name = order.plate.name + " *"
        else:
            cost=order.plate.cost
            name=order.plate.name
        tmp = {'pid': order.plate.pid, 'name': name, 'cost': cost * order.quantity,
               'qty': order.quantity}
        response['orders'].append(tmp)
        db.session.delete(order)
    table.token = createToken(table)
    db.session.commit()
    return response


@app.route("/restaurant/<int:rid>/tableLogin", methods=['POST', 'GET'])
def page_table_login(rid):
    if 'tid' in session and request.method == "GET":
        del session['tid']
        del session['token']
        del session['rid']
        return redirect(url_for('page_restaurant_info', rid=rid))
    table = Table.query.filter_by(tid=int(request.form.get('tableId')) - 1, restaurantId=rid,
                                  token=request.form.get('token')).first()
    if not table:
        abort(403)
    session['tid'] = int(request.form.get('tableId')) - 1
    session['token'] = request.form.get('token')
    session['rid'] = rid
    return redirect(url_for('page_orders_dashboard', rid=rid))


@app.route("/restaurant/<int:rid>/orderManager")
def page_orders_dashboard(rid):
    if 'tid' not in session or not Table.query.filter_by(tid=session['tid'], restaurantId=session['rid'],
                                                         token=session['token']).first():
        return redirect(url_for('page_restaurant_info', rid=rid))
    menus = Menu.query.join(MenuAssociation).filter(MenuAssociation.restaurantId == rid, Menu.enabled == True).all()
    orders = Order.query.filter_by(restaurantId=rid, tableId=session['tid']).all()
    return render_template("Orders/dashboard.htm", menus=menus, orders=orders, tid=session['tid'], rid=rid)


@app.route("/restaurant/<int:rid>/orders/table/<int:tid>/menu/<int:mid>", methods=['GET', 'POST'])
def page_orders_menu(rid, tid, mid):
    if 'tid' not in session or not Table.query.filter_by(tid=session['tid'], restaurantId=session['rid'],
                                                         token=session['token']).first():
        return redirect(url_for('page_restaurant_info', rid=rid))
    menu = Menu.query.get_or_404(mid)
    if not menu.enabled:
        abort(403)
    return render_template("Orders/menu.htm", menu=menu, rid=rid, tid=tid)


@app.route('/restaurant/<int:rid>/order/<int:tid>', methods=['GET', 'POST'])
def page_order_submit(rid, tid):
    if 'tid' not in session or not Table.query.filter_by(tid=session['tid'], restaurantId=session['rid'],
                                                         token=session['token']).first():
        abort(403)
    data = request.json
    for elem in data.keys():
        if not elem == '-1':
            newOrder = Order(restaurantId=rid, tableId=tid, plateId=elem, quantity=data[elem]['qty'])
            db.session.add(newOrder)
            db.session.commit()
            json = {'rid': rid, 'order': {'tid': tid, 'token': session['token'], 'pid': elem, 'qty': data[elem]['qty'],
                                          'oid': newOrder.oid, 'status': newOrder.status}}
            orderHandler(json)
    db.session.commit()
    return "200 OK"


@app.route("/about")
def page_about():
    subscriptions = Subscription.query.order_by(desc(Subscription.duration)).all()
    return render_template("about.htm", subscriptions=subscriptions)


# Item deletion functions

@app.route("/restaurant/<int:rid>/category/<int:cid>/delete")
@login_or_403
def page_category_del(rid, cid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    category = Category.query.get_or_404(cid)
    mid = category.menuId
    db.session.delete(category)
    db.session.commit()
    return redirect(url_for('page_menu_details', rid=rid, mid=mid))


@app.route("/restaurant/<int:rid>/plate/<int:pid>/delete")
@login_or_403
def page_plate_delete(rid, pid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    plate = Plate.query.get_or_404(pid)
    if plate.restaurant_id != rid:
        abort(403)
    db.session.delete(plate)
    db.session.commit()
    return redirect(url_for("page_restaurant_management", rid=rid) + "#menus")


@app.route("/restaurant/<int:rid>/category/<int:cid>/plate/<int:pid>/remove", methods=['POST'])
@login_or_403
def page_plate_remove_from_menu(rid, cid, pid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    assoc = CategoryAssociation.query.filter_by(plateId=pid, categoryId=cid).first()
    db.session.delete(assoc)
    db.session.commit()
    return "200"


@app.route("/restaurant/<int:rid>/personnel/<string:email>/remove")
@login_or_403
def page_personnel_remove(rid, email):
    user = find_user(session['email'])
    if email == user.email:
        return redirect(url_for("page_restaurant_management", rid=rid))
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    work = Work.query.filter_by(userEmail=email, restaurantId=rid).first()
    db.session.delete(work)
    db.session.commit()
    return redirect(url_for("page_restaurant_management", rid=rid))


@app.route("/delete/<int:rid>/<elementId>/<string:type>/<int:mode>")  # if mode = 1, delete
@login_or_403
def page_delete(rid, elementId, type, mode):
    if mode == 0:
        return render_template("delete.htm", rid=rid, elementId=elementId, type=type)
    user = find_user(session['email'])
    if not type == "user":
        check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
        if not check:
            abort(403)
            return
        if type == "menu":
            element = Menu.query.get_or_404(elementId)
            if not MenuAssociation.query.filter_by(menuId=elementId, restaurantId=rid).first():
                abort(403)
        if type == "restaurant":
            element = Restaurant.query.get_or_404(elementId)
        if type == "table":
            element = Table.query.get_or_404(elementId)
            if element.restaurantId != rid:
                abort(403)
    elif type == "user":
        element = User.query.get_or_404(elementId)
        if element.email != user.email and not user.isAdmin:
            abort(403)
    db.session.delete(element)
    db.session.commit()
    if type == "user":
        if not Work.query.filter_by(restaurantId=rid, type=UserType.owner).first():
            restaurant = Restaurant.query.get_or_404(rid)
            db.session.delete(restaurant)
            db.session.commit()
        return redirect(url_for('page_root'))
    if type == "restaurant":
        return redirect(url_for('page_dashboard'))
    else:
        return redirect(url_for('page_restaurant_management', rid=rid))


@app.route("/restaurant/<int:rid>/subscription/select")
@login_or_403
def page_subscription_info(rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    subscriptions = Subscription.query.order_by(desc(Subscription.duration)).all()
    return render_template("Subscriptions/show.htm", subscriptions=subscriptions, rid=rid, user=user)


# Socket definitions go below

@socketio.on('connectPersonnel')
@login_or_403
def connHandler(rid):
    user = find_user(session['email'])
    print("User {} is trying to access...".format(user.email))
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid).first()
    if not check or check.type < UserType.waiter:
        return
    print("User {} has joined room {}.".format(user.email, rid))
    join_room(rid)


@socketio.on('ping')
def pingHandler(rid):
    print("Table {} is pinging".format(rid))
    if 'tid' not in session:
        return
    print("Table {} is pinging".format(rid))
    emit("ping", room=rid)


@socketio.on('disconnectPersonnel')
@login_or_403
def disconnHandler(rid):
    user = find_user(session['email'])
    leave_room(rid)
    print("User {} has disconnected from room {}.".format(user.email, rid))


@socketio.on('newOrder')
def orderHandler(json):
    print("start")
    if 'tid' not in session or not Table.query.filter_by(tid=session['tid'], restaurantId=session['rid'],
                                                         token=session['token']).first():
        abort(403)
    orderlist = {}
    counter = 0
    data = json['json']
    for element in data.keys():
        if data[element]['pid'] == '-1':
            continue
        isCustom = False
        if data[element]['pid'][0] == "!":
            res = data[element]['pid'].split("!")
            orderlist[counter] = data[element]
            orderlist[counter]['pid'] = res[2]
            orderlist[counter]['isCustom'] = True
        else:
            orderlist[counter] = data[element]
            orderlist[counter]['isCustom'] = False
        counter+=1
    for order in orderlist.keys():
        newOrder = Order(restaurantId=session['rid'], tableId=session['tid'], plateId=orderlist[order]['pid'],
                         quantity=orderlist[order]['data']['qty'])
        if orderlist[order]['isCustom']:
            newOrder.specialReq = "TBD"
        db.session.add(newOrder)
        db.session.commit()
        orderlist[order]['data']['oid'] = newOrder.oid
        orderlist[order]['data']['tid'] = session['tid']
        db.session.commit()
    emit('newOrder', orderlist, room=session['rid'], json=True)
    print("finish")


@socketio.on('updateOrderStatus')
@login_or_403
def updaterHandler(json):  # {'oid': oid, 'status': statusDict[newLevel], 'oldStatus': statusDict[oldLevel]}
    if json['status'] < 0 or json['status'] > 2:
        return
    order = Order.query.filter_by(oid=json['oid']).first()
    if not order:
        return "404"
    order.status = json['status']
    json['name'] = order.plate.name
    db.session.commit()
    emit('updateOrderStatus', json, room=json['rid'], json=True)


# Payments pages

@app.route("/restaurant/<int:rid>/subscribe/<int:sid>")
@login_or_403
def page_subscribe(rid, sid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    sub = Subscription.query.get_or_404(sid)
    res = Restaurant.query.get_or_404(rid)
    return render_template("Subscriptions/request.htm", user=user, restaurant=res, subscription=sub, key=stripe_public)


@app.route("/create-checkout-session/<int:sid>/<int:rid>")
def create_checkout_session(sid, rid):
    user = find_user(session['email'])
    check = Work.query.filter_by(userEmail=user.email, restaurantId=rid, type=UserType.owner).first()
    if not check:
        abort(403)
        return
    subscription = Subscription.query.get_or_404(sid)
    stripe.api_key = stripe_private
    domain_url = base_url + "/"
    data = request.get_json()
    try:
        checkout_session = stripe.checkout.Session.create(
            success_url=domain_url + "success/{CHECKOUT_SESSION_ID}",
            cancel_url=domain_url + "cancelled",
            payment_method_types=["card"],
            mode="payment",
            line_items=[
                {
                    "name": subscription.name,
                    "quantity": 1,
                    "currency": "eur",
                    "amount": int(subscription.monthlyCost)*100,
                }
            ]
        )
        transaction = Transaction(paymentId=checkout_session['id'], sid=sid, rid=rid)
        db.session.add(transaction)
        db.session.commit()
        return {"sessionId": checkout_session["id"]}
    except Exception as e:
        abort(403)


@app.route("/success/<sessionId>")
def success(sessionId):
    check = Transaction.query.filter_by(paymentId=sessionId, enabled=True).first()
    if not check:
        abort(403)
    check.enabled = False
    association = SubscriptionAssociation.query.filter_by(subscriptionId=check.sid, restaurantId=check.rid).first()
    subscription = Subscription.query.get_or_404(check.sid)
    if not association:
        today = datetime.date.today()
        lastDay = add_months(today, subscription.duration)
        newsub = SubscriptionAssociation(restaurantId=check.rid, subscriptionId=check.sid, last_validity=lastDay)
        db.session.add(newsub)
    else:
        today = association.last_validity
        lastDay = add_months(today, subscription.duration)
        association.last_validity =lastDay
    db.session.commit()
    return render_template("Subscriptions/result.htm", sessionId=sessionId, mode="success", hidebar=True, invert=True)


def add_months(sourcedate, months):
    month = sourcedate.month - 1 + months
    year = sourcedate.year + month // 12
    month = month % 12 + 1
    day = min(sourcedate.day, calendar.monthrange(year,month)[1])
    return datetime.date(year, month, day)


@app.route("/cancelled")
def cancelled():
    return render_template("Subscriptions/result.htm", user=user, mode="fail")


#Admin pages

@app.route("/admin/add", methods=['POST'])
@admin_or_403
def page_admin_add():
    pass



if __name__ == "__main__":
    # Aggiungi sempre le tabelle non esistenti al database, senza cancellare quelle vecchie
    print("Now cooking up the database...")
    db.create_all()
    user = User.query.filter_by(isAdmin=True).all()
    if len(user) == 0:
        p = bytes("password", encoding="utf-8")
        ash = bcrypt.hashpw(p, bcrypt.gensalt())
        newUser = User(email="lorenzo.balugani@gmail.com", name="Lorenzo", surname="Balugani", isAdmin=True,
                       password=ash)
        db.session.add(newUser)
        db.session.commit()
    print("The db is delicious!")
    socketio.run(app, debug=True, host='0.0.0.0')
