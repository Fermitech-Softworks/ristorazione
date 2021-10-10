from sqlalchemy import Integer, String, LargeBinary, Column, Boolean, ForeignKey, SmallInteger, DateTime, Float, JSON, \
    Time, Table
from sqlalchemy.orm import relationship, backref
from ristorazione.database.schemas import User as UserSchema

from ristorazione.database.db import Base

category_association = Table("category_association", Base.metadata,
                             Column("category_id", ForeignKey("category.id")),
                             Column("dish_id", ForeignKey("dish.id")))

composition = Table("composition", Base.metadata,
                    Column("ingredient_id", ForeignKey("ingredient.id")),
                    Column("dish_id", ForeignKey("dish.id")))

additions = Table("additions", Base.metadata,
                  Column("ingredient_id", ForeignKey("ingredient.id")),
                  Column("dish_id", ForeignKey("dish.id")))

ing_group_assoc = Table("ing_group_assoc", Base.metadata,
                        Column("ingredient_id", ForeignKey("ingredient.id")),
                        Column("group_id", ForeignKey("ingredient_g.id")))


contains_allergens = Table("contains_allergens", Base.metadata,
                           Column("ingredient_id", ForeignKey("ingredient.id")),
                           Column("allergen_id", ForeignKey("allergen.id")))


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    surname = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    password = Column(LargeBinary, nullable=False)
    isAdmin = Column(Boolean, default=True)

    work = relationship("Work", backref="user")

    def to_schema(self):
        return UserSchema(uid=self.uid, name=self.name, surname=self.surname, email=self.email)


class Restaurant(Base):
    __tablename__ = "restaurant"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    city = Column(String)
    address = Column(String)
    state = Column(String)
    description = Column(String)
    tax = Column(Float, nullable=False)

    order_management = Column(Boolean, default=True, nullable=False)
    take_away = Column(Boolean, default=True, nullable=False)
    license_key = Column(String, nullable=False)
    style = Column(JSON)
    logo_uri = Column(String)

    tables = relationship("Table", backref="restaurant")
    bills = relationship("Bill", backref="restaurant")
    time_slots = relationship("TimeSlot", backref="restaurant")
    menus = relationship("Menu", backref="restaurant")
    ingredients = relationship("Ingredient", backref="restaurant")
    dishes = relationship("Dish", backref="restaurant")
    workers = relationship("Work", backref="restaurant")
    ingredients_groups = relationship("IngredientsGroup", backref="restaurant")


class Work(Base):
    __tablename__ = "work"

    user_id = Column(Integer, ForeignKey("user.id"), primary_key=True)
    restaurant_id = Column(Integer, ForeignKey("restaurant.id"), primary_key=True)
    role = Column(Integer, nullable=False, default=0)


class Table(Base):
    __tablename__ = "table"
    id = Column(Integer, primary_key=True, autoincrement=True)
    number = Column(Integer)
    enabled = Column(Boolean, default=True, nullable=False)
    occupied = Column(Boolean, default=False, nullable=False)
    people = Column(Integer)

    bill_id = Column(Integer, ForeignKey("bill.id"), nullable=False)
    bill = relationship("Bill", backref="table")
    restaurant_id = Column(Integer, ForeignKey("restaurant.id"), nullable=False)


class Menu(Base):
    __tablename__ = "menu"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)

    categories = relationship("Category", backref="menu")
    restaurant_id = Column(Integer, ForeignKey("restaurant.id"), nullable=False)


class Category(Base):
    __tablename__ = "category"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    is_top_level = Column(Boolean, default=False)
    image_uri = Column(String)

    menu_id = Column(Integer, ForeignKey("menu.id"), nullable=False)
    parent_id = Column(Integer, ForeignKey("category.id"))
    children = relationship("Category", backref=backref('parent', remote_side=[id]))
    dishes = relationship("Dish", secondary=category_association, backref="categories")


class Dish(Base):
    __tablename__ = "dish"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    description = Column(String)
    price = Column(Float, nullable=False)
    rem_ing_low_price = Column(Boolean, nullable=False, default=False)
    image_uri = Column(String)

    restaurant_id = Column(Integer, ForeignKey("restaurant.id"), nullable=False)
    ingredients = relationship("Ingredient", secondary=composition, backref="dishes")
    additions = relationship("Ingredient", secondary=additions, backref="compatible")


class Ingredient(Base):
    __tablename__ = "ingredient"
    id = Column(Integer, primary_key=True, autoincrement=True)
    in_stock = Column(Boolean, default=True, nullable=False)
    name = Column(String, nullable=False)
    price = Column(Float)

    restaurant_id = Column(Integer, ForeignKey("restaurant.id"), nullable=False)


class Allergen(Base):
    __tablename__ = "allergen"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)

    ingredients = relationship("Ingredient", secondary=contains_allergens, backref="allergens")


class IngredientsGroup(Base):
    """
    Group of ingredients that are united in a group
    """
    __tablename__ = "ingredient_g"
    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(Integer, autoincrement=True)

    restaurant_id = Column(Integer, ForeignKey("restaurant.id"), nullable=False)
    ingredients = relationship("Ingredient", secondary=ing_group_assoc, backref="groups")


class Order(Base):
    __tablename__ = "order"

    id = Column(Integer, primary_key=True, autoincrement=True)
    quantity = Column(Integer, nullable=False, default=1)
    status = Column(Integer, nullable=False, default=0)
    price_override = Column(Float)
    is_special = Column(Boolean, default=False, nullable=False)

    bill_id = Column(Integer, ForeignKey("bill.id"), nullable=False)
    customizations = relationship("Customization", backref="order")


class Customization(Base):
    __tablename__ = "customization"
    order_id = Column(Integer, ForeignKey("order.id"), primary_key=True)
    ingredient_id = Column(Integer, ForeignKey("ingredient.id"), primary_key=True)
    add = Column(Boolean, default=True, nullable=False)


class Bill(Base):
    __tablename__ = "bill"
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(Integer, nullable=False, default=0)
    total = Column(Float)
    date = Column(DateTime, nullable=False)
    paid = Column(Boolean, nullable=False, default=False)

    restaurant_id = Column(Integer, ForeignKey("restaurant.id"))
    orders = relationship("Order", backref="bill")
    takeaway_data = relationship("TakeAway", backref="bill")


class TimeSlot(Base):
    __tablename__ = "timeslot"
    id = Column(Integer, primary_key=True, autoincrement=True)
    upper = Column(Time, nullable=False)
    lower = Column(Time, nullable=False)
    enabled = Column(Boolean, default=True)

    restaurant_id = Column(Integer, ForeignKey("restaurant.id"), nullable=False)
    bookings = relationship("TakeAway", backref="time_slot")


class TakeAway(Base):
    __tablename__ = "takeaway"
    id = Column(Integer, autoincrement=True, primary_key=True)
    ref_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    completed = Column(Boolean, nullable=False, default=False)
    payment_id = Column(String, nullable=False, unique=True)

    time_slot_id = Column(Integer, ForeignKey("timeslot.id"), nullable=False)
    bill_id = Column(Integer, ForeignKey("bill.id"), nullable=False)
