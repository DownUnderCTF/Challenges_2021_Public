from . import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    aboutme = db.Column(db.String(300))

class Messages(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    message = db.Column(db.String(400), nullable=False)
    timesent = db.Column(db.BigInteger, nullable=False)
    sender = db.Column(db.String(150))

class Roles(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    role = db.Column(db.String(30), nullable=False)

class SessionKeys(db.Model):
    __tablename__ = "sessionkeys"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    session_key = db.Column(db.String(300), nullable=False)
    
class Reports(db.Model):
    __tablename__ = "reports"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    userid = db.Column(db.Integer, nullable=False)

db.create_all()
