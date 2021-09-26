#!/usr/bin/python3


import os
from flask import Flask, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from urllib.parse import urlparse, urljoin
from hashlib import sha256

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10))
    password = db.Column(db.String(64))
    privilege = db.Column(db.Boolean, default=False)

class Reports(db.Model):
	__tablename__ = 'reports'

	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(10))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	user = db.relationship("User", backref=db.backref("reports", uselist=True))
	message = db.Column(db.String(256))

db.create_all()

def create_admin(user, flag, db):
	pword = sha256(str(os.environ.get('ADMIN_PW')).encode()).hexdigest()
	u = User(username=user[0], password=pword, privilege=user[1])
	db.session.add(u)
	db.session.commit()
	r = Reports(user_id=u.id, username=u.username, message="God damn script kids trying to hack me, this is the only place I can store this flag: "+flag)
	db.session.add(r)
	db.session.commit()

create_admin(['admin', True], str(os.environ.get('FLAG')), db)
