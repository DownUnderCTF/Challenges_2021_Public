from chainreaction import app, login_manager,db,bcrypt
from flask import redirect, request, url_for, flash, render_template, session, jsonify, make_response
from .models import *
from os import environ
import unicodedata
from flask_login import login_user, current_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import json
import uuid
import requests
from apscheduler.schedulers.background import BackgroundScheduler

XSSBOT_URL = environ.get("XSSBOT_URL", "http://127.0.0.1:8000")

domain = "localhost"

bad = open("bad.txt", "r").read()

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["60 per minute"]
)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.cookies.get('admin-cookie') != "sup3rs3cur34dm1nc00k13" and not current_user.is_authenticated:
            flash('Not allowed.')
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.cookies.get('admin-cookie') != "sup3rs3cur34dm1nc00k13":
            flash('Not allowed.')
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

def waf(data):
    found = False
    for b in bad.split("\n"):
        if b.lower() in data:
            print(b.lower())
            found = True
            break
    else:
        found = False
    return found

@app.route("/")
def index():
    next = request.args.get("next")
    if next:
        return redirect(next) 
    return render_template("index.html")

@app.route("/dev")
def dev():
    return render_template("dev.html")

@app.route("/admin")
@admin_required
def admin():
    return render_template("admin.html")

@app.route("/devchat")
def chat():
    user_messages = Messages.query.order_by(Messages.timesent.desc()).all()
    user_messages.reverse()
    return render_template("chats.html", user_messages=user_messages)

@app.route("/profile/<userid>", methods=["GET", "POST"])
@login_required
def profile(userid):
    if request.method == "POST":
        if "aboutme" in request.form:
            aboutme = request.form["aboutme"]
            update = User.query.filter_by(id=userid).first()
            if aboutme == current_user.aboutme:
                pass
            elif len(aboutme) > 300:
                flash("About me too long", "warning")
            elif not waf(aboutme.lower()):
                update.aboutme = unicodedata.normalize("NFKD", aboutme)
            else:
                return render_template("bad.html")
            db.session.commit()
        if "username" in request.form:
            username = request.form["username"]
            user_update = User.query.filter_by(id=userid).first()
            if username == current_user.username:
                pass
            elif len(username) > 200:
                flash("Username too long", "warning")
            elif not User.query.filter_by(username=unicodedata.normalize("NFKD", username)).first():
                if not waf(username.lower()):
                    user_update.username = unicodedata.normalize("NFKD", username)
                else:
                    return render_template("bad.html")
                db.session.commit()
            else:
                flash("Username already exists!", "warning")
    user_data = User.query.filter_by(id=userid).first()
    auth = False
    admin = False
    if request.cookies.get('admin-cookie') == "sup3rs3cur34dm1nc00k13":
        admin = True
    if (current_user.is_authenticated and current_user.id == int(userid)):
        auth = True
    
    response = make_response(render_template("profile.html", user_data=user_data, auth=auth, admin=admin))
    return response

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        redirect(url_for('home'))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Need a username and password", 'warning')
            return render_template("login.html")
        if len(username) > 100:
            return "Pick a shorter username"
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, False)
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful please check your username or password')
    return render_template("login.html")


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == "POST":
        username = unicodedata.normalize("NFKD", request.form["username"])
        if waf(username.lower()):
            return "HACKING ATTEMPT DETECTED"
        hashed_password = bcrypt.generate_password_hash(request.form["password"]).decode('utf-8')
        if not User.query.filter_by(username=username).first():
            user = User(username=username, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Created account', 'success')
            return redirect(url_for("login"))
        else:
            flash('Account already exists', 'danger')
    return render_template('register.html', title="Register")

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/home")

@app.route("/home")
def home():
    return render_template('home.html', auth=current_user.is_authenticated)

@app.route("/api/v1/report")
@login_required
@limiter.limit("6 per minute")
def report():
    requests.post(f"{XSSBOT_URL}/visit", json={'url':
        f'http://{domain}:1337/profile/{str(current_user.id)}'
    }, headers={
        'X-SSRF-Protection': '1'
    })
    return jsonify(status="Success")


def init():
    # Just some initializing
    users = ['admin', 'john', 'wick', 'kay']
    for i in users:
        if not User.query.filter_by(username=i).first():
            user = User(username=i, password=bcrypt.generate_password_hash(uuid.uuid4().hex).decode('utf-8'), aboutme="Placeholder")
            db.session.add(user)
            db.session.commit()

    file = json.loads(open("init.json", 'r').read())

    for message in file['messages']:
        if not Messages.query.filter_by(message=message['message']).first():
            user = User.query.filter_by(username=message['username']).first()
            message = Messages(message=message['message'], timesent=message["timesent"], sender=user.username)
            db.session.add(message)
            db.session.commit()

init()
