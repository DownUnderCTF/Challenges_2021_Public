#!/usr/bin/python3

import os
import subprocess
import requests
from time import sleep
from random import randint
from hashlib import sha256
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, render_template, flash, abort, redirect, url_for, Markup
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, AnonymousUserMixin, UserMixin
from flask_wtf import FlaskForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	loginbtn = SubmitField('Sign In')

class RegisterForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	submit = SubmitField('Register')

class ReportForm(FlaskForm):
	message = TextAreaField('Message', validators=[DataRequired()])
	submit = SubmitField('Report')

class EditForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	submit = SubmitField('Edit Profile')


app = Flask(__name__)
app.config['SECRET_KEY'] = 'a0f67bd2a7d4ec662e2697900cf871bff1175114fae543e110e71883eacfa8e8'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SESSION_COOKIE_HTTPONLY']=False

db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

limiter = Limiter(
	app,
	key_func=get_remote_address,
	default_limits=["36000 per hour"]
)

class Reports(db.Model):
	__tablename__ = 'reports'

	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(10))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	user = db.relationship("User", backref=db.backref("reports", uselist=True))
	message = db.Column(db.String(256))

class User(UserMixin, db.Model):
	__tablename__ = 'user'

	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(10))
	password = db.Column(db.String(64))
	privilege = db.Column(db.Boolean, default=False)

	def is_active(self):
		return True

	def get_id(self):
		return self.id

	def get_username(self):
		return self.username

	def get_privs(self):
		return self.privilege

	def is_authenticated(self):
		return True

	def is_anonymous(self):
		return False

class Anonymous(AnonymousUserMixin):
	def is_active(self):
		return True

	def is_authenticated(self):
		return False

	def is_anonymous(self):
		return True

def authenticate(user,pw):
	result = None
	u = User.query.filter_by(username=user).first()
	if u != None:
		if u.password == sha256(pw.encode()).hexdigest():
			result = u
	sleep(randint(1,3))
	return result


@login_manager.user_loader
def load_user(user_id):
	user = User.query.filter_by(id=user_id).first()
	if user:
		return user
	anon = Anonymous()
	return anon


@app.errorhandler(401)
def _unauthorized(e):
	return redirect(url_for('_login'))

@app.errorhandler(405)
def _methoderror(e):
	return redirect(url_for('_index'))

@app.route('/')
@limiter.exempt
def _index():
	return render_template('index.html', title='Home', current_user=current_user)

@app.route('/login', methods=['GET','POST'])
@limiter.limit("500 per minute")
def _login():
	# Admin Login
	token = request.args.get('token')
	if token == os.environ.get('ADMIN_PW'):
		admin = User.query.filter_by(privilege=True).first()
		login_user(admin)
		return "admin", 200
	# User Login
	form = LoginForm()
	if form.validate_on_submit():
		user = authenticate(request.form.get('username'), request.form.get('password'))
		if user == None:
			flash('Invalid username or password!', 'alert-danger')
			return render_template('login.html', title='Login', form=form, current_user=current_user)
		login_user(user)
		flash('Logged in successfully.', 'alert-success')
		return redirect(url_for('_dashboard'))
	return render_template('login.html', title='Login', form=form, current_user=current_user)

@app.route('/register', methods=['GET', 'POST'])
@limiter.exempt
def _register():
	form = RegisterForm()
	if request.method == 'POST':
		if form.validate_on_submit():
			uname = request.form.get('username')
			if len(uname) > 10:
				flash('Username must be 10 characters or shorter!', 'alert-danger')
				return render_template('register.html', title='Register', form=form, current_user=current_user)
			pword = request.form.get('password')
			u = User.query.filter_by(username=uname).first()
			if u:
				flash('User Exists', 'alert-danger')
				return redirect(url_for('_register'))
			del(u)
			u = User(username=uname, password=sha256(pword.encode()).hexdigest(), privilege=False)
			db.session.add(u)
			db.session.commit()
			flash('User registered, you can now login', 'alert-success')
			return redirect(url_for('_login'))
		else:
			flash('Missing Arguments', 'alert-danger')
	return render_template('register.html', title='Register', form=form, current_user=current_user)

@app.route('/dashboard')
@login_required
@limiter.exempt
def _dashboard():
	reportform = ReportForm()
	editform = EditForm()
	return render_template('dashboard.html', title='Dashboard', reportform=reportform, editform=editform, current_user=User.query.filter_by(id=current_user.get_id()).first())

@app.route('/edit', methods=['POST'])
@login_required
@limiter.exempt
def _edit():
	form = EditForm()
	if form.validate_on_submit():
		uname = request.form.get('username')
		if len(uname) > 10:
				flash('Username must be 10 characters or shorter!', 'alert-danger')
				return redirect(url_for('_dashboard'))
		u = current_user
		u.username = uname
		db.session.commit()
		flash('Username Changed!', 'alert-success')
		return redirect(url_for('_dashboard'))

@app.route('/report', methods=['POST'])
@login_required
@limiter.exempt
def _report():
	form = ReportForm()
	if form.validate_on_submit():
		msg = request.form.get('message')
		if len(msg) > 256:
			flash('Message Too Long! >:(','alert-danger')
			return redirect(url_for('_dashboard'))
		username=current_user.username+'>'
		report = Reports(username=username, user_id=current_user.id, message=msg)
		db.session.add(report)
		db.session.commit()	
		flash('Sk1D Rep0rt3d >:)', 'alert-success')
		return redirect(url_for('_view_report',id=report.id))

@app.route('/send2admin/<int:id>', methods=['GET'])
@login_required
@limiter.limit("4 per minute")
def _send2admin(id):
	report = Reports.query.filter_by(id=id).first()
	if report == None:
		return redirect(url_for('_dashboard'))
	### Admin Views it >:)
	## INFRA: Update this when deploying just incase it needs to be localhost
	###
	requests.post('http://localhost:8000/visit', json={
		'url': 'http://localhost:5000'+url_for('_view_report',id=id)
		}, headers={
		'X-SSRF-Protection': '1'
	})
	flash('The admin will take action shortly >:)', 'alert-success')
	return redirect(url_for('_dashboard'))


@app.route('/report/<int:id>')
@login_required
@limiter.exempt
def _view_report(id):
	report = Reports.query.filter_by(id=id).first()
	if report == None or not (report in current_user.reports or current_user.get_privs()):
		return redirect(url_for('_dashboard'))
	username = Markup(report.user.username)
	previous_reports = []
	for prep in Reports.query.filter_by(user_id=report.user.id).order_by(Reports.id)[::-1][1:3]:
		previous_reports.append([Markup(prep.username), Markup.escape(prep.message)])
	return render_template('report_view.html', username=username, previous_reports=previous_reports, report=report, current_user=current_user)

@app.route("/logout")
@login_required
def _logout():
	logout_user()
	flash('Logged out!', 'alert-success')
	return redirect(url_for('_index'))


if __name__ == "__main__":
	app.run(host='0.0.0.0', port=5000, debug=False)
