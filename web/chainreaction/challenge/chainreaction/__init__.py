from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import environ
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from time import sleep 
load_dotenv()
app = Flask(__name__)
app.secret_key = b"iugi3jbnsad7g32kjbgiojubdhghs"
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f'mysql+pymysql://{environ["MYSQL_USER"]}:{environ["MYSQL_PASSWORD"]}' + 
    f'@{environ.get("MYSQL_HOST", "localhost")}' +
    f'/{environ.get("MYSQL_DB", "ductf_db")}'
)
app.config["SESSION_COOKIE_HTTPONLY"] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
# Import the routes 
from chainreaction import routes