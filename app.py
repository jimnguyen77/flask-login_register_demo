
from flask import Flask

# Create a Flask instance
app = Flask(__name__)

# Add Database - for SQLite, it is stored in the 'instance' folder
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Secret key, should be changed
app.config['SECRET_KEY'] = '# this is a secret key! but you should change it #'

# Routes
import routes