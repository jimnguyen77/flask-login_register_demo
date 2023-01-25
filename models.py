from app import app
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Users Model class
class Users(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	created = db.Column(db.DateTime, default=datetime.utcnow)
	username = db.Column(db.String(200), nullable=False, unique=True)
	password_hash = db.Column(db.String(200), nullable=False)
	is_admin = db.Column(db.Integer)

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute!')

	# hash the password
	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	# verify against hashed password
	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

	def __repr__(self):
		return '<Name %r>' % self.username

# Create the actual database; if it already exists, don't do anything
with app.app_context():
	db.create_all()
