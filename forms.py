from app import app
from models import Users
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_login import LoginManager

# Login handler
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))

# User class
class UserForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match!')])
	password_hash2 = PasswordField("Confirm Password", validators=[DataRequired()])
	is_admin = BooleanField("Is Admin")
	submit = SubmitField("Submit")

# Password class
class PasswordForm(FlaskForm):
	username = StringField("What's your username", validators=[DataRequired()])
	password_hash = PasswordField("What's your password", validators=[DataRequired()])
	submit = SubmitField("Submit")

# Login class
class LoginForm(FlaskForm):
	username = StringField("Username", validators=[DataRequired()])
	password = PasswordField("Password", validators=[DataRequired()])
	submit = SubmitField("Submit")
