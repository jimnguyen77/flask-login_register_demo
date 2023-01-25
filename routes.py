from app import app
from flask import render_template, flash, request, redirect, url_for
from models import db, Users
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from forms import load_user, UserForm, PasswordForm, LoginForm

# Home/Index page
@app.route('/')
def index():
	return render_template('index.html')

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(username=form.username.data).first()
		if user:
			# Check the hash
			if check_password_hash(user.password_hash, form.password.data):
				login_user(user)
				flash('Login successful!')
				return redirect(url_for('dashboard'))
			else:
				flash('Username or password was incorrect, try again!')
		else:
			flash('Username or password was incorrect, try again!')

	return render_template('login.html', 
		form=form
	)

# Logout Page
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	flash("You've been logged out")
	return redirect(url_for('login'))

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
	form = UserForm()
		
	if form.validate_on_submit():
		user = Users.query.filter_by(username=form.username.data).first()

		# User doesn't exist, so create an entry in DB (add the user)
		if user is None:
			# Hash the password
			hashed_pw = generate_password_hash(form.password_hash.data)
			user = Users(
				username=form.username.data.lower(),
				password_hash=hashed_pw
			)
			db.session.add(user)
			db.session.commit()

			form.username.data = ''
			form.password_hash.data = ''
			flash('Registered Successfully!')
			return redirect(url_for('login'))
		else:
			flash('Someone already registered with that username, try another')

	return render_template('register.html', form=form)

# Dashboard Page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
	return render_template('dashboard.html')

# User Admin - Add user
@app.route('/user_admin', methods=['GET', 'POST'])
@login_required
def user_admin():
	username = None
	form = UserForm()
		
	if form.validate_on_submit():
		user = Users.query.filter_by(username=form.username.data).first()

		# User doesn't exist, so create an entry in DB (add the user)
		if user is None:
			# Hash the password
			hashed_pw = generate_password_hash(form.password_hash.data)
			user = Users(
				username=form.username.data.lower(),
				password_hash=hashed_pw,
				is_admin=form.is_admin.data
			)
			db.session.add(user)
			db.session.commit()
			username = form.username.data

			flash('User Added Successfully!')
		else:
			flash('User already exists!')

		form.username.data = ''
		form.password_hash.data = ''
		form.is_admin.data = False

	all_users = Users.query.order_by(Users.created)

	return render_template('user_admin.html', 
		form=form,
		username=username,
		all_users=all_users
	)

# Update user
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_user(id):
	form = UserForm()
	user_to_update = Users.query.get_or_404(id)
	if request.method == "POST":
		hashed_pw = generate_password_hash(request.form['password_hash'])

		user_to_update.username = request.form['username']
		user_to_update.password_hash = hashed_pw
		user_to_update.is_admin = request.form['is_admin']
		try:
			db.session.commit()
			flash('User Updated Successfully!')
		except:
			flash('Error! Looks like there was a problem, try again.')

		return redirect(url_for('user_admin'))
	
	return render_template('update.html',
		form=form,
		user_to_update=user_to_update
	)

# Delete user
@app.route('/delete/<int:id>')
@login_required
def delete_user(id):
	username = None
	form = UserForm()
	user_to_delete = Users.query.get_or_404(id)
	
	try:
		db.session.delete(user_to_delete)
		db.session.commit()
		flash("User Deleted Successfully!")		
	except:
		flash("Whoops! There was a problem deleting user, try again")

	return redirect(url_for('user_admin'))

# Custom error pages
@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
	return render_template('500.html'), 500