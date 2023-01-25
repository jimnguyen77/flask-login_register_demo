# To initialize this project: #

1. Within the project directory, type: `. venv/bin/activate`
2. To run the dev server: `flask run` or `flash --debug run --host=0.0.0.0`
3. If you need to install some dependancies:
	a. `pip install flask-wtf`
	b. `pip install flask-sqlalchemy`
	c. `pip install Flask-Migrate`
	d. `pip install flask_login`

---

**When adding new columns to the database, update the model class in app.py, and then run the following commands on the terminal:**
`flask db init` <-- only needed to do the first time, if the "migrations" folder does not exist
`flask db migrate -m 'some message'`
`flask db upgrade`

---

### Initial users and passwords are: ###

1. john / password (admin)
2. mary / password
3. bob / password
4. mark / password (admin)
5. jim / password
6. jones / password