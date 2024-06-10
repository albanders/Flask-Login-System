import os
import datetime

from flask import Flask, abort, render_template, request, flash, redirect, url_for, session
from users import get_users, get_user, create_user, update_user, delete_user
from hashing import get_hash

app = Flask(__name__)
app.secret_key = os.urandom(24) # Random secret key on every start-up

def login_required(func):
    def _wrapper(*args, **kwargs):
        if session.get("logged_in", default=False) is not True:
            abort(403) # Forbidden

        return func(*args, **kwargs)

    _wrapper.__name__ = func.__name__

    return _wrapper

def admin_required(func):
    def _wrapper(*args, **kwargs):
        if session.get("admin", default=False) is not True:
            abort(403) # Forbidden

        return func(*args, **kwargs)

    _wrapper.__name__ = func.__name__

    return _wrapper

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    # Track login attempts:
    if "login_attempts" not in session:
        session["login_attempts"] = 0

    try:
        # Time since last login attempt:
        if "last_login_attempt" in session:
            elapsed_time = datetime.datetime.now(datetime.timezone.utc) - session["last_login_attempt"]

            if elapsed_time > datetime.timedelta(minutes=30):
                session["login_attempts"] = 0 # If 30 minutes have passed, counter resets

        session["last_login_attempt"] = datetime.datetime.now(datetime.timezone.utc)

        assert session["login_attempts"] < 3, "Too many failed login attempts. Try again later"

        # Gets user info from a local SQLite3 Database:
        username = request.form.get("username")
        password = request.form.get("password")

        user = get_user(username)

        assert user, "User does not exist"
        assert get_hash(password) == user["password"], "Incorrect password"

        # Create new session:
        session.clear()

        session["logged_in"] = True
        session["username"] = username
        if user["admin"] is True:
            session["admin"] = True

    except AssertionError as e:
        session["login_attempts"] += 1
        flash(str(e))

    finally:
        return redirect(request.headers.get("referer"))

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("username", None)
    session.pop("admin", None)

    return redirect(url_for("index"))

@app.route("/admin")
@app.route("/admin/<username>", methods=["GET", "POST"])
@admin_required
def admin(username=None):
    users = get_users()
    specific_user = get_user(username)

    if username is not None and specific_user is None:
        return redirect(url_for("admin"))

    return render_template("admin.html", users=users, specific_user=specific_user)

@app.route("/admin/redirect")
@app.route("/admin/redirect/<username>", methods=["GET", "POST"])
@admin_required
def admin_redirect(username=None):
    return redirect(f"/admin/{username}")

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    try:
        username = request.form.get("username")
        password = request.form.get("password")
        admin = request.form.get("admin", default=False, type=bool)

        create_user(username, password, admin)

        flash("User creation successful", "success")

    except AssertionError as e:
        flash(f"User creation failed: {str(e)}", "error")

    finally:
        return redirect(request.headers.get("referer"))

@app.route("/admin/update_user/<username>", methods=["POST"])
@admin_required
def admin_update_user(username):
    try:
        password_1 = request.form.get("password-1")
        password_2 = request.form.get("password-2")
        admin = request.form.get("admin", default=False, type=bool)

        assert password_1 == password_2, "Passwords do not match"
        assert username != session["username"] or admin is True, "Cannot change current user's admin-rights"

        if not password_1:
            password_1 = None

        update_user(username, new_password=password_1, admin=admin)

        flash("User update successful", "success")

    except AssertionError as e:
        flash(f"User update failed: {str(e)}", "error")

    finally:
        return redirect(request.headers.get("referer"))

@app.route("/admin/delete_user/<username>", methods=["POST"])
@admin_required
def admin_delete_user(username):
    try:
        assert username != session["username"], "Cannot delete current user"

        delete_user(username)

        flash("User deletion successful", "success")

    except AssertionError as e:
        flash(f"User deletion failed: {str(e)}", "error")

    finally:
        return redirect(request.headers.get("referer"))

if __name__ == "__main__":
    app.run(
        host = "localhost",
        port = 80,
        debug = True
    )
